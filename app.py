"""Protected entrypoint. Original Phase 1 handlers remain byte-identical in phase1.py."""
import hashlib
import hmac
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit
from flask import Flask, jsonify, redirect, render_template, request, session
from werkzeug.exceptions import HTTPException
import phase1
from judge_access import Denied, FirestoreStore, digest_code


def secret(name):
    filename = os.environ.get(name + '_FILE')
    return Path(filename).read_text().strip() if filename else os.environ.get(name, '')


def create_app(store=None, config=None):
    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=9 * 1024 * 1024,
                      SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE='Strict', SESSION_COOKIE_NAME='sitelens_judge',
                      PUBLIC_ORIGIN=os.environ.get('PUBLIC_ORIGIN', ''),
                      SESSION_SECRET=secret('SESSION_SECRET'), CODE_PEPPER=secret('CODE_PEPPER'),
                      SESSION_TTL_SECONDS=900)
    if config:
        app.config.update(config)
    app.secret_key = app.config['SESSION_SECRET'] or secrets.token_hex(32)
    ready = len(app.config['SESSION_SECRET']) >= 32 and len(app.config['CODE_PEPPER']) >= 32
    origin = urlsplit(app.config['PUBLIC_ORIGIN'])
    local_test_origin = app.testing and origin.scheme == 'http' and origin.hostname in ('127.0.0.1', 'localhost')
    ready = ready and (origin.scheme == 'https' or local_test_origin) and bool(origin.netloc) and not origin.path and not origin.query and not origin.fragment and not origin.username
    if store is None and ready:
        try:
            if os.environ.get('FIRESTORE_EMULATOR_HOST') and (os.environ.get('K_SERVICE') or os.environ.get('LOCAL_EMULATOR_ALLOWED') != 'true'):
                raise RuntimeError('Emulator requires explicit local opt-in and is prohibited in Cloud Run')
            from google.cloud import firestore
            store = FirestoreStore(firestore.Client(project=os.environ.get('GOOGLE_CLOUD_PROJECT', 'evidencebound'), database=os.environ.get('FIRESTORE_DATABASE', 'sitelens-judge')))
        except Exception:
            ready = False
    app.extensions['judge_store'] = store

    @app.before_request
    def throttle_request():
        # One shared document; no IP/header-derived identity or in-memory fallback.
        try:
            available()
            category = {'login': 'login', 'analyze': 'analysis'}.get(request.endpoint, 'entry')
            store.throttle_request(category, None)
        except Denied:
            raise
        except HTTPException:
            raise
        except Exception:
            return jsonify(error='Request protection unavailable. No analysis permitted.'), 503

    @app.errorhandler(Exception)
    def safe_exception(error):
        if isinstance(error, HTTPException):
            # Do not reflect attacker-controlled request targets or descriptions.
            return jsonify(error='Request rejected.'), error.code or 500
        app.logger.error('Request failed.')  # no exception, URL, headers or body
        return jsonify(error='Request failed.'), 500

    def now():
        return datetime.now(timezone.utc)

    def available():
        if not ready or store is None:
            raise RuntimeError('Access gate not configured')

    def require_origin():
        if request.headers.get('Origin') != app.config['PUBLIC_ORIGIN']:
            raise Denied('Request origin denied.')

    def authenticated():
        available()
        grant_id = session.get('grant_id')
        expiry = session.get('expires_at', 0)
        if not grant_id or now().timestamp() >= expiry:
            raise Denied('Judge access required.', 401)
        grant = store.authenticate(grant_id, now())
        if grant['version'] != session.get('grant_version'):
            raise Denied('Access revoked or changed.')
        return grant

    @app.errorhandler(Denied)
    def denial(e):
        response = jsonify(error=str(e))
        response.status_code = e.status
        if e.status == 429:
            response.headers['Retry-After'] = '60'
        return response

    @app.errorhandler(413)
    def oversized(e):
        return phase1.oversized(e)

    @app.after_request
    def privacy(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        # Keep same-origin form Origin available; no-referrer makes Chrome POST Origin:null.
        response.headers['Referrer-Policy'] = 'same-origin'
        response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' blob:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
        return response

    @app.get('/judge')
    def judge():
        session['login_csrf'] = secrets.token_urlsafe(32)
        return render_template('judge.html', csrf=session['login_csrf'])

    @app.post('/judge')
    def login():
        try:
            available()
            require_origin()
            expected = session.get('login_csrf', '')
            if not expected or not hmac.compare_digest(expected, request.form.get('csrf', '')):
                raise Denied('Access form expired.')
            bucket = hmac.new(app.config['CODE_PEPPER'].encode(), (request.remote_addr or 'unknown').encode(), hashlib.sha256).hexdigest()
            store.login_attempt(bucket, now())
            code = request.form.get('code', '')
            if not 20 <= len(code) <= 256:
                raise Denied('Invalid access code.')
            grant = store.authenticate(digest_code(code, app.config['CODE_PEPPER']), now())
            session.clear()
            session.update(grant_id=grant['id'], grant_version=grant['version'],
                           expires_at=min(grant['expires_at'].timestamp(), (now() + timedelta(seconds=app.config['SESSION_TTL_SECONDS'])).timestamp()),
                           csrf=secrets.token_urlsafe(32))
            return redirect('/')
        except Denied:
            raise
        except HTTPException:
            raise
        except Exception:
            return jsonify(error='Judge access unavailable. No analysis permitted.'), 503

    @app.post('/logout')
    def logout():
        require_origin()
        expected = session.get('csrf', '')
        if not expected or not hmac.compare_digest(expected, request.headers.get('X-CSRF-Token', '')):
            raise Denied('Request verification failed.')
        session.clear()
        return jsonify(ok=True)

    @app.get('/')
    def index():
        try:
            authenticated()
            return render_template('index.html', csrf_token=session['csrf'])
        except Denied:
            return redirect('/judge')
        except Exception:
            return jsonify(error='Judge access unavailable.'), 503

    @app.post('/analyze')
    def analyze():
        try:
            grant = authenticated()
            require_origin()
            expected = session.get('csrf', '')
            if not expected or not hmac.compare_digest(expected, request.headers.get('X-CSRF-Token', '')):
                raise Denied('Request verification failed.')
            upload = request.files.get('photo')
            if not upload:
                return jsonify(error='Select one site photo.'), 400
            image = upload.read(8 * 1024 * 1024 + 1)
            if not image or len(image) > 8 * 1024 * 1024:
                return jsonify(error='Photo must be 1 byte to 8 MiB.'), 400
            try:
                phase1.image_type(image)
            except ValueError as e:
                return jsonify(error=str(e)), 400
            upload.stream.seek(0)
            request_id = request.headers.get('X-Request-ID', '')
            try:
                request_id = uuid.UUID(request_id).hex
            except ValueError:
                return jsonify(error='Valid request ID required.'), 400
            expiry = store.admit(grant['id'], grant['version'], request_id, hashlib.sha256(image).hexdigest())
            if now() >= expiry:
                raise Denied('Access expired before analysis.')
        except Denied:
            raise
        except HTTPException:
            raise
        except Exception:
            return jsonify(error='Request ledger unavailable. No Gemini call made.'), 503
        try:
            result = phase1.analyze()
            response = app.make_response(result)
            if response.status_code >= 400:
                # The preserved Phase1 module can expose str(RuntimeError).
                result = (jsonify(error='Analysis unavailable. No replacement findings generated.'),
                          response.status_code if response.status_code in (400, 413, 502, 503, 504) else 502)
        except Exception:
            result = (jsonify(error='Analysis failed. No replacement findings generated.'), 502)
        try:
            store.finish(request_id, 'completed' if app.make_response(result).status_code == 200 else 'failed')
        except Exception:
            pass  # Slot is consumed permanently; never refund or retry a model call.
        return result

    return app


app = create_app()
