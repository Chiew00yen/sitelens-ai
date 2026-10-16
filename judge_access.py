"""Persistent admission ledger. Transaction callbacks never execute model requests."""
import hashlib
import hmac
from datetime import datetime, timezone


class Denied(Exception):
    def __init__(self, message, status=403):
        super().__init__(message)
        self.status = status


def digest_code(code, pepper):
    return hmac.new(pepper.encode(), code.encode(), hashlib.sha256).hexdigest()


def valid_state(data, now):
    if not data or data.get('enabled') is not True:
        raise Denied('Access unavailable or revoked.')
    expiry = data.get('expires_at')
    if not isinstance(expiry, datetime) or expiry.tzinfo is None:
        raise RuntimeError('Invalid expiry configuration')
    if now >= expiry:
        raise Denied('Access expired.')
    if not isinstance(data.get('version'), int):
        raise RuntimeError('Missing ledger version')


class FirestoreStore:
    def __init__(self, client, prefix='sitelens_judge'):
        self.client = client
        self.global_ref = client.collection(prefix + '_global').document('budget')
        self.grants = client.collection(prefix + '_grants')
        self.reservations = client.collection(prefix + '_reservations')
        self.logins = client.collection(prefix + '_login')
        self.throttle_ref = client.collection(prefix + '_throttle').document('requests')

    def authenticate(self, digest, now):
        data = self.grants.document(digest).get(retry=None, timeout=8).to_dict()
        valid_state(data, now)
        if not hmac.compare_digest(data.get('code_digest', ''), digest):
            raise Denied('Invalid access code.')
        valid_state(self.global_ref.get(retry=None, timeout=8).to_dict(), now)
        return {'id': digest, 'version': data['version'], 'expires_at': data['expires_at']}

    def login_attempt(self, bucket, now):
        from google.cloud import firestore
        ref = self.logins.document(bucket)
        @firestore.transactional
        def commit(tx):
            data = ref.get(transaction=tx, retry=None, timeout=8).to_dict() or {}
            minute = int(now.timestamp() // 60)
            count = data.get('count', 0) if data.get('minute') == minute else 0
            if type(count) is not int or count < 0:
                raise RuntimeError('Invalid login counter')
            if count >= 10:
                raise Denied('Too many access attempts. Try later.', 429)
            tx.set(ref, {'minute': minute, 'count': count + 1})
        commit(self.client.transaction(max_attempts=3))

    def admit(self, grant_id, version, request_id, image_digest, now=None):
        from google.cloud import firestore
        grant_ref = self.grants.document(grant_id)
        reservation_ref = self.reservations.document(request_id)
        @firestore.transactional
        def commit(tx):
            # Fresh time on EVERY retry; caller-supplied time only supports frozen tests.
            current = now or datetime.now(timezone.utc)
            global_data = self.global_ref.get(transaction=tx, retry=None, timeout=8).to_dict()
            grant = grant_ref.get(transaction=tx, retry=None, timeout=8).to_dict()
            duplicate = reservation_ref.get(transaction=tx, retry=None, timeout=8).exists
            valid_state(global_data, current)
            valid_state(grant, current)
            if grant['version'] != version:
                raise Denied('Access revoked or changed.')
            if duplicate:
                raise Denied('Request already reserved. Do not retry.', 409)
            for data, limit_name in ((global_data, 'total_limit'), (grant, 'limit')):
                limit, used = data.get(limit_name), data.get('used')
                if type(limit) is not int or type(used) is not int or limit < 0 or used < 0:
                    raise RuntimeError('Invalid allowance configuration')
                if used >= limit:
                    raise Denied('Request budget exhausted.', 429)
            minute = int(current.timestamp() // 60)
            count = grant.get('minute_used', 0) if grant.get('minute_bucket') == minute else 0
            rate = grant.get('per_minute', 2)
            if type(rate) is not int or rate < 1 or type(count) is not int or count < 0:
                raise RuntimeError('Invalid rate configuration')
            if count >= rate:
                raise Denied('Request rate exceeded. Try later.', 429)
            tx.update(self.global_ref, {'used': global_data['used'] + 1})
            tx.update(grant_ref, {'used': grant['used'] + 1, 'minute_bucket': minute, 'minute_used': count + 1})
            tx.create(reservation_ref, {'grant_id': grant_id, 'reserved_at': current,
                                      'status': 'reserved', 'image_digest': image_digest})
            return min(global_data['expires_at'], grant['expires_at'])
        return commit(self.client.transaction(max_attempts=3))

    def finish(self, request_id, status):
        self.reservations.document(request_id).update({'status': status}, retry=None, timeout=8)

    def throttle_request(self, category, now):
        """Shared fixed-window admission BEFORE every route; no auto-provisioning.

        Persistent finite total caps accepted requests/writes, not denied reads or
        infrastructure cost. Fixed keys and aggregate limits prevent header/IP
        rotation bypass. Existing login and model budgets remain independent.
        """
        from google.cloud import firestore
        if category not in ('entry', 'login', 'analysis'):
            raise RuntimeError('Invalid throttle category')
        @firestore.transactional
        def commit(tx):
            current = datetime.now(timezone.utc) if now is None else now
            data = self.throttle_ref.get(transaction=tx, retry=None, timeout=8).to_dict()
            # Missing, disabled, malformed or expired state never creates a new budget.
            try:
                valid_state(data, current)
            except Denied:
                raise RuntimeError('Throttle unavailable') from None
            for key in ('all_limit', 'login_limit', 'analysis_limit', 'total_limit'):
                if type(data.get(key)) is not int or data[key] < 1:
                    raise RuntimeError('Invalid throttle configuration')
            for key in ('minute_bucket', 'all_used', 'login_used', 'analysis_used', 'total_used'):
                if type(data.get(key)) is not int or data[key] < 0:
                    raise RuntimeError('Invalid throttle state')
            minute = int(current.timestamp() // 60)
            if minute < data['minute_bucket']:
                raise RuntimeError('Throttle clock moved backwards')
            counts = {k: data[k] if minute == data['minute_bucket'] else 0
                      for k in ('all_used', 'login_used', 'analysis_used')}
            specific = category + '_used'
            if (data['total_used'] >= data['total_limit'] or counts['all_used'] >= data['all_limit']
                or (category != 'entry' and counts[specific] >= data[category + '_limit'])):
                raise Denied('Too many requests. Access is temporarily limited.', 429)
            counts['all_used'] += 1
            if category != 'entry':
                counts[specific] += 1
            tx.update(self.throttle_ref, {**counts, 'minute_bucket': minute,
                                       'total_used': data['total_used'] + 1})
        return commit(self.client.transaction(max_attempts=3))
