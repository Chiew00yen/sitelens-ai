"""Minimal Cloud Run production startup; application behavior is unchanged."""
import os

bind = '0.0.0.0:' + os.environ.get('PORT', '8080')
workers = 1
worker_class = 'gthread'
threads = 4
# Existing upstream request timeout is100s; allow credential refresh/serialization headroom.
# Gunicorn timeout is a worker-liveness bound, not a strict per-thread request deadline.
timeout = 180
# Cloud Run shutdown grace is short; do not promise180s graceful completion on termination.
graceful_timeout = 8
keepalive = 5
accesslog = '-'
errorlog = '-'
loglevel = 'info'

# Numeric operational fields only; never URL, query, headers, IP or user agent.
access_log_format = 'status=%(s)s bytes=%(b)s duration_us=%(D)s'

# Gunicorn malformed-request warnings can include attacker-controlled parser text.
# Install before worker request handling; master startup logs have no HTTP input.
import logging

class RedactWorkerDiagnostics(logging.Filter):
    def filter(self, record):
        if record.levelno >= logging.WARNING or record.exc_info:
            record.msg = 'Worker diagnostic; request details suppressed.'
            record.args = ()
            record.exc_info = None
            record.exc_text = None
            record.stack_info = None
        return True

def post_fork(server, worker):
    server.log.error_log.addFilter(RedactWorkerDiagnostics())
