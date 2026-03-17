import logging
import os
import re
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler

from flask import has_request_context, request, session, g, got_request_exception

_ACCESS_LOGGER_NAME = 'integrated_share.access'
_ERROR_LOGGER_NAME = 'integrated_share.error'
_MAX_LOG_BYTES = 10 * 1024 * 1024  # 10MB chunks
_BACKUP_COUNT = 10


def _add_file_handler_once(logger, handler_path, level=logging.INFO):
    abs_path = os.path.abspath(handler_path)
    for h in logger.handlers:
        if getattr(h, 'baseFilename', None) == abs_path:
            return
    handler = RotatingFileHandler(abs_path, maxBytes=_MAX_LOG_BYTES, backupCount=_BACKUP_COUNT, encoding='utf-8')
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(handler)


def _now():
    return datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')


def _sanitize(value):
    if value is None:
        return '-'
    cleaned = str(value)
    cleaned = re.sub(r'[\r\n\t]+', ' ', cleaned)
    cleaned = cleaned.replace('|', '/').replace('=', ':')
    cleaned = ''.join(ch if 32 <= ord(ch) <= 126 else '?' for ch in cleaned)
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()
    if len(cleaned) > 512:
        cleaned = cleaned[:512]
    return cleaned or '-'


def _request_meta(username=None):
    if not has_request_context():
        return {
            'ip': '-',
            'path': '-',
            'method': '-',
            'ua': '-',
            'username': _sanitize(username),
            'referrer': '-',
        }
    return {
        'ip': _sanitize(request.remote_addr),
        'path': _sanitize(request.path),
        'method': _sanitize(request.method),
        'ua': _sanitize(request.headers.get('User-Agent')),
        'username': _sanitize(username if username is not None else session.get('username')),
        'referrer': _sanitize(request.referrer),
    }


def _siem_line(level, event, **fields):
    base = [_now(), level, f"EVENT={_sanitize(event)}"]
    for k, v in fields.items():
        base.append(f"{k}={_sanitize(v)}")
    return " | ".join(base)


def get_access_logger():
    return logging.getLogger(_ACCESS_LOGGER_NAME)


def get_error_logger():
    return logging.getLogger(_ERROR_LOGGER_NAME)


def setup_logging(app, log_dir='logs'):
    os.makedirs(log_dir, exist_ok=True)

    access_logger = get_access_logger()
    access_logger.setLevel(logging.INFO)
    access_logger.propagate = False
    _add_file_handler_once(access_logger, os.path.join(log_dir, 'access.log'), logging.INFO)

    error_logger = get_error_logger()
    error_logger.setLevel(logging.ERROR)
    error_logger.propagate = False
    _add_file_handler_once(error_logger, os.path.join(log_dir, 'error.log'), logging.ERROR)


def log_siem_event(
    *,
    action,
    severity='INFO',
    event_category='GENERAL',
    outcome='SUCCESS',
    target='-',
    message='-',
    username=None,
    status='-',
    stream='access',
):
    meta = _request_meta(username=username)
    line = _siem_line(
        severity,
        action.upper(),
        IP=meta['ip'],
        PATH=meta['path'],
        METHOD=meta['method'],
        UA=meta['ua'],
        USERNAME=meta['username'],
        REFERRER=meta['referrer'],
        CATEGORY=event_category,
        OUTCOME=outcome,
        STATUS=status,
        TARGET=target,
        MESSAGE=message,
    )
    if stream == 'error':
        get_error_logger().error(line)
    else:
        get_access_logger().info(line)


def register_request_logging(app):
    @app.before_request
    def _mark_start():
        g._req_start = time.time()

    @app.after_request
    def _log_request(response):
        elapsed_ms = int((time.time() - getattr(g, '_req_start', time.time())) * 1000)
        outcome = 'SUCCESS' if response.status_code < 400 else 'FAILURE'
        severity = 'INFO' if response.status_code < 400 else ('MEDIUM' if response.status_code < 500 else 'HIGH')
        log_siem_event(
            action='HTTP_REQUEST',
            severity=severity,
            event_category='GENERAL',
            outcome=outcome,
            status=response.status_code,
            target=request.path,
            message=f'LATENCY_MS={elapsed_ms}',
            stream='access',
        )
        if response.status_code >= 400:
            log_siem_event(
                action='HTTP_ERROR',
                severity='MEDIUM' if response.status_code < 500 else 'HIGH',
                event_category='GENERAL',
                outcome='FAILURE',
                status=response.status_code,
                target=request.path,
                message=f'LATENCY_MS={elapsed_ms}',
                stream='error',
            )
        return response

    def _on_exception(sender, exception, **extra):
        log_siem_event(
            action='UNHANDLED_EXCEPTION',
            severity='HIGH',
            event_category='GENERAL',
            outcome='FAILURE',
            status=500,
            target=request.path if has_request_context() else '-',
            message=str(exception),
            stream='error',
        )

    got_request_exception.connect(_on_exception, app)
