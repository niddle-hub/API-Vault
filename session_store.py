import secrets
import threading
from datetime import datetime, timezone

from flask.sessions import SessionInterface, SessionMixin
from itsdangerous import BadSignature, URLSafeSerializer
from werkzeug.datastructures import CallbackDict


class MemorySession(CallbackDict, SessionMixin):
    def __init__(self, initial=None, sid=None, new=False):
        def on_update(_session):
            self.modified = True

        super().__init__(initial, on_update)
        self.sid = sid
        self.new = new
        self.modified = False


class MemorySessionInterface(SessionInterface):
    salt = "api-holder-session"

    def __init__(self):
        self._sessions = {}
        self._lock = threading.RLock()

    def _serializer(self, app):
        return URLSafeSerializer(app.secret_key, salt=self.salt)

    def _timeout_seconds(self, app):
        return app.permanent_session_lifetime.total_seconds()

    def _remove_expired(self, app, now):
        timeout = self._timeout_seconds(app)
        expired = [
            sid
            for sid, stored in self._sessions.items()
            if (now - stored["last_access"]).total_seconds() > timeout
        ]
        for sid in expired:
            self._sessions.pop(sid, None)

    def open_session(self, app, request):
        cookie_value = request.cookies.get(self.get_cookie_name(app))
        sid = None
        if cookie_value:
            try:
                sid = self._serializer(app).loads(cookie_value)
            except BadSignature:
                sid = None

        now = datetime.now(timezone.utc)
        with self._lock:
            self._remove_expired(app, now)
            stored = self._sessions.get(sid)
            if stored is not None:
                stored["last_access"] = now
                return MemorySession(stored["data"], sid=sid)

        return MemorySession(sid=secrets.token_urlsafe(32), new=True)

    def save_session(self, app, session, response):
        cookie_name = self.get_cookie_name(app)
        if not session:
            with self._lock:
                self._sessions.pop(session.sid, None)
            response.delete_cookie(
                cookie_name,
                domain=self.get_cookie_domain(app),
                path=self.get_cookie_path(app),
                secure=self.get_cookie_secure(app),
                httponly=self.get_cookie_httponly(app),
                samesite=self.get_cookie_samesite(app),
            )
            return

        with self._lock:
            self._sessions[session.sid] = {
                "data": dict(session),
                "last_access": datetime.now(timezone.utc),
            }

        response.set_cookie(
            cookie_name,
            self._serializer(app).dumps(session.sid),
            max_age=int(self._timeout_seconds(app)),
            httponly=self.get_cookie_httponly(app),
            secure=self.get_cookie_secure(app),
            samesite=self.get_cookie_samesite(app),
            domain=self.get_cookie_domain(app),
            path=self.get_cookie_path(app),
        )
