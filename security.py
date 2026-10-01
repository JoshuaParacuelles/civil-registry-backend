
"""Shared security helpers so every sensitive route is protected the same way."""
import re
from functools import wraps

from flask import jsonify, request, session

from auth.Rolemanagement import is_admin


VERCEL_ORIGIN_PATTERNS = [
    re.compile(r"^https://civil-registry-scc\.vercel\.app$"),
    re.compile(r"^https://civil-registry(-[a-z0-9]+)*-joshua-paracuelles-projects\.vercel\.app$"),
]


def _is_vercel_origin(origin: str) -> bool:
    return any(p.match(origin) for p in VERCEL_ORIGIN_PATTERNS)


def login_required_hook():
    """Register with blueprint.before_request(...) to require a logged-in
    session for every route in that blueprint."""
    if request.method == "OPTIONS":  # CORS preflight must get a 2xx
        return None
    if not session.get("username"):
        return jsonify({"error": "Not authenticated"}), 401
    return None


def admin_required(fn):
    """Decorator: caller must be logged in AND actually be an admin."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        username = session.get("username")
        if not username:
            return jsonify({"error": "Not authenticated"}), 401
        if not is_admin(username):
            return jsonify({"error": "Admin access required"}), 403
        return fn(*args, **kwargs)
    return wrapper


def register_origin_check(app, allowed_origins):
    """Basic CSRF defence.

    Session cookies are SameSite=None in production (needed for
    Vercel -> Render), so a logged-in user's browser will attach the cookie
    to requests fired from ANY website. Reject state-changing requests that
    come from a browser origin we don't recognise.

    Origins are accepted if they are in `allowed_origins` (localhost +
    CORS_EXTRA_ORIGINS) OR match one of the Vercel patterns above, so new
    Vercel preview URLs work without editing the Render env variable.
    """
    allowed = set(allowed_origins)

    @app.before_request
    def _origin_check():
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return None

        origin = request.headers.get("Origin")
        if not origin:
            return None

        if origin in allowed or _is_vercel_origin(origin):
            return None

        if session.get("username"):
            return jsonify({"error": "Origin not allowed"}), 403
        return None