# security.py  (place in backend/, next to app.py)
"""Shared security helpers so every sensitive route is protected the same way."""
from functools import wraps

from flask import jsonify, request, session

from auth.Rolemanagement import is_admin


def login_required_hook():
    """Register with blueprint.before_request(...) to require a logged-in
    session for every route in that blueprint."""
    if request.method == "OPTIONS":  # CORS preflight must get a 2xx
        return None
    if not session.get("username"):
        return jsonify({"error": "Not authenticated"}), 401
    return None


def admin_required(fn):
    """Decorator: caller must be logged in AND actually be an admin.
    (The old version only checked that *someone* was logged in.)"""
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
    """
    allowed = set(allowed_origins)

    @app.before_request
    def _origin_check():
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return None
        origin = request.headers.get("Origin")
        if origin and origin not in allowed and session.get("username"):
            return jsonify({"error": "Origin not allowed"}), 403
        return None