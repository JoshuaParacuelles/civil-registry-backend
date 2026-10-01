
"""Shared security helpers so every sensitive route is protected the same way."""
import re
from functools import wraps

from flask import g, has_request_context, jsonify, request, session

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
        audit_denial("Authentication required")
        return jsonify({"error": "Not authenticated"}), 401
    return None


def _is_admin(username):
    # Lazy import avoids a cycle when Rolemanagement imports this decorator.
    from auth.Rolemanagement import is_admin
    return is_admin(username)


def audit_denial(reason, action="ACCESS_DENIED"):
    """Best-effort server-side denial event; skips routine session probes."""
    if not has_request_context():
        return
    if request.path in {
        "/api/session", "/api/my-permissions", "/api/current-user",
        "/api/login", "/api/audit/access-denied",
    } and action != "SESSION_EXPIRED":
        return
    if getattr(g, "_audit_denial_logged", False):
        return
    g._audit_denial_logged = True
    username = session.get("username") or "System"
    role = session.get("role") or ("Administrator" if session.get("is_admin") else None)
    try:
        from logs.Audits import record_action

        record_action(
            action,
            reason,
            username=username,
            role=role,
            status="DENIED",
            resource_type="route",
            resource_id=request.path,
            meta={"route": request.path, "method": request.method, "role": role},
            ip=request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr,
        )
    except Exception as exc:
        import logging
        logging.getLogger(__name__).exception("Could not record access denial: %s", exc)


def admin_required(fn):
    """Decorator: caller must be logged in AND actually be an admin."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        username = session.get("username")
        if not username:
            audit_denial("Admin route requires authentication")
            return jsonify({"error": "Not authenticated"}), 401
        if not _is_admin(username):
            audit_denial("Admin privileges required")
            return jsonify({"error": "Admin access required"}), 403
        return fn(*args, **kwargs)
    return wrapper


def require_admin(fn):
    """Decorator used by role-management and audit-history endpoints."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        username = session.get("username")
        if not username:
            audit_denial("Admin route requires authentication")
            return jsonify({"error": "Not logged in"}), 401
        if not _is_admin(username):
            audit_denial("Admin privileges required")
            return jsonify({"error": "Access denied — admin privileges required"}), 403
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
            audit_denial("Origin not allowed", action="ORIGIN_REJECTED")
            return jsonify({"error": "Origin not allowed"}), 403
        return None