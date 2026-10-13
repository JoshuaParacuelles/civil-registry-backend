"""Shared security helpers so every sensitive route is protected the same way."""
import logging
import re
from functools import wraps

from flask import g, has_request_context, jsonify, request, session

logger = logging.getLogger(__name__)

VERCEL_ORIGIN_PATTERNS = [
    re.compile(r"^https://civil-registry-scc\.vercel\.app$"),
    re.compile(r"^https://civil-registry(-[a-z0-9]+)*-joshua-paracuelles-projects\.vercel\.app$"),
]

# Must match ENTITY_PERMISSIONS in src/offline/syncScope.js.
ENTITY_PERMISSIONS = {
    "birth":    ["birth_verification", "birth_archive_uploader"],
    "death":    ["death_verification", "death_archive_uploader"],
    "marriage": ["marriage_verification", "marriage_archive_uploader"],
    "tracking": [
        "document_tracking",
        "document_stage_registration",
        "document_stage_civil_registrar",
        "document_stage_posting_period",
        "document_stage_records_division",
        "document_stage_registry_number",
        "document_stage_releasing",
    ],
}

# Only changes are guarded. Reads stay open so the dashboard and analytics
# keep working for every role.
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Routine session probes that fire on every page load. Recording them would
# bury real denials in the audit log.
_ROUTINE_PROBE_PATHS = {
    "/api/session",
    "/api/my-permissions",
    "/api/current-user",
    "/api/login",
    "/api/audit/access-denied",
}


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


def _current_permissions():
    """The logged-in user's permission set, cached once per request.
    Returns None when nobody is logged in (login_required_hook answers 401)."""
    username = session.get("username")
    if not username:
        return None
    if has_request_context() and hasattr(g, "_request_perms"):
        return g._request_perms
    # Lazy import avoids a cycle: Rolemanagement imports this module.
    from auth.Rolemanagement import get_user_permissions
    perms = set(get_user_permissions(username) or [])
    if has_request_context():
        g._request_perms = perms
    return perms


def entity_permission_hook(entity):
    """Blocks mutating requests (POST/PUT/PATCH/DELETE) unless the user's role
    includes one of the permissions for `entity` (birth, death, marriage,
    tracking). Administrators hold every module, so they pass automatically."""
    if entity not in ENTITY_PERMISSIONS:
        raise ValueError(f"Unknown entity: {entity!r}")
    required = ENTITY_PERMISSIONS[entity]

    def _hook():
        if request.method not in MUTATING_METHODS:
            return None
        perms = _current_permissions()
        if perms is None:
            return None  # not logged in: the login hook / route handles it
        if "*" in perms or any(p in perms for p in required):
            return None
        audit_denial(f"Module '{entity}' is not in the user's role permissions")
        return jsonify({
            "error": f"Access denied — your role does not include the {entity} module"
        }), 403

    return _hook


def _is_admin(username):
    # Lazy import avoids a cycle when Rolemanagement imports this decorator.
    from auth.Rolemanagement import is_admin
    return is_admin(username)


def audit_denial(reason, action="ACCESS_DENIED"):
    """Record a denial once per request, using the logged-in identity.

    Anonymous requests and routine session probes are not recorded. The
    request is still marked as handled, so the generic 401/403 hook in
    app.py does not write a second row for it.
    """
    if not has_request_context():
        return
    # Mark first: whether or not this call writes a row, the generic hook
    # in app.py must not also write one for this request.
    if getattr(g, "_denial_logged", False):
        return
    g._denial_logged = True

    if request.path in _ROUTINE_PROBE_PATHS and action != "SESSION_EXPIRED":
        return

    username = session.get("username")
    if not username and action != "SESSION_EXPIRED":
        return

    role = session.get("role") or ("Administrator" if session.get("is_admin") else None)
    try:
        # Lazy import: logs.Audits imports this module at load time.
        from logs.Audits import record_action

        record_action(
            action,
            reason,
            username=username or "System",
            role=role,
            status="DENIED",
            resource_type="route",
            resource_id=request.path,
            meta={"route": request.path, "method": request.method},
        )
    except Exception as exc:
        logger.exception("Could not record access denial: %s", exc)


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