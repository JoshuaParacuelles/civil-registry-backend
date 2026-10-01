import json
import logging
import re
import threading
import time
from datetime import datetime, timezone
from functools import wraps

from flask import Blueprint, g, has_request_context, jsonify, request, session

from supabase_client import supabase
from security import require_admin

audit_bp = Blueprint("audit_bp", __name__)
_logger = logging.getLogger(__name__)

_DEDUPE_LOCK = threading.Lock()
_DEDUPE_EVENTS = {}
_DEDUPE_WINDOW_SECONDS = 300
_VALID_STATUSES = {"SUCCESS", "FAILED", "DENIED"}
_SECRET_KEYS = {"password", "token", "secret", "session", "authorization", "cookie", "apikey"}


def init_audit_db():
    """No-op: audit_logs table is created via Supabase SQL Editor, not here."""
    print("[AUDIT] Using Supabase table 'audit_logs' (assumed to already exist)")


def client_ip():
    """Real client IP. Behind Vercel/Render, request.remote_addr is the proxy's
    address, so prefer the first entry of X-Forwarded-For."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr


def mask_identifier(value, visible=4):
    """Mask an identifier while retaining only its final `visible` characters."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return text
    visible = max(0, int(visible))
    if len(text) <= visible:
        return "*" * len(text)
    hidden = max(1, len(text) - visible)
    return f"{'*' * hidden}{text[-visible:] if visible else ''}"


def mask_name(value):
    """Return initials with masked remainder, e.g. `Juan Dela Cruz` -> `J*** D*** C***`."""
    if value is None:
        return None
    parts = re.findall(r"\S+", str(value))
    return " ".join(f"{part[0]}***" for part in parts if part)


def mask_email(value):
    """Mask an email address without retaining its local part."""
    if value is None:
        return None
    text = str(value).strip()
    if "@" not in text:
        return mask_identifier(text)
    _, domain = text.rsplit("@", 1)
    return f"***@{domain}"


def scrub_sensitive(value, key=None):
    """Recursively redact secrets and mask common PII fields in audit details."""
    key_text = re.sub(r"[^a-z0-9]", "", str(key or "").lower())
    if any(secret in key_text for secret in _SECRET_KEYS):
        return "[REDACTED]"
    if any(token in key_text for token in ("birthdate", "dateofbirth", "dateofdeath", "dob")):
        return "[REDACTED]"
    if key_text in {"search", "query", "criteria", "searchcriteria"} and isinstance(value, str):
        return mask_name(value)
    if "email" in key_text:
        return mask_email(value)
    if key_text == "tin":
        return mask_identifier(value)
    if any(token in key_text for token in ("nationalid", "passport", "identitynumber", "registryno")):
        return mask_identifier(value)
    if (
        key_text.endswith("name")
        and key_text not in {
            "username", "rolename", "filename", "documentname", "modulename", "resourcename"
        }
    ):
        return mask_name(value)
    if isinstance(value, dict):
        return {str(k): scrub_sensitive(v, k) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub_sensitive(item, key) for item in value]
    return value


def should_dedupe(action, user_id=None, username=None, window_seconds=_DEDUPE_WINDOW_SECONDS):
    """Return True when this user/action pair was seen within the dedupe window.

    This process-local guard is intended for low-volume page-view events, not
    record mutations; multiple workers may each admit one event in the window.
    """
    now = time.monotonic()
    identity = user_id if user_id is not None else (username or "System")
    key = (str(identity), str(action))
    with _DEDUPE_LOCK:
        previous = _DEDUPE_EVENTS.get(key)
        if previous is not None and now - previous < window_seconds:
            return True
        _DEDUPE_EVENTS[key] = now
        if len(_DEDUPE_EVENTS) > 2048:
            expired = [event_key for event_key, seen_at in _DEDUPE_EVENTS.items()
                       if now - seen_at >= window_seconds]
            for event_key in expired:
                _DEDUPE_EVENTS.pop(event_key, None)
        return False


def _request_identity(username=None, user_id=None, role=None, ip=None, user_agent=None):
    if not has_request_context():
        return username or "System", user_id, role, ip, user_agent
    username = username or session.get("username") or "System"
    user_id = user_id if user_id is not None else session.get("user_id")
    role = role or session.get("role")
    if role is None and session.get("is_admin"):
        role = "Administrator"
    ip = ip or client_ip()
    user_agent = user_agent or request.headers.get("User-Agent")
    return username, user_id, role, ip, user_agent


def record_action(
    action,
    description,
    username=None,
    meta=None,
    ip=None,
    *,
    user_id=None,
    role=None,
    status="SUCCESS",
    resource_type=None,
    resource_id=None,
    user_agent=None,
    old_value=None,
    new_value=None,
):
    """Insert a server-side audit entry; preserves the legacy first 5 arguments."""
    try:
        username, user_id, role, ip, user_agent = _request_identity(
            username, user_id, role, ip, user_agent
        )
        status = str(status or "SUCCESS").upper()
        if status not in _VALID_STATUSES:
            status = "FAILED"

        supabase.table("audit_logs").insert({
            "username":    username or "System",
            "user_id":     user_id,
            "role":        role,
            "action":      action,
            "description": description,
            "meta":        json.dumps(scrub_sensitive(meta), default=str) if meta is not None else None,
            "ip_address":  ip,
            "status":      status,
            "resource_type": resource_type,
            "resource_id": str(resource_id) if resource_id is not None else None,
            "user_agent":  user_agent,
            "old_value":   scrub_sensitive(old_value) if old_value is not None else None,
            "new_value":   scrub_sensitive(new_value) if new_value is not None else None,
            "created_at":  datetime.now(timezone.utc).isoformat(),
        }).execute()
    except Exception as e:
        _logger.exception("[AUDIT RECORD ERROR] %s", e)
        print(f"[AUDIT RECORD ERROR] {e}", flush=True)


def set_audit_context(*, old_value=None, new_value=None, resource_id=None, meta=None):
    """Attach safe transition details for the current route's audit decorator."""
    if has_request_context():
        g._audit_context = {
            "old_value": old_value,
            "new_value": new_value,
            "resource_id": resource_id,
            "meta": meta or {},
        }


def _response_status(result):
    if isinstance(result, tuple):
        for item in result[1:]:
            if isinstance(item, int) and not isinstance(item, bool):
                return item
            if isinstance(item, str) and item[:3].isdigit():
                return int(item[:3])
    return getattr(result, "status_code", 200)


def audit_action(action, resource_type=None, description=None):
    """Audit a route response as SUCCESS, FAILED, or DENIED without altering it."""
    def decorate(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            try:
                result = fn(*args, **kwargs)
            except Exception as exc:
                route_args = getattr(request, "view_args", None) or {}
                context = getattr(g, "_audit_context", {})
                resource_id = next(
                    (route_args[key] for key in (
                        "record_id", "document_id", "payment_id", "role_id", "handler_id", "id"
                    ) if key in route_args),
                    None,
                )
                record_action(
                    action,
                    description or action.replace("_", " ").title(),
                    status="FAILED",
                    resource_type=resource_type,
                    resource_id=context.get("resource_id", resource_id),
                    old_value=context.get("old_value"),
                    new_value=context.get("new_value"),
                    meta={
                        "route": request.path,
                        "error_type": type(exc).__name__,
                        **context.get("meta", {}),
                    },
                )
                raise

            status_code = _response_status(result)
            event_status = "DENIED" if status_code in (401, 403) else (
                "FAILED" if status_code >= 400 else "SUCCESS"
            )
            route_args = getattr(request, "view_args", None) or {}
            context = getattr(g, "_audit_context", {})
            resource_id = next(
                (route_args[key] for key in (
                    "record_id", "document_id", "payment_id", "role_id", "handler_id", "id"
                ) if key in route_args),
                None,
            )
            record_action(
                action,
                description or action.replace("_", " ").title(),
                status=event_status,
                resource_type=resource_type,
                resource_id=context.get("resource_id", resource_id),
                old_value=context.get("old_value"),
                new_value=context.get("new_value"),
                meta={
                    "route": request.path,
                    "method": request.method,
                    **context.get("meta", {}),
                },
            )
            return result
        return wrapped
    return decorate


@audit_bp.route("/api/audit/history", methods=["GET"])
@require_admin
def get_history():
    limit  = max(1, min(request.args.get("limit", 100, type=int), 1000))
    offset = max(0, request.args.get("offset", 0, type=int))
    action = request.args.get("action", "").strip()
    search = request.args.get("search", "").strip()

    try:
        query = supabase.table("audit_logs").select(
            "id, username, action, description, meta, ip_address, created_at"
        )

        if action:
            query = query.eq("action", action)
        if search:
            # Commas/parentheses have special meaning inside PostgREST's or_().
            safe = search.replace(",", " ").replace("(", " ").replace(")", " ")
            query = query.or_(f"description.ilike.%{safe}%,username.ilike.%{safe}%")

        # Secondary sort on id keeps page boundaries stable when several rows
        # share the same created_at.
        res = (
            query.order("created_at", desc=True)
            .order("id", desc=True)
            .range(offset, offset + limit - 1)
            .execute()
        )

        return jsonify(res.data)

    except Exception as e:
        print(f"[AUDIT HISTORY ERROR] {e}")
        return jsonify({"error": str(e)}), 500


@audit_bp.route("/api/audit/access-denied", methods=["POST"])
def record_client_access_denied():
    """Record a client-side permission guard denial using server identity."""
    username = session.get("username")
    if not username:
        return jsonify({"error": "Not logged in"}), 401

    body = request.get_json(silent=True) or {}
    attempted_route = body.get("route")
    if (
        not isinstance(attempted_route, str)
        or not attempted_route.startswith("/")
        or len(attempted_route) > 300
        or "://" in attempted_route
    ):
        return jsonify({"error": "A local route path is required"}), 400

    if should_dedupe("ACCESS_DENIED", session.get("user_id"), username):
        return "", 204

    role = session.get("role") or (
        "Administrator" if session.get("is_admin") else None
    )
    record_action(
        "ACCESS_DENIED",
        "Frontend permission guard denied route access",
        username=username,
        user_id=session.get("user_id"),
        role=role,
        status="DENIED",
        resource_type="route",
        resource_id=attempted_route,
        meta={"route": attempted_route, "source": "frontend_permission_guard"},
    )
    return "", 204


# Audit writes are server-side only; audit history is append-only.

