import json
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify, session

from supabase_client import supabase
from auth.Rolemanagement import require_admin

audit_bp = Blueprint("audit_bp", __name__)


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


def record_action(action, description, username=None, meta=None, ip=None):
    """Insert an audit log entry. Safe to call from any blueprint."""
    try:
        supabase.table("audit_logs").insert({
            "username":    username or "System",
            "action":      action,
            "description": description,
            # JSON (not str(dict)) so the frontend can always JSON.parse it.
            "meta":        json.dumps(meta, default=str) if meta else None,
            "ip_address":  ip,
            # Timezone-aware UTC: Render runs in UTC, a naive local timestamp
            # would be off by the viewer's UTC offset.
            "created_at":  datetime.now(timezone.utc).isoformat(),
        }).execute()
    except Exception as e:
        print(f"[AUDIT RECORD ERROR] {e}")


@audit_bp.route("/api/audit/log", methods=["POST"])
def log_action():
    data        = request.get_json(silent=True) or {}
    action      = data.get("action", "UNKNOWN")
    description = data.get("description", "")
    meta        = data.get("meta")
    username    = session.get("username") or data.get("username") or "System"
    record_action(action, description, username=username, meta=meta, ip=client_ip())
    return jsonify({"success": True})


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


@audit_bp.route("/api/audit/clear", methods=["DELETE"])
@require_admin
def clear_logs():
    try:
        res = supabase.table("audit_logs").delete().neq("id", 0).execute()
        return jsonify({"success": True, "deleted": len(res.data or [])})
    except Exception as e:
        print(f"[AUDIT CLEAR ERROR] {e}")
        return jsonify({"error": str(e)}), 500