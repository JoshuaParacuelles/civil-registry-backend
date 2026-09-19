from flask import Blueprint, request, jsonify, session
from datetime import datetime
from supabase_client import supabase

audit_bp = Blueprint("audit_bp", __name__)


def init_audit_db():
    """No-op: audit_logs table is created via Supabase SQL Editor, not here."""
    print("[AUDIT] Using Supabase table 'audit_logs' (assumed to already exist)")


def record_action(action, description, username=None, meta=None, ip=None):
    """Insert an audit log entry. Safe to call from any blueprint."""
    try:
        supabase.table("audit_logs").insert({
            "username":    username or "System",
            "action":      action,
            "description": description,
            "meta":        str(meta) if meta else None,
            "ip_address":  ip,
            "created_at":  datetime.now().isoformat(),
        }).execute()
    except Exception as e:
        print(f"[AUDIT RECORD ERROR] {e}")


@audit_bp.route("/api/audit/log", methods=["POST"])
def log_action():
    data        = request.get_json() or {}
    action      = data.get("action", "UNKNOWN")
    description = data.get("description", "")
    meta        = data.get("meta")
    username    = session.get("username") or data.get("username") or "System"
    ip          = request.remote_addr
    record_action(action, description, username=username, meta=meta, ip=ip)
    return jsonify({"success": True})


@audit_bp.route("/api/audit/history", methods=["GET"])
def get_history():
    limit  = min(int(request.args.get("limit", 500)), 1000)
    action = request.args.get("action", "")
    search = request.args.get("search", "")

    try:
        query = supabase.table("audit_logs").select(
            "id, username, action, description, meta, ip_address, created_at"
        )

        if action:
            query = query.eq("action", action)
        if search:
            query = query.or_(f"description.ilike.%{search}%,username.ilike.%{search}%")

        query = query.order("created_at", desc=True).limit(limit)
        res = query.execute()

        return jsonify(res.data)

    except Exception as e:
        print(f"[AUDIT HISTORY ERROR] {e}")
        return jsonify({"error": str(e)}), 500


@audit_bp.route("/api/audit/clear", methods=["DELETE"])
def clear_logs():
    try:
        res = supabase.table("audit_logs").delete().neq("id", 0).execute()
        return jsonify({"success": True, "deleted": len(res.data)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500