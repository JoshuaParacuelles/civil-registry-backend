import bcrypt
from flask import Blueprint, jsonify, request, session

from logs.Audits import audit_action, set_audit_context
from supabase_client import supabase

birth_archive_bp = Blueprint("birth_archive", __name__)

SEED_MODULES = ["birth_record", "archive_birth"]


def _hash(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(12)).decode("utf-8")


def _verify(plain: str, hashed) -> bool:
    try:
        hash_bytes = hashed if isinstance(hashed, (bytes, bytearray)) else str(hashed).encode("utf-8")
        return bcrypt.checkpw(plain.encode("utf-8"), hash_bytes)
    except Exception as e:
        print(f"[_verify] bcrypt error: {e}")
        return False


def init_birth_archive_db():
    # Kept so app.py's call still works. No default password is created.
    # An admin sets the first password via /api/birth/change-module-password.
    print("[init_birth_archive_db] no default passwords are seeded")


@birth_archive_bp.route("/api/birth/auth/verify", methods=["POST"])
@audit_action("MODULE_PASSWORD_VERIFICATION", resource_type="module_password")
def verify_module_password():
    data     = request.get_json(silent=True) or {}
    module   = data.get("module",   "").strip()
    password = data.get("password", "").strip()
    set_audit_context(resource_id=module or "birth_module", meta={"module": module})

    if module not in SEED_MODULES:
        return jsonify({"success": False, "message": "Unknown module."}), 400
    if not password:
        return jsonify({"success": False, "message": "Password is required."}), 400

    res = supabase.table("module_passwords").select("password_hash").eq("module_key", module).execute()
    row = res.data[0] if res.data else None

    if not row or not row.get("password_hash"):
        return jsonify({"success": False, "message": "No password is set for this module. Ask an administrator to set one.", "code": "NOT_CONFIGURED"}), 404

    if _verify(password, row["password_hash"]):
        return jsonify({"success": True})
    return jsonify({"success": False, "message": "Incorrect password."}), 401


@birth_archive_bp.route("/api/birth/change-module-password", methods=["POST"])
@audit_action("MODULE_PASSWORD_CHANGED", resource_type="module_password")
def change_module_password():
    data       = request.get_json(silent=True) or {}
    module     = data.get("module",          "").strip()
    current_pw = data.get("currentPassword", "").strip()
    new_pw     = data.get("newPassword",     "").strip()
    set_audit_context(resource_id=module or "birth_module", meta={"module": module})

    if module not in SEED_MODULES:
        return jsonify({"success": False, "message": "Unknown module."}), 400
    if not new_pw or len(new_pw) < 6:
        return jsonify({"success": False, "message": "New password must be at least 6 characters."}), 400

    res = supabase.table("module_passwords").select("password_hash").eq("module_key", module).execute()
    row = res.data[0] if res.data else None

    labels = {"birth_record": "Birth Record", "archive_birth": "Archive Birth"}

    # First-time setup: no row yet -> admin only, no current password needed.
    if not row or not row.get("password_hash"):
        if not session.get("is_admin"):
            return jsonify({"success": False, "message": "Only an administrator can set the first password."}), 403
        supabase.table("module_passwords").insert({
            "module_key": module, "password_hash": _hash(new_pw),
        }).execute()
        return jsonify({"success": True, "message": f"{labels[module]} password created."})

    if not current_pw:
        return jsonify({"success": False, "message": "Current password is required."}), 400
    if current_pw == new_pw:
        return jsonify({"success": False, "message": "New password must differ from current."}), 400
    if not _verify(current_pw, row["password_hash"]):
        return jsonify({"success": False, "message": "Current password is incorrect.", "code": "INVALID_PASSWORD"}), 401

    supabase.table("module_passwords").update({
        "password_hash": _hash(new_pw),
    }).eq("module_key", module).execute()
    return jsonify({"success": True, "message": f"{labels[module]} password updated successfully."})