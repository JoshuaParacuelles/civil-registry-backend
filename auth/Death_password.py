import bcrypt
from flask import Blueprint, jsonify, request, session

from logs.Audits import audit_action, set_audit_context
from supabase_client import supabase

death_archive_bp = Blueprint("death_archive", __name__)

SEED_MODULES = ["death_record", "archive_death"]


# ─── Password helpers ────────────────────────────────────────────────────────

def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(12)).decode("utf-8")


def _verify_password(plain_password: str, stored_hash) -> bool:
    try:
        plain_bytes = plain_password.encode("utf-8")
        hash_bytes = stored_hash if isinstance(stored_hash, (bytes, bytearray)) else str(stored_hash).encode("utf-8")
        return bcrypt.checkpw(plain_bytes, hash_bytes)
    except Exception as e:
        print(f"[ERROR] Password verify failed: {e}")
        return False


# ─── DB initialisation ───────────────────────────────────────────────────────

def init_death_archive_db():
    print("[init_death_archive_db] no default passwords are seeded")


# ─── VERIFY PASSWORD ──────────────────────────────────────────────────────────

@death_archive_bp.route("/api/death/auth/verify", methods=["POST"])
@audit_action("MODULE_PASSWORD_VERIFICATION", resource_type="module_password")
def verify_module_password():
    try:
        data = request.get_json(silent=True) or {}
        module = data.get("module", "").strip()
        password = data.get("password", "").strip()
        set_audit_context(resource_id=module or "death_module", meta={"module": module})

        if module not in SEED_MODULES:
            return jsonify({"success": False, "message": "Unknown module."}), 400
        if not password:
            return jsonify({"success": False, "message": "Password is required."}), 400

        res = supabase.table("module_passwords").select("password_hash").eq("module_key", module).execute()
        row = res.data[0] if res.data else None

        if not row or not row.get("password_hash"):
            return jsonify({
                "success": False,
                "message": "No password is set for this module. Ask an administrator to set one.",
                "code": "NOT_CONFIGURED"
            }), 404

        stored_hash = row["password_hash"]

        if _verify_password(password, stored_hash):
            return jsonify({"success": True, "message": "Password verified successfully."}), 200

        return jsonify({"success": False, "message": "Incorrect password."}), 401

    except Exception as e:
        print(f"[verify_module_password] ERROR: {e}")
        return jsonify({"success": False, "message": f"Server error: {str(e)}"}), 500


# ─── CHANGE PASSWORD ──────────────────────────────────────────────────────────

@death_archive_bp.route("/api/death/change-module-password", methods=["POST"])
@audit_action("MODULE_PASSWORD_CHANGED", resource_type="module_password")
def change_module_password():
    try:
        data = request.get_json(silent=True) or {}
        module = data.get("module", "").strip()
        current_password = data.get("currentPassword", "").strip()
        new_password = data.get("newPassword", "").strip()
        set_audit_context(resource_id=module or "death_module", meta={"module": module})

        if module not in SEED_MODULES:
            return jsonify({"success": False, "message": "Unknown module."}), 400
        if not new_password:
            return jsonify({"success": False, "message": "New password is required."}), 400
        if len(new_password) < 6:
            return jsonify({"success": False, "message": "New password must be at least 6 characters."}), 400
        if current_password and current_password == new_password:
            return jsonify({"success": False, "message": "New password must be different from current password."}), 400

        res = supabase.table("module_passwords").select("password_hash").eq("module_key", module).execute()
        row = res.data[0] if res.data else None

        if not row or not row.get("password_hash"):
            if not session.get("is_admin"):
                return jsonify({"success": False, "message": "Only an administrator can set the first password."}), 403
            supabase.table("module_passwords").insert({
                "module_key": module,
                "password_hash": _hash_password(new_password),
            }).execute()
            return jsonify({"success": True, "message": "Password created."}), 200

        if not current_password:
            return jsonify({"success": False, "message": "Current password is required."}), 400

        stored_hash = row["password_hash"]

        if not _verify_password(current_password, stored_hash):
            return jsonify({"success": False, "message": "Current password is incorrect.", "code": "INVALID_PASSWORD"}), 401

        new_hash = _hash_password(new_password)
        supabase.table("module_passwords").update({
            "password_hash": new_hash,
        }).eq("module_key", module).execute()

        labels = {
            "death_record": "Death Record",
            "archive_death": "Archive Death",
        }

        return jsonify({
            "success": True,
            "message": f"{labels.get(module, module)} password updated successfully."
        }), 200

    except Exception as e:
        print(f"[change_module_password] ERROR: {e}")
        return jsonify({"success": False, "message": f"Server error: {str(e)}"}), 500