import bcrypt
from flask import Blueprint, jsonify, request

from supabase_client import supabase

death_archive_bp = Blueprint("death_archive", __name__)

SEED_MODULES = ["death_record", "archive_death"]
DEFAULT_PASSWORD = "123456"


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
    try:
        for module in SEED_MODULES:
            res = supabase.table("module_passwords").select("id").eq("module_key", module).execute()
            if not res.data:
                supabase.table("module_passwords").insert({
                    "module_key": module,
                    "password_hash": _hash_password(DEFAULT_PASSWORD),
                }).execute()
                print(f"[init_death_archive_db] Seeded: {module}")
            else:
                print(f"[init_death_archive_db] Already exists: {module}")
    except Exception as e:
        print(f"[init_death_archive_db] ERROR: {e}")


# ─── VERIFY PASSWORD ──────────────────────────────────────────────────────────

@death_archive_bp.route("/api/death/auth/verify", methods=["POST"])
def verify_module_password():
    try:
        data = request.get_json(silent=True) or {}
        module = data.get("module", "").strip()
        password = data.get("password", "").strip()

        if module not in SEED_MODULES:
            return jsonify({"success": False, "message": "Unknown module."}), 400
        if not password:
            return jsonify({"success": False, "message": "Password is required."}), 400

        res = supabase.table("module_passwords").select("password_hash").eq("module_key", module).execute()
        row = res.data[0] if res.data else None

        if row is None:
            default_hash = _hash_password(DEFAULT_PASSWORD)
            # Mirrors the original's ON DUPLICATE KEY UPDATE password_hash = password_hash
            # (i.e. insert-if-missing, never clobber a hash that already exists).
            existing = supabase.table("module_passwords").select("id").eq("module_key", module).execute()
            if not existing.data:
                supabase.table("module_passwords").insert({
                    "module_key": module,
                    "password_hash": default_hash,
                }).execute()
            res = supabase.table("module_passwords").select("password_hash").eq("module_key", module).execute()
            row = res.data[0] if res.data else None

        if not row:
            return jsonify({"success": False, "message": "Password record not found."}), 404

        stored_hash = row["password_hash"]

        if _verify_password(password, stored_hash):
            return jsonify({"success": True, "message": "Password verified successfully."}), 200

        return jsonify({"success": False, "message": "Incorrect password."}), 401

    except Exception as e:
        print(f"[verify_module_password] ERROR: {e}")
        return jsonify({"success": False, "message": f"Server error: {str(e)}"}), 500


# ─── CHANGE PASSWORD ──────────────────────────────────────────────────────────

@death_archive_bp.route("/api/death/change-module-password", methods=["POST"])
def change_module_password():
    try:
        data = request.get_json(silent=True) or {}
        module = data.get("module", "").strip()
        current_password = data.get("currentPassword", "").strip()
        new_password = data.get("newPassword", "").strip()

        if module not in SEED_MODULES:
            return jsonify({"success": False, "message": "Unknown module."}), 400
        if not current_password:
            return jsonify({"success": False, "message": "Current password is required."}), 400
        if not new_password:
            return jsonify({"success": False, "message": "New password is required."}), 400
        if len(new_password) < 6:
            return jsonify({"success": False, "message": "New password must be at least 6 characters."}), 400
        if current_password == new_password:
            return jsonify({"success": False, "message": "New password must be different from current password."}), 400

        res = supabase.table("module_passwords").select("password_hash").eq("module_key", module).execute()
        row = res.data[0] if res.data else None

        if not row:
            return jsonify({"success": False, "message": "Module password record not found."}), 404

        stored_hash = row["password_hash"]

        if not _verify_password(current_password, stored_hash):
            return jsonify({"success": False, "message": "Current password is incorrect."}), 401

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