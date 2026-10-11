import bcrypt
from flask import Blueprint, jsonify, request, session

from logs.Audits import audit_action, set_audit_context
from supabase_client import supabase

marriage_auth_bp = Blueprint("marriage_auth_bp", __name__)

SEED_MODULES = ["marriage_record", "archive_marriage"]


# ─────────────────────────────────────────────
# Password helpers
# ─────────────────────────────────────────────

def _hash(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(12)).decode("utf-8")


def _verify(plain: str, hashed) -> bool:
    try:
        if not plain or not hashed:
            return False

        plain_bytes = plain.encode("utf-8")
        hash_bytes = hashed if isinstance(hashed, (bytes, bytearray)) else str(hashed).encode("utf-8")

        if not hash_bytes.startswith(b"$2"):
            return False

        return bcrypt.checkpw(plain_bytes, hash_bytes)
    except Exception as e:
        print(f"[_verify] bcrypt error: {e}")
        return False


# ─────────────────────────────────────────────
# Seeding / repair
# ─────────────────────────────────────────────

def seed_module_passwords():
    """Migrate any legacy plaintext `password` to a bcrypt hash. Never creates a default."""
    for mod in SEED_MODULES:
        res = supabase.table("module_passwords").select("id, password_hash, password").eq("module_key", mod).execute()
        row = res.data[0] if res.data else None
        if not row:
            continue
        hash_ok = bool(row.get("password_hash") and str(row["password_hash"]).startswith("$2"))
        legacy = row.get("password")
        if not hash_ok and legacy:
            supabase.table("module_passwords").update({
                "password_hash": _hash(legacy), "password": None,
            }).eq("id", row["id"]).execute()
        elif legacy is not None:
            supabase.table("module_passwords").update({"password": None}).eq("id", row["id"]).execute()


# NOTE: marriage_records table creation removed — routes/marriage.py already
# created it via marriage_schema.sql with the full ~50-column schema. Creating
# or touching it again here, with a different column set, risked writing
# incompatible rows into the same table.

def init_marriage_archive_db():
    seed_module_passwords()
    print("[init_marriage_archive_db] ready")


# ─────────────────────────────────────────────
# AUTH ROUTES
# ─────────────────────────────────────────────

@marriage_auth_bp.route("/api/marriage/auth/verify", methods=["POST"])
@audit_action("MODULE_PASSWORD_VERIFICATION", resource_type="module_password")
def verify_module_password():
    try:
        data = request.get_json(silent=True) or {}
        module = str(data.get("module", "")).strip()
        password = str(data.get("password", "")).strip()
        set_audit_context(resource_id=module or "marriage_module", meta={"module": module})

        if module not in SEED_MODULES:
            return jsonify({"success": False, "message": "Unknown module."}), 400
        if not password:
            return jsonify({"success": False, "message": "Password is required."}), 400

        seed_module_passwords()

        res = supabase.table("module_passwords").select("password_hash").eq("module_key", module).execute()
        row = res.data[0] if res.data else None

        if not row or not row.get("password_hash"):
            return jsonify({"success": False, "message": "No password is set for this module.", "code": "NOT_CONFIGURED"}), 404

        stored_hash = row["password_hash"]

        if _verify(password, stored_hash):
            return jsonify({"success": True, "message": "Password verified successfully."}), 200

        return jsonify({"success": False, "message": "Incorrect password."}), 401

    except Exception as e:
        print(f"[verify_module_password] Error: {e}")
        return jsonify({"success": False, "message": f"Server error: {e}"}), 500


@marriage_auth_bp.route("/api/marriage/change-module-password", methods=["POST"])
@audit_action("MODULE_PASSWORD_CHANGED", resource_type="module_password")
def change_marriage_module_password():
    try:
        data = request.get_json(silent=True) or {}
        module = str(data.get("module", "")).strip()
        current_pw = str(data.get("currentPassword", "")).strip()
        new_pw = str(data.get("newPassword", "")).strip()
        set_audit_context(resource_id=module or "marriage_module", meta={"module": module})

        if module not in SEED_MODULES:
            return jsonify({"success": False, "message": "Unknown module."}), 400
        if not new_pw:
            return jsonify({"success": False, "message": "New password is required."}), 400
        if len(new_pw) < 6:
            return jsonify({"success": False, "message": "New password must be at least 6 characters."}), 400
        if current_pw and current_pw == new_pw:
            return jsonify({"success": False, "message": "New password must be different from current password."}), 400

        seed_module_passwords()

        res = supabase.table("module_passwords").select("id, password_hash").eq("module_key", module).execute()
        row = res.data[0] if res.data else None

        if not row or not row.get("password_hash"):
            if not session.get("is_admin"):
                return jsonify({"success": False, "message": "Only an administrator can set the first password."}), 403
            supabase.table("module_passwords").insert({
                "module_key": module,
                "password_hash": _hash(new_pw),
                "password": None,
            }).execute()
            return jsonify({"success": True, "message": "Password created."}), 200

        if not current_pw:
            return jsonify({"success": False, "message": "Current password is required."}), 400

        if not _verify(current_pw, row["password_hash"]):
            return jsonify({"success": False, "message": "Current password is incorrect.", "code": "INVALID_PASSWORD"}), 401

        supabase.table("module_passwords").update({
            "password_hash": _hash(new_pw),
            "password": None,
        }).eq("id", row["id"]).execute()

        return jsonify({"success": True, "message": "Password updated successfully."}), 200

    except Exception as e:
        print(f"[change_marriage_module_password] Error: {e}")
        return jsonify({"success": False, "message": f"Server error: {e}"}), 500