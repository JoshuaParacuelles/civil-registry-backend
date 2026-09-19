import bcrypt
from datetime import datetime, timezone
from flask import Blueprint, jsonify, request

from supabase_client import supabase

birth_archive_bp = Blueprint("birth_archive", __name__)

# ─── Password helpers ───────────────────────────────────────────────────────

def _hash(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(12)).decode("utf-8")


def _verify(plain: str, hashed) -> bool:
    try:
        plain_bytes = plain.encode("utf-8")
        hash_bytes = hashed if isinstance(hashed, (bytes, bytearray)) else str(hashed).encode("utf-8")
        return bcrypt.checkpw(plain_bytes, hash_bytes)
    except Exception as e:
        print(f"[_verify] bcrypt error: {e}")
        return False


SEED_MODULES     = ["birth_record", "archive_birth"]
DEFAULT_PASSWORD = "123456"


# ─── DB initialisation ───────────────────────────────────────────────────────
# NOTE: birth_records table creation removed — it's owned by routes/birth.py's
# Supabase migration now. This file only manages module_passwords.

def init_birth_archive_db():
    for mod in SEED_MODULES:
        res = supabase.table("module_passwords").select("id").eq("module_key", mod).execute()
        if not res.data:
            supabase.table("module_passwords").insert({
                "module_key": mod,
                "password_hash": _hash(DEFAULT_PASSWORD),
            }).execute()
            print(f"[init_birth_archive_db] Seeded password for module: {mod}")
        else:
            print(f"[init_birth_archive_db] Module already seeded: {mod}")


# ─── Auth endpoints ──────────────────────────────────────────────────────────

@birth_archive_bp.route("/api/birth/auth/verify", methods=["POST"])
def verify_module_password():
    data     = request.get_json(silent=True) or {}
    module   = data.get("module",   "").strip()
    password = data.get("password", "").strip()

    if module not in SEED_MODULES:
        return jsonify({"success": False, "message": "Unknown module."}), 400
    if not password:
        return jsonify({"success": False, "message": "Password is required."}), 400

    res = supabase.table("module_passwords").select("password_hash").eq("module_key", module).execute()
    row = res.data[0] if res.data else None

    if row is None:
        print(f"[verify_module_password] No row found for module '{module}' — re-seeding.")
        default_hash = _hash(DEFAULT_PASSWORD)
        supabase.table("module_passwords").insert({
            "module_key": module,
            "password_hash": default_hash,
        }).execute()
        if _verify(password, default_hash):
            return jsonify({"success": True})
        return jsonify({"success": False, "message": "Incorrect password."}), 401

    stored_hash = row["password_hash"]
    if _verify(password, stored_hash):
        return jsonify({"success": True})

    return jsonify({"success": False, "message": "Incorrect password."}), 401


@birth_archive_bp.route("/api/change-module-password", methods=["POST"])
def change_module_password():
    data       = request.get_json(silent=True) or {}
    module     = data.get("module",          "").strip()
    current_pw = data.get("currentPassword", "").strip()
    new_pw     = data.get("newPassword",     "").strip()

    if module not in SEED_MODULES:
        return jsonify({"success": False, "message": "Unknown module."}), 400
    if not current_pw:
        return jsonify({"success": False, "message": "Current password is required."}), 400
    if not new_pw or len(new_pw) < 6:
        return jsonify({"success": False, "message": "New password must be at least 6 characters."}), 400
    if current_pw == new_pw:
        return jsonify({"success": False, "message": "New password must differ from current."}), 400

    res = supabase.table("module_passwords").select("password_hash").eq("module_key", module).execute()
    row = res.data[0] if res.data else None

    if not row or not _verify(current_pw, row["password_hash"]):
        return jsonify({"success": False, "message": "Current password is incorrect."}), 401

    supabase.table("module_passwords").update({
        "password_hash": _hash(new_pw),
    }).eq("module_key", module).execute()

    labels = {
        "birth_record":  "Birth Record",
        "archive_birth": "Archive Birth",
    }
    return jsonify({"success": True, "message": f"{labels[module]} password updated successfully."})

# Record CRUD (list_records, upload_record, get_record, download_record,
# archive_record, restore_record, delete_record, list_archived) intentionally
# removed here — routes/birth.py already owns birth_records CRUD against
# Supabase. Tell me if these specific /api/birth/records... endpoints under
# this blueprint are still called separately by the frontend and I'll add
# them back, pointed at the same table with matching columns.