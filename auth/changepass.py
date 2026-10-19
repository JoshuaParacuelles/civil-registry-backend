import hashlib
from flask import Blueprint, request, jsonify, session
from flask_cors import CORS
import bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
from logs.Audits import audit_action, record_action, set_audit_context
from supabase_client import supabase

changepass_bp = Blueprint("changepass_bp", __name__)

# ─────────────────────────────────────────────
# CORS FIX
# ─────────────────────────────────────────────
CORS(
    changepass_bp,
    supports_credentials=True,
    origins=["http://localhost:3000"],
)

# ─────────────────────────────────────────────
# THE REAL BUG (this time)
# ─────────────────────────────────────────────
# Rolemanagement.py hashes/re-hashes the admin password using
# werkzeug's generate_password_hash(), which produces strings like
# "scrypt:32768:8:1$....." or "pbkdf2:sha256:....". This file's
# _verify_password() only ever checked for bcrypt ("$2...") or raw
# sha256 hex — it had no branch for werkzeug's format at all, so a
# correct password against a werkzeug-hashed row always failed with
# "Current password incorrect," even when typed correctly.
#
# Fix: add a werkzeug check_password_hash() branch, and hash NEW
# passwords set from here using the same werkzeug format so both
# files stay consistent going forward.

VALID_MODULES = {
    "archive_birth":    "Archive Birth",
    "archive_marriage": "Marriage Archive",
    "archive_death":    "Death Archive",
}


def _looks_like_werkzeug_hash(s) -> bool:
    if not s or not isinstance(s, str):
        return False
    return s.startswith("scrypt:") or s.startswith("pbkdf2:")


def _verify_werkzeug(plain: str, hashed) -> bool:
    try:
        if not plain or not hashed:
            return False
        hashed_str = hashed.decode("utf-8") if isinstance(hashed, (bytes, bytearray)) else str(hashed)
        if not _looks_like_werkzeug_hash(hashed_str):
            return False
        return check_password_hash(hashed_str, plain)
    except Exception as e:
        print(f"[_verify_werkzeug] error: {e}")
        return False


def _verify_bcrypt(plain: str, hashed) -> bool:
    try:
        if not plain or not hashed:
            return False
        plain_bytes = plain.encode("utf-8")
        hash_bytes = hashed if isinstance(hashed, (bytes, bytearray)) else str(hashed).encode("utf-8")
        if not hash_bytes.startswith(b"$2"):
            return False
        return bcrypt.checkpw(plain_bytes, hash_bytes)
    except Exception as e:
        print(f"[_verify_bcrypt] error: {e}")
        return False


def _hash_bcrypt(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(12)).decode("utf-8")


def _verify_sha256_hex(plain: str, hashed) -> bool:
    """Matches an older Postgres seed:
        encode(digest('admin123', 'sha256'), 'hex')
    a 64-char lowercase hex digest. bcrypt/werkzeug can't check that
    format directly, so this exists for any row that still has it.
    """
    try:
        if not plain or not hashed:
            return False
        hashed_str = hashed.decode("utf-8") if isinstance(hashed, (bytes, bytearray)) else str(hashed)
        hashed_str = hashed_str.strip().lower()
        if len(hashed_str) != 64 or any(c not in "0123456789abcdef" for c in hashed_str):
            return False
        return hashlib.sha256(plain.encode("utf-8")).hexdigest() == hashed_str
    except Exception as e:
        print(f"[_verify_sha256_hex] error: {e}")
        return False


def _verify_password(plain: str, stored) -> bool:
    """
    Tries every supported hash format in order: werkzeug (scrypt/pbkdf2 —
    what Rolemanagement.py actually writes), bcrypt, then sha256-hex.
    Stored plaintext is never accepted.
    """
    stored_str = stored.decode("utf-8") if isinstance(stored, (bytes, bytearray)) else str(stored)
    print(
        f"[_verify_password] stored_len={len(stored_str)} "
        f"looks_like_werkzeug={_looks_like_werkzeug_hash(stored_str)} "
        f"looks_like_bcrypt={stored_str.startswith('$2')} "
        f"looks_like_sha256={len(stored_str) == 64}"
    )

    if _verify_werkzeug(plain, stored):
        print("[_verify_password] matched via werkzeug (scrypt/pbkdf2)")
        return True
    if _verify_bcrypt(plain, stored):
        print("[_verify_password] matched via bcrypt")
        return True
    if _verify_sha256_hex(plain, stored):
        print("[_verify_password] matched via sha256")
        return True

    print("[_verify_password] no match against any known hash format")
    return False


def _hash_new_password(plain: str) -> str:
    """New passwords set from this file are stored in the SAME
    werkzeug format Rolemanagement.py uses, so future logins/verifies
    from either file stay consistent instead of drifting between
    bcrypt and werkzeug hashes."""
    return generate_password_hash(plain)


def _err(message, code, http_status):
    return jsonify({"success": False, "message": message, "code": code}), http_status


def _supabase_error_response(e):
    """Standard response when a Supabase call itself throws (network
    issue, RLS rejection, bad table/column name, etc.) — distinct from
    a normal 'no rows found' result, which is not an error at all."""
    print("[SUPABASE ERROR]", e)
    return _err("Database error. Please try again.", "SERVER_ERROR", 500)


def _log_password_event(status, description, username, *, resource_id=None, meta=None):
    record_action(
        "PASSWORD_CHANGED",
        description,
        username=username,
        status=status,
        resource_type="account",
        resource_id=resource_id,
        meta=meta,
    )


@changepass_bp.route("/api/change-password", methods=["POST"])
def change_password():
    data = request.get_json(silent=True) or {}

    current_username = (session.get("username") or "").strip()
    current_password = (data.get("currentPassword") or "").strip()
    new_password      = (data.get("newPassword") or "").strip()
    new_username      = (data.get("newUsername") or "").strip()

    print(f"[change_password] session username='{current_username}'")

    if not current_username:
        return _err("User not logged in", "NOT_LOGGED_IN", 401)

    if not current_password:
        _log_password_event("FAILED", "Password change rejected: current password missing",
                            current_username, meta={"reason": "missing_current_password"})
        return _err("Current password is required", "VALIDATION_ERROR", 400)

    try:
        res = supabase.table("users").select("id, username, password") \
            .eq("username", current_username).limit(1).execute()
    except Exception as e:
        _log_password_event("FAILED", "Password change failed: database unavailable",
                            current_username, meta={"reason": "database_error"})
        return _supabase_error_response(e)

    if not res.data:
        return _err("User not found", "NOT_LOGGED_IN", 401)

    user = res.data[0]
    stored_password = user["password"]
    print(f"[change_password] fetched row for username='{user['username']}' id={user['id']}")

    if not _verify_password(current_password, stored_password):
        _log_password_event("FAILED", "Password change failed: current password incorrect",
                            current_username, resource_id=user["id"],
                            meta={"reason": "invalid_current_password"})
        return _err("Current password incorrect", "INVALID_PASSWORD", 403)

    if not new_username:
        new_username = current_username

    changing_username = new_username != current_username
    changing_password = bool(new_password)

    if not changing_username and not changing_password:
        return _err("No changes detected", "VALIDATION_ERROR", 400)

    if changing_username:
        try:
            existing = supabase.table("users").select("id") \
                .eq("username", new_username).limit(1).execute()
        except Exception as e:
            _log_password_event("FAILED", "Account update failed: database unavailable",
                                current_username, resource_id=user["id"],
                                meta={"reason": "database_error"})
            return _supabase_error_response(e)
        if existing.data:
            _log_password_event("FAILED", "Account update failed: username already taken",
                                current_username, resource_id=user["id"],
                                meta={"reason": "username_taken"})
            return _err("Username already taken", "USERNAME_TAKEN", 409)

    final_password = stored_password
    if changing_password:
        if len(new_password) < 6:
            _log_password_event("FAILED", "Password change rejected: password too short",
                                current_username, resource_id=user["id"],
                                meta={"reason": "password_too_short"})
            return _err("New password must be at least 6 characters", "VALIDATION_ERROR", 400)
        if new_password == current_password:
            _log_password_event("FAILED", "Password change rejected: same as current password",
                                current_username, resource_id=user["id"],
                                meta={"reason": "password_unchanged"})
            return _err("New password must be different from current password", "VALIDATION_ERROR", 400)
        final_password = _hash_new_password(new_password)

    try:
        supabase.table("users").update({
            "username": new_username,
            "password": final_password,
        }).eq("id", user["id"]).execute()

        # user_roles.username is keyed by string, so a rename must follow it.
        if changing_username:
            supabase.table("user_roles").update({
                "username": new_username
            }).eq("username", current_username).execute()
    except Exception as e:
        _log_password_event("FAILED", "Account update failed: database error",
                            current_username, resource_id=user["id"],
                            meta={"reason": "database_error"})
        return _supabase_error_response(e)

    if changing_password:
        _log_password_event("SUCCESS", "Password changed", new_username,
                            resource_id=user["id"])
    if changing_username:
        record_action(
            "ACCOUNT_UPDATED",
            "Username changed",
            username=new_username,
            resource_type="account",
            resource_id=user["id"],
            old_value={"username": current_username},
            new_value={"username": new_username},
        )

    session["username"] = new_username

    return jsonify({
        "success": True,
        "message": "Account updated successfully",
        "username": new_username
    }), 200


@changepass_bp.route("/api/change-module-password", methods=["POST"])
def change_module_password():
    data = request.get_json(silent=True) or {}

    module     = (data.get("module") or "").strip()
    current_pw = (data.get("currentPassword") or "").strip()
    new_pw     = (data.get("newPassword") or "").strip()
    label      = VALID_MODULES.get(module, module)

    def _fail(description, reason, http_status, message, code):
        record_action(
            "PASSWORD_CHANGED",
            f"{label} password change failed: {description}",
            username=session.get("username"),
            status="FAILED",
            resource_type="module_password",
            resource_id=module,
            meta={"module": module, "reason": reason},
        )
        return _err(message, code, http_status)

    if module not in VALID_MODULES:
        return _err("Unknown module.", "VALIDATION_ERROR", 400)

    if not current_pw:
        return _fail("current password missing", "missing_current_password", 400,
                     "Current password is required.", "VALIDATION_ERROR")

    if not new_pw:
        return _fail("new password missing", "missing_new_password", 400,
                     "New password is required.", "VALIDATION_ERROR")

    if len(new_pw) < 6:
        return _fail("password too short", "password_too_short", 400,
                     "New password must be at least 6 characters.", "VALIDATION_ERROR")

    if current_pw == new_pw:
        return _fail("same as current password", "password_unchanged", 400,
                     "New password must differ from current.", "VALIDATION_ERROR")

    try:
        res = supabase.table("module_passwords").select("password_hash") \
            .eq("module_key", module).limit(1).execute()
    except Exception as e:
        return _fail("database unavailable", "database_error", 500,
                     "Database error. Please try again.", "SERVER_ERROR")

    if not res.data:
        return _fail("no password record", "no_record", 404,
                     f"No password record found for '{label}'. "
                     "Please seed module_passwords for this module first.", "NOT_FOUND")

    stored_hash = res.data[0]["password_hash"]

    if not stored_hash or not str(stored_hash).startswith("$2"):
        return _fail("stored password invalid", "invalid_record", 500,
                     "Password record is invalid or corrupted.", "SERVER_ERROR")

    if not _verify_bcrypt(current_pw, stored_hash):
        return _fail("current password incorrect", "invalid_current_password", 403,
                     "Current password is incorrect.", "INVALID_PASSWORD")

    new_hash = _hash_bcrypt(new_pw)

    try:
        supabase.table("module_passwords").update({
            "password_hash": new_hash
        }).eq("module_key", module).execute()
    except Exception as e:
        return _fail("database write failed", "database_error", 500,
                     "Database error. Please try again.", "SERVER_ERROR")

    record_action(
        "PASSWORD_CHANGED",
        f"{label} password changed",
        username=session.get("username"),
        resource_type="module_password",
        resource_id=module,
        meta={"module": module},
    )
    return jsonify({
        "success": True,
        "message": f"{label} password updated successfully."
    }), 200