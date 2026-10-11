"""Serves the bcrypt verifiers the browser needs to unlock the Archive offline.
Login required. No plaintext password ever leaves the server."""
from flask import Blueprint, jsonify

from security import login_required_hook
from supabase_client import supabase

offline_credentials_bp = Blueprint("offline_credentials", __name__)
offline_credentials_bp.before_request(login_required_hook)

OFFLINE_MODULES = [
    "birth_record", "archive_birth",
    "death_record", "archive_death",
    "marriage_record", "archive_marriage",
]


@offline_credentials_bp.route("/api/offline-credentials", methods=["GET"])
def get_offline_credentials():
    # Optional: a row keyed "<module>_offline" overrides the normal password
    # for OFFLINE use only (a separate temporary offline password).
    keys = OFFLINE_MODULES + [f"{m}_offline" for m in OFFLINE_MODULES]
    try:
        res = supabase.table("module_passwords") \
            .select("module_key, password_hash") \
            .in_("module_key", keys).execute()
    except Exception as e:
        print(f"[OFFLINE-CREDS] lookup failed: {e}", flush=True)
        return jsonify({"error": "Credential store unavailable"}), 503

    rows = {r["module_key"]: r.get("password_hash") for r in (res.data or [])}
    modules = {}
    for m in OFFLINE_MODULES:
        h = rows.get(f"{m}_offline") or rows.get(m)
        modules[m] = h if h and str(h).startswith("$2") else None
    return jsonify({"modules": modules}), 200