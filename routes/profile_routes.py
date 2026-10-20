"""Profile routes: display name and profile picture.

- Any signed-in user can read their own profile.
- Only accounts with login credentials (a row in `users`) can change it.
- Administrators can read every member's display name and picture.

The username always comes from the server session, never from the request.
"""
import base64
import binascii
import re
import time
import traceback
from datetime import datetime, timezone
from functools import wraps

import httpx
from flask import Blueprint, Response, jsonify, request, session

from supabase_client import supabase

print("[PROFILE] routes loaded: profile_routes.py", flush=True)

profile_bp = Blueprint("profile", __name__, url_prefix="/api/profile")

TABLE = "user_profiles"
MAX_AVATAR_BYTES = 2 * 1024 * 1024
DISPLAY_NAME_MAX = 100
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_COLUMNS = "username,display_name,avatar_mime,updated_at"


# ── Helpers ──────────────────────────────────────────────────────────────────

def _error(status, message):
    return jsonify(error=message), status


def _retry(fn, attempts=3, delay=0.4):
    """Retry transient socket errors (for example WinError 10035 on Windows)."""
    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except (httpx.TransportError, OSError) as exc:
            last_exc = exc
            if attempt < attempts - 1:
                time.sleep(delay * (attempt + 1))
    raise last_exc


def _sniff_image_type(data: bytes):
    """Identify the image from its magic bytes. The client's Content-Type is never trusted."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


def _clean_display_name(value):
    if not isinstance(value, str):
        return None
    name = " ".join(_CONTROL_CHARS.sub(" ", value).split())
    return name if 1 <= len(name) <= DISPLAY_NAME_MAX else None


def _decode_avatar(stored):
    if not stored:
        return None
    try:
        return base64.b64decode(stored, validate=True)
    except (binascii.Error, ValueError):
        return None


def _fetch_row(username, columns=_COLUMNS):
    res = _retry(lambda: (
        supabase.table(TABLE)
        .select(columns)
        .eq("username", username)
        .limit(1)
        .execute()
    ))
    return res.data[0] if res.data else None


def _has_credentials(username):
    res = _retry(lambda: (
        supabase.table("users")
        .select("username")
        .eq("username", username)
        .limit(1)
        .execute()
    ))
    return bool(res.data)


def _is_admin(username):
    res = _retry(lambda: (
        supabase.table("user_roles")
        .select("role_id")
        .eq("username", username)
        .eq("category", "admin")
        .limit(1)
        .execute()
    ))
    return bool(res.data)


def _summary(row):
    return {
        "display_name": row.get("display_name"),
        "has_avatar": bool(row.get("avatar_mime")),
        "avatar_version": row.get("updated_at"),
    }


def _payload(username, row):
    if not row:
        return {"username": username, "display_name": None,
                "has_avatar": False, "avatar_version": None}
    return {"username": username, **_summary(row)}


def _save(username, fields):
    """Upsert only the given fields, then return the full profile."""
    now = datetime.now(timezone.utc).isoformat()
    _retry(lambda: (
        supabase.table(TABLE)
        .upsert({"username": username, **fields, "updated_at": now}, on_conflict="username")
        .execute()
    ))
    return _payload(username, _fetch_row(username))


def _avatar_response(row):
    image = _decode_avatar(row.get("avatar_data")) if row else None
    if image is None or not row.get("avatar_mime"):
        return _error(404, "No profile picture.")
    response = Response(image, mimetype=row["avatar_mime"])
    response.headers["Cache-Control"] = "private, max-age=31536000, immutable"
    return response


# ── Decorators ───────────────────────────────────────────────────────────────

def guarded(view):
    """Turn unexpected errors into a readable JSON response and print the traceback."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        try:
            return view(*args, **kwargs)
        except Exception as exc:
            print(f"[PROFILE] {view.__name__} failed:", flush=True)
            traceback.print_exc()
            return _error(500, f"Profile error: {exc}")
    return wrapper


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("username"):
            return _error(401, "Not signed in.")
        return view(*args, **kwargs)
    return wrapper


def credentials_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not _has_credentials(session["username"]):
            return _error(403, "Only accounts with login credentials can change their profile.")
        return view(*args, **kwargs)
    return wrapper


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not _is_admin(session["username"]):
            return _error(403, "Administrators only.")
        return view(*args, **kwargs)
    return wrapper


# ── Own profile ──────────────────────────────────────────────────────────────

@profile_bp.get("")
@guarded
@login_required
def get_profile():
    username = session["username"]
    return jsonify(_payload(username, _fetch_row(username)))


@profile_bp.put("")
@guarded
@login_required
@credentials_required
def update_display_name():
    username = session["username"]
    data = request.get_json(silent=True) or {}
    name = _clean_display_name(data.get("display_name"))
    if name is None:
        return _error(400, "Display name must be 1 to 100 characters.")
    return jsonify(_save(username, {"display_name": name}))


@profile_bp.post("/avatar")
@guarded
@login_required
@credentials_required
def upload_avatar():
    username = session["username"]
    file = request.files.get("avatar")
    if file is None:
        return _error(400, "No image was uploaded.")

    data = file.read(MAX_AVATAR_BYTES + 1)
    if len(data) > MAX_AVATAR_BYTES:
        return _error(413, "Image must be 2 MB or smaller.")

    mime = _sniff_image_type(data)
    if mime is None:
        return _error(415, "Only PNG, JPEG, or WebP images are allowed.")

    return jsonify(_save(username, {
        "avatar_data": base64.b64encode(data).decode("ascii"),
        "avatar_mime": mime,
    }))


@profile_bp.delete("/avatar")
@guarded
@login_required
@credentials_required
def remove_avatar():
    return jsonify(_save(session["username"], {"avatar_data": None, "avatar_mime": None}))


@profile_bp.get("/avatar")
@guarded
@login_required
def get_avatar():
    return _avatar_response(_fetch_row(session["username"], "avatar_data,avatar_mime"))


# ── Member profiles for Role Management (administrators only) ────────────────

@profile_bp.get("/users")
@guarded
@login_required
@admin_required
def list_member_profiles():
    res = _retry(lambda: supabase.table(TABLE).select(_COLUMNS).execute())
    return jsonify({row["username"]: _summary(row) for row in (res.data or [])})


@profile_bp.get("/users/<username>/avatar")
@guarded
@login_required
@admin_required
def get_member_avatar(username):
    return _avatar_response(_fetch_row(username, "avatar_data,avatar_mime"))