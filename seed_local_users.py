"""
Create / update entries in backend/local_users.json so a user can log in
through Flask even if they have NEVER logged in online and Supabase is down.

Run from the backend/ folder:
    python seed_local_users.py

Only the salted hash is stored, never the plain password.
Add local_users.json to .gitignore.
"""
import json
import os
import getpass
import tempfile
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash

FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "local_users.json")

try:
    with open(FILE, "r", encoding="utf-8") as f:
        users = json.load(f)
except FileNotFoundError:
    users = {}
except Exception as e:
    raise SystemExit(
        f"Refusing to overwrite {FILE}: it can't be read ({e}). "
        "Fix or move the file, then run this again."
    )

if not isinstance(users, dict):
    raise SystemExit(
        f"Refusing to overwrite {FILE}: expected a JSON object at the top level."
    )


def save(data):
    """Write atomically so an interrupted run can't leave a truncated file."""
    folder = os.path.dirname(FILE)
    fd, tmp_path = tempfile.mkstemp(dir=folder, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, FILE)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def ask_user_id():
    """Keeps asking until the user enters a positive whole number."""
    while True:
        raw = input("User ID from Supabase users table (required): ").strip()
        if raw.isdigit() and int(raw) > 0:
            return int(raw)
        print("A numeric user ID is required (for example, 12).\n")


while True:
    username = input("Username (blank to finish): ").strip()
    if not username:
        break

    password = getpass.getpass("Password: ")
    if not password:
        print("Password required.\n")
        continue

    user_id = ask_user_id()

    is_admin = input("Is admin? (y/N): ").strip().lower() == "y"
    permissions = ["dashboard"]
    if is_admin or username.lower() == "admin":
        permissions = ["*", "dashboard"]

    users[username.lower()] = {
        "id": user_id,
        "username": username,
        "password": generate_password_hash(password),
        "roles": [],
        "permissions": permissions,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "fail_count": 0,
        "locked_until": None,
    }
    save(users)
    print(f"Saved '{username}'.\n")

print(f"Done. Wrote {len(users)} user(s) to {FILE}")