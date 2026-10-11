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
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash

FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "local_users.json")

try:
    with open(FILE, "r", encoding="utf-8") as f:
        users = json.load(f)
except Exception:
    users = {}

while True:
    username = input("Username (blank to finish): ").strip()
    if not username:
        break

    password = getpass.getpass("Password: ")
    if not password:
        print("Password required.\n")
        continue

    raw_id = input("User ID from Supabase users table (Enter for 1): ").strip()
    user_id = int(raw_id) if raw_id.isdigit() else (raw_id or 1)

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
    print(f"Saved '{username}'.\n")

with open(FILE, "w", encoding="utf-8") as f:
    json.dump(users, f, indent=2)

print(f"Done. Wrote {len(users)} user(s) to {FILE}")