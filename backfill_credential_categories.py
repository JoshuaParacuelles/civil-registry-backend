# backend/backfill_credential_categories.py
"""
One-time fix: fill in missing 'category' values on legacy credentials.

Dry run (default, writes nothing):
    python backfill_credential_categories.py

Apply:
    python backfill_credential_categories.py --apply
"""
import argparse
import json
from pathlib import Path

from dotenv import load_dotenv

# Must run BEFORE importing supabase_client (it reads SUPABASE_URL/KEY at import time).
load_dotenv(Path(__file__).resolve().parent / ".env")

from supabase_client import supabase  # noqa: E402

# Copied from auth/Rolemanagement.py so this script does not import the app
# modules. Keep these in sync if the categories change there.
CATEGORY_MODULES = {
    "vital": {
        "birth_verification", "birth_archive_uploader",
        "death_verification", "death_archive_uploader",
        "marriage_verification", "marriage_archive_uploader",
    },
    "document": {
        "document_stage_registration", "document_stage_civil_registrar",
        "document_stage_posting_period", "document_stage_records_division",
        "document_stage_registry_number", "document_stage_releasing",
        "document_tracking",
    },
}
RESERVED_ADMIN_USERNAME = "admin"


def parse_permissions(val):
    if not val:
        return []
    if isinstance(val, list):
        return val
    try:
        return json.loads(val)
    except Exception:
        return []


def get_role_category(role):
    perms = set(parse_permissions(role.get("permissions")))
    if role.get("name") == "Administrator" or "role_management" in perms or "user_management" in perms:
        return "admin"
    if perms & CATEGORY_MODULES["document"]:
        return "document"
    if perms & CATEGORY_MODULES["vital"]:
        return "vital"
    return "other"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    roles = {
        r["id"]: r
        for r in (supabase.table("roles").select("id, name, permissions").execute().data or [])
    }
    assignments = (
        supabase.table("user_roles").select("id, username, role_id, category").execute().data or []
    )

    # Step 1: user_roles rows with no category
    role_fixes = []
    for a in assignments:
        if a.get("category"):
            continue
        role = roles.get(a["role_id"])
        if not role:
            print(f"[SKIP] user_roles id {a['id']}: role {a['role_id']} not found")
            continue
        role_fixes.append((a["id"], a["username"], get_role_category(role)))

    # Categories each username holds, existing plus the ones being fixed
    cats_by_user = {}
    for a in assignments:
        if a.get("category"):
            cats_by_user.setdefault(a["username"], set()).add(a["category"])
    for _, uname, cat in role_fixes:
        cats_by_user.setdefault(uname, set()).add(cat)

    # Step 2: users rows with no category
    user_fixes = []
    users = supabase.table("users").select("id, username, category").execute().data or []
    for u in users:
        if u.get("category"):
            continue
        uname = u["username"]
        cats = cats_by_user.get(uname, set())
        if uname.lower() == RESERVED_ADMIN_USERNAME and not cats:
            cats = {"admin"}
        if len(cats) == 1:
            user_fixes.append((u["id"], uname, next(iter(cats))))
        else:
            print(f"[REVIEW] users '{uname}' (id {u['id']}): categories {sorted(cats) or 'none'}, fix manually")

    for row_id, uname, cat in role_fixes:
        print(f"[user_roles] '{uname}' id {row_id} -> {cat}")
    for row_id, uname, cat in user_fixes:
        print(f"[users]      '{uname}' id {row_id} -> {cat}")

    if args.apply:
        for row_id, _, cat in role_fixes:
            supabase.table("user_roles").update({"category": cat}).eq("id", row_id).execute()
        for row_id, _, cat in user_fixes:
            supabase.table("users").update({"category": cat}).eq("id", row_id).execute()
        print(f"Done. {len(role_fixes)} assignment(s) and {len(user_fixes)} account(s) updated.")
    else:
        print(f"Dry run: {len(role_fixes)} assignment(s), {len(user_fixes)} account(s) would be updated. Re-run with --apply.")


if __name__ == "__main__":
    main()