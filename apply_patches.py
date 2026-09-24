"""
apply_patches.py - applies small, targeted fixes to routes/marriage_death_birth.py

Run from the backend/ folder:

    python apply_patches.py            # preview: shows which patches would apply
    python apply_patches.py --apply    # writes the file (makes a .bak backup first)

    python apply_patches.py --file routes/some_other_name.py --apply

Safety:
  * Every patch must match EXACTLY ONE place in the file, otherwise it is
    skipped and reported (nothing is guessed).
  * Patches already applied are detected and skipped, so re-running is safe.
  * The patched code is compiled before writing; if it would not be valid
    Python, nothing is written.
  * A backup is saved as <file>.bak before any change.

WHAT THE PATCHES DO
  1. BIRTH  complete_transaction: match the online request using the names stored
            on the record (child_first_name / child_last_name) instead of
            splitting the typed name at the first space. "Maria Luz Santos"
            used to be split as first="Maria", last="Luz Santos" and never matched.
  2. MARRIAGE _matches_online_marriage_request: groom AND bride must match the
            same online request. Before, EITHER name alone was enough, so a
            different couple sharing one name triggered a false notification.
  3. DEATH  push_notification call: lowercase record_type, a real title, and
            control_no no longer falls back to a person's name.
  4. ADMIN  /api/marriage/admin/* maintenance routes now require a logged-in
            session (set ADMIN_ROUTES_REQUIRE_LOGIN=0 to switch off while testing).
"""

import argparse
import shutil
import sys
from pathlib import Path

NEW_MARRIAGE_MATCHER = '''def _matches_online_marriage_request(groom_full_name: Optional[str] = None,
                                      bride_full_name: Optional[str] = None,
                                      control_no: Optional[str] = None) -> bool:
    """Groom AND bride must match the SAME online request row.
    (Previously either name alone was enough, which caused false notifications.)"""
    try:
        if control_no:
            res = supabase.table(CIVIL_REGISTRY_REQUEST_TABLE).select("id") \\
                .eq("record_type", "marriage").eq("control_no", control_no).limit(1).execute()
            if res.data:
                return True

        groom = (groom_full_name or "").strip()
        bride = (bride_full_name or "").strip()
        if not groom and not bride:
            return False

        q = supabase.table(CIVIL_REGISTRY_REQUEST_TABLE).select("id").eq("record_type", "marriage")
        if groom:
            q = q.ilike("husband_fullname", groom)
        if bride:
            q = q.ilike("wife_maiden_name", bride)
        return bool(q.limit(1).execute().data)
    except Exception:
        return False'''

ADMIN_REQUIRED_DEF = '''def get_user():
    return session.get("username", "System")


def admin_required(fn):
    """Blocks the /admin/* maintenance routes unless someone is logged in.
    Set ADMIN_ROUTES_REQUIRE_LOGIN=0 to disable while testing.
    Add a role check here too if your login stores a role in the session."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if os.getenv("ADMIN_ROUTES_REQUIRE_LOGIN", "1") == "1" and not session.get("username"):
            return jsonify({"error": "Authentication required."}), 401
        return fn(*args, **kwargs)
    return wrapper
'''

# (name, old, new)
SIMPLE_PATCHES = [
    (
        "imports: add functools.wraps",
        "import hashlib\nfrom datetime import datetime\n",
        "import hashlib\nfrom functools import wraps\nfrom datetime import datetime\n",
    ),
    (
        "admin_required decorator",
        'def get_user():\n    return session.get("username", "System")\n',
        ADMIN_REQUIRED_DEF,
    ),
    ("guard admin_repair_paths", "def admin_repair_paths():",
     "@admin_required\ndef admin_repair_paths():"),
    ("guard admin_debug_paths", "def admin_debug_paths():",
     "@admin_required\ndef admin_debug_paths():"),
    ("guard admin_backfill_is_archived", "def admin_backfill_is_archived():",
     "@admin_required\ndef admin_backfill_is_archived():"),
    ("guard admin_is_archived_status", "def admin_is_archived_status():",
     "@admin_required\ndef admin_is_archived_status():"),
    ("guard admin_set_archived", "def admin_set_archived():",
     "@admin_required\ndef admin_set_archived():"),
    (
        "birth: match online request by record names",
        "        if payment_status == 'positive' and _matches_online_birth_request(\n"
        "            first_name, last_name, control_no=payment_reference or None\n"
        "        ):\n",
        "        match_first, match_last = first_name, last_name\n"
        "        if record_id:\n"
        "            _rec = supabase.table(\"birth_records\").select(\"child_first_name, child_last_name\") \\\n"
        "                .eq(\"id\", record_id).limit(1).execute().data\n"
        "            if _rec:\n"
        "                match_first = _rec[0].get(\"child_first_name\") or first_name\n"
        "                match_last  = _rec[0].get(\"child_last_name\") or last_name\n"
        "\n"
        "        if payment_status == 'positive' and _matches_online_birth_request(\n"
        "            match_first, match_last, control_no=payment_reference or None\n"
        "        ):\n",
    ),
    ("death: record_type lowercase", 'record_type="DEATH",', 'record_type="death",'),
    (
        "death: control_no no longer falls back to a name",
        "                control_no=payment_reference or search_operator or None,\n"
        "                message=f\"Death certificate issued for '{subject}'\",\n",
        "                control_no=payment_reference or None,\n"
        "                message=f\"Death certificate issued for '{subject}'\",\n",
    ),
    (
        "death: proper title instead of legacy notif_type",
        '                notif_type="death",\n',
        '                title="Death Certificate Issued",\n',
    ),
]


def patch_marriage_matcher(src):
    """Returns (status, new_src). Replaces the whole function body."""
    marker = "SAME online request row"
    if marker in src:
        return "already applied", src
    start_token = "def _matches_online_marriage_request("
    if src.count(start_token) != 1:
        return f"SKIPPED (found {src.count(start_token)} definitions)", src
    start = src.index(start_token)
    end = src.find("\n\n\n# ####", start)
    if end == -1:
        return "SKIPPED (could not find end of function)", src
    return "ok", src[:start] + NEW_MARRIAGE_MATCHER + src[end:]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default="routes/marriage_death_birth.py")
    ap.add_argument("--apply", action="store_true", help="write changes (default: preview only)")
    args = ap.parse_args()

    path = Path(args.file)
    if not path.is_file():
        print(f"File not found: {path}")
        sys.exit(1)

    src = path.read_text(encoding="utf-8")
    new_src = src
    applied = skipped = already = 0

    for name, old, new in SIMPLE_PATCHES:
        if new in new_src:
            print(f"[already applied] {name}")
            already += 1
            continue
        n = new_src.count(old)
        if n != 1:
            print(f"[SKIPPED]         {name}  (expected 1 match, found {n})")
            skipped += 1
            continue
        new_src = new_src.replace(old, new, 1)
        print(f"[ok]              {name}")
        applied += 1

    status, new_src = patch_marriage_matcher(new_src)
    label = "marriage: require groom AND bride to match"
    if status == "ok":
        print(f"[ok]              {label}")
        applied += 1
    elif status == "already applied":
        print(f"[already applied] {label}")
        already += 1
    else:
        print(f"[{status}] {label}")
        skipped += 1

    print(f"\n{applied} to apply, {already} already applied, {skipped} skipped.")

    if applied == 0:
        return

    try:
        compile(new_src, str(path), "exec")
    except SyntaxError as e:
        print(f"\nPatched code would not compile ({e}). Nothing written.")
        sys.exit(1)

    if not args.apply:
        print("Preview only. Re-run with --apply to write the changes.")
        return

    backup = path.with_suffix(path.suffix + ".bak")
    shutil.copy2(path, backup)
    path.write_text(new_src, encoding="utf-8")
    print(f"Written. Backup saved to {backup}")


if __name__ == "__main__":
    main()