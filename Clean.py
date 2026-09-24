"""
cleanup.py - tidy the backend/ folder.

Run from the backend/ folder. Everything is a DRY RUN unless you add --apply.

1) Duplicate PDFs (same file content, different UUID prefix)

     python cleanup.py uploads                       # preview only
     python cleanup.py uploads --apply               # move duplicates to _quarantine/
     python cleanup.py uploads --keep-list keep.txt --apply

   * Duplicates are found by SHA-256 of the file CONTENT, so different names
     with identical bytes are caught. Different content is never touched.
   * Nothing is deleted. Duplicates are MOVED into  backend/_quarantine/<timestamp>/
     so you can restore them. Delete that folder yourself once the app has been
     checked and everything still works.
   * IMPORTANT: your database probably stores the file name/path of each PDF.
     If a record points at a file that gets moved, its download link breaks.
     Export the file names your database references into keep.txt
     (one file name per line) and pass --keep-list. Those files are never moved.
     Example query (adjust the table/column to your schema):
         select file_path from marriage_records where file_path is not null;
     Then strip the folder part so only the file name remains.
   * Each folder is handled separately. uploads/marriage_archive looks like
     intentional version history; if so, skip it with:  --dir uploads/marriage

2) Old Flask session files

     python cleanup.py sessions --days 7             # preview
     python cleanup.py sessions --days 7 --apply     # delete
   Only affects users whose session is older than N days (they log in again).
"""

import argparse
import hashlib
import shutil
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

BACKEND = Path(__file__).resolve().parent
DEFAULT_UPLOAD_DIRS = ["uploads/marriage", "uploads/marriage_archive"]


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def sha256_of(path, chunk=1024 * 1024):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(chunk):
            h.update(block)
    return h.hexdigest()


# ------------------------------------------------------------ uploads ---
def cmd_uploads(args):
    keep_names = set()
    if args.keep_list:
        keep_names = {
            line.strip() for line in Path(args.keep_list).read_text(encoding="utf-8").splitlines()
            if line.strip()
        }
        print(f"Keep-list loaded: {len(keep_names)} protected file names.\n")
    elif args.apply:
        print("WARNING: no --keep-list given. Files referenced by your database may be moved.\n")

    dirs = args.dir or DEFAULT_UPLOAD_DIRS
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    quarantine_root = BACKEND / "_quarantine" / stamp

    total_moved, total_bytes = 0, 0

    for d in dirs:
        folder = (BACKEND / d).resolve()
        if not folder.is_dir():
            print(f"[skip] {d} (not found)")
            continue

        files = [p for p in folder.iterdir() if p.is_file()]
        groups = defaultdict(list)
        for p in files:
            groups[sha256_of(p)].append(p)

        dup_groups = {h: ps for h, ps in groups.items() if len(ps) > 1}
        moved, saved = 0, 0

        for ps in dup_groups.values():
            protected = [p for p in ps if p.name in keep_names]
            # keep every protected file; otherwise keep the oldest one
            keepers = protected or [min(ps, key=lambda p: (p.stat().st_mtime, p.name))]
            for p in ps:
                if p in keepers:
                    continue
                size = p.stat().st_size
                moved += 1
                saved += size
                if args.apply:
                    dest = quarantine_root / folder.name / p.name
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(p), str(dest))

        print(f"{d}: {len(files)} files, {len(groups)} unique, "
              f"{moved} duplicates ({human(saved)}) {'moved' if args.apply else 'would be moved'}")
        total_moved += moved
        total_bytes += saved

    print(f"\nTotal: {total_moved} duplicate files, {human(total_bytes)}.")
    if args.apply and total_moved:
        print(f"Moved to: {quarantine_root}")
        print("Test the app, then delete that folder when you are sure.")
    elif not args.apply:
        print("Dry run only. Re-run with --apply to actually move them.")


# ----------------------------------------------------------- sessions ---
def cmd_sessions(args):
    folder = (BACKEND / args.dir).resolve()
    if not folder.is_dir():
        print(f"{args.dir} not found.")
        return

    cutoff = time.time() - args.days * 86400
    old = [p for p in folder.iterdir() if p.is_file() and p.stat().st_mtime < cutoff]
    size = sum(p.stat().st_size for p in old)
    total = sum(1 for p in folder.iterdir() if p.is_file())

    print(f"{args.dir}: {total} session files, {len(old)} older than {args.days} days ({human(size)}).")
    if args.apply:
        for p in old:
            p.unlink(missing_ok=True)
        print("Deleted.")
    else:
        print("Dry run only. Re-run with --apply to delete them.")


# --------------------------------------------------------------- main ---
def main():
    parser = argparse.ArgumentParser(description="Backend cleanup helper (dry run by default).")
    sub = parser.add_subparsers(dest="command", required=True)

    up = sub.add_parser("uploads", help="find/move duplicate PDFs")
    up.add_argument("--dir", action="append", help="folder relative to backend/ (repeatable)")
    up.add_argument("--keep-list", help="text file of file names that must never be moved")
    up.add_argument("--apply", action="store_true", help="actually move files")
    up.set_defaults(func=cmd_uploads)

    se = sub.add_parser("sessions", help="delete old flask_session files")
    se.add_argument("--dir", default="flask_session")
    se.add_argument("--days", type=int, default=7)
    se.add_argument("--apply", action="store_true", help="actually delete files")
    se.set_defaults(func=cmd_sessions)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()