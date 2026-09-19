"""
fix_password.py
===============
Run this ONCE to insert/reset ALL module passwords to "123456".
Covers Birth, Marriage, and Death modules.

KEY FIX in this version:
- Forces a hard UPSERT for every module — no row is skipped.
- After writing the bcrypt hash, the legacy `password` (plaintext) column
  is set to NULL for every row, closing the dual-password backdoor.
- Also repairs rows where password_hash is '' (empty string from old
  NOT NULL DEFAULT '' schema) — these previously caused "No password record
  found" errors for modules like archive_marriage.

Usage:
    python fix_password.py
"""

import bcrypt
import mysql.connector

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "system",
    "port": 3306,
}

MODULES = [
    "birth_record",
    "archive_birth",
    "marriage_record",
    "archive_marriage",
    "death_record",
    "archive_death",
]

DEFAULT_PASSWORD = "123456"


def get_db():
    return mysql.connector.connect(**DB_CONFIG)


def column_exists(cursor, table_name: str, column_name: str) -> bool:
    cursor.execute(f"SHOW COLUMNS FROM `{table_name}` LIKE %s", (column_name,))
    return cursor.fetchone() is not None


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(12)).decode("utf-8")


def ensure_table_and_columns(db):
    c = db.cursor()

    # Create base table if missing
    c.execute("""
        CREATE TABLE IF NOT EXISTS module_passwords (
            id            INT          NOT NULL AUTO_INCREMENT,
            module_key    VARCHAR(50)  NOT NULL,
            password_hash VARCHAR(255) NULL,
            created_at    DATETIME     DEFAULT CURRENT_TIMESTAMP,
            updated_at    DATETIME     DEFAULT CURRENT_TIMESTAMP
                                       ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY uq_module_key (module_key)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    db.commit()

    for col, definition in [
        ("password",      "VARCHAR(255) NULL"),
        ("password_hash", "VARCHAR(255) NULL"),
        ("created_at",    "DATETIME DEFAULT CURRENT_TIMESTAMP"),
        ("updated_at",    "DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"),
    ]:
        if not column_exists(c, "module_passwords", col):
            c.execute(f"ALTER TABLE module_passwords ADD COLUMN {col} {definition}")
            db.commit()
            print(f"  + Added column: {col}")

    # If password_hash was created as NOT NULL, alter it to be nullable
    # so broken/empty rows are detectable
    c.execute("SHOW COLUMNS FROM module_passwords LIKE 'password_hash'")
    col_info = c.fetchone()
    if col_info:
        # col_info[2] is the Null column: 'YES' = nullable, 'NO' = not null
        is_nullable = col_info[2] == "YES"
        if not is_nullable:
            c.execute("ALTER TABLE module_passwords MODIFY COLUMN password_hash VARCHAR(255) NULL")
            db.commit()
            print("  + Altered password_hash to be nullable (was NOT NULL)")

    c.close()


def upsert_all_passwords(db):
    """
    Hard-reset every module password to the default.
    Uses DELETE + INSERT instead of ON DUPLICATE KEY UPDATE to guarantee
    a clean row even if the old row had schema issues (e.g. NOT NULL DEFAULT '').

    plaintext `password` column is always set to NULL — never stored in plain text.
    """
    hashed = hash_password(DEFAULT_PASSWORD)

    for mod in MODULES:
        c = db.cursor()

        # Check if row exists
        c.execute("SELECT id FROM module_passwords WHERE module_key = %s", (mod,))
        existing = c.fetchone()
        c.close()

        if existing:
            # Update existing row — force both hash and plaintext column
            c = db.cursor()
            c.execute("""
                UPDATE module_passwords
                   SET password_hash = %s,
                       password      = NULL,
                       updated_at    = CURRENT_TIMESTAMP
                 WHERE module_key    = %s
            """, (hashed, mod))
            db.commit()
            c.close()
            print(f"  ✓ '{mod}' → updated hash, cleared plaintext (NULL)")
        else:
            # Insert fresh row
            c = db.cursor()
            c.execute("""
                INSERT INTO module_passwords (module_key, password_hash, password)
                VALUES (%s, %s, NULL)
            """, (mod, hashed))
            db.commit()
            c.close()
            print(f"  ✓ '{mod}' → inserted with hash, plaintext NULL")


def verify_all_hashes(db):
    """
    Sanity check: verify that bcrypt.checkpw succeeds for every module
    using the default password. Prints PASS or FAIL for each.
    """
    print("\nVerifying hashes...")
    for mod in MODULES:
        c = db.cursor()
        c.execute(
            "SELECT password_hash FROM module_passwords WHERE module_key = %s",
            (mod,)
        )
        row = c.fetchone()
        c.close()

        if not row or not row[0]:
            print(f"  ✗ '{mod}' → NO ROW or EMPTY HASH")
            continue

        stored = row[0]
        if not str(stored).startswith("$2"):
            print(f"  ✗ '{mod}' → hash does not look like bcrypt: {stored!r}")
            continue

        try:
            ok = bcrypt.checkpw(
                DEFAULT_PASSWORD.encode("utf-8"),
                stored.encode("utf-8") if isinstance(stored, str) else stored
            )
            print(f"  {'✓' if ok else '✗'} '{mod}' → {'PASS' if ok else 'FAIL'}")
        except Exception as e:
            print(f"  ✗ '{mod}' → bcrypt error: {e}")


def show_rows(db):
    c = db.cursor()
    c.execute("""
        SELECT id, module_key, password, password_hash, updated_at
        FROM module_passwords
        ORDER BY id ASC
    """)
    rows = c.fetchall()
    c.close()

    print("\nCurrent rows in module_passwords:")
    for row in rows:
        row_id, module_key, password, password_hash, updated_at = row
        plaintext_status = repr(password) if password is not None else "NULL ✓"
        if password_hash and str(password_hash).startswith("$2"):
            hash_status = "valid bcrypt ✓"
        elif password_hash == "" or password_hash is None:
            hash_status = "EMPTY / NULL ✗"
        else:
            hash_status = f"INVALID: {password_hash!r} ✗"

        print(
            f"  [{row_id}] {module_key}\n"
            f"       plaintext  = {plaintext_status}\n"
            f"       hash       = {hash_status}\n"
            f"       updated_at = {updated_at}"
        )


def main():
    try:
        db = get_db()
        print("Connected to database.\n")

        print("Step 1: Ensuring table and columns...")
        ensure_table_and_columns(db)
        print()

        print("Step 2: Upserting all module passwords...")
        upsert_all_passwords(db)
        print()

        print("Step 3: Verifying bcrypt hashes...")
        verify_all_hashes(db)
        print()

        print("Step 4: Current table state...")
        show_rows(db)
        db.close()

        print()
        print("=" * 55)
        print("Done!")
        print("Restart your Flask server after running this script.")
        print(f"All module passwords are now: {DEFAULT_PASSWORD}")
        print("Plaintext backdoor column is cleared (NULL) for all rows.")
        print("=" * 55)

    except mysql.connector.Error as e:
        print(f"MySQL error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()