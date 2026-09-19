import re
import time
from flask import Blueprint, jsonify
from supabase_client import supabase
from datetime import datetime, timezone, timedelta
from collections import defaultdict

analytics_bp = Blueprint("analytics", __name__)

MONTH_NAMES = [
    "", "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
]

MONTH_NAME_TO_NUM = {
    "january": 1, "february": 2, "march": 3, "april": 4, "may": 5, "june": 6,
    "july": 7, "august": 8, "september": 9, "october": 10, "november": 11, "december": 12,
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "jun": 6, "jul": 7, "aug": 8,
    "sep": 9, "sept": 9, "oct": 10, "nov": 11, "dec": 12,
}

TYPE_LABELS = {
    "birth_records": "Birth",
    "marriage_records": "Marriage",
    "death_records": "Death",
}

UPLOAD_COL = "uploaded_at"
ARCHIVED_COL = "is_archived"

RECORD_TABLES = ["birth_records", "marriage_records", "death_records"]

# Columns confirmed against the real Supabase schema for each table.
SELECT_COLUMNS = {
    "birth_records": (
        "uploaded_at, birth_date, birth_year, birth_month, birth_day, "
        "city_municipality, place_of_birth, is_archived"
    ),
    "marriage_records": (
        "uploaded_at, marriage_year, marriage_month, marriage_day, "
        "city_municipality, place_of_marriage, marriage_city, is_archived"
    ),
    "death_records": (
        "uploaded_at, date_of_death, city_municipality, place_of_death, is_archived"
    ),
}

# Fallback chain (in priority order) used to resolve a "place" for each record type.
PLACE_COLUMNS = {
    "birth_records": ["city_municipality", "place_of_birth"],
    "marriage_records": ["city_municipality", "place_of_marriage", "marriage_city"],
    "death_records": ["city_municipality", "place_of_death"],
}

# Each record type has its own payment/transaction table with slightly
# different column names (confirmed against the birth_payments,
# marriage_transactions, and death_transactions schemas).
PAYMENT_TABLES = {
    "birth_records": {
        "table": "birth_payments",
        "columns": "amount, payment_status, payment_date, payment_method",
        "amount_col": "amount",
        "date_col": "payment_date",
        "status_col": "payment_status",
    },
    "marriage_records": {
        "table": "marriage_transactions",
        "columns": "payment_amount, record_status, created_at, payment_method",
        "amount_col": "payment_amount",
        "date_col": "created_at",
        "status_col": "record_status",
    },
    "death_records": {
        "table": "death_transactions",
        "columns": "payment_amount, record_status, created_at, payment_method",
        "amount_col": "payment_amount",
        "date_col": "created_at",
        "status_col": "record_status",
    },
}

# ─────────────────────────────────────────────────────────────────────────
# NOTE on status_col ("payment_status" / "record_status"):
#
# This does NOT indicate whether a payment succeeded -- every row in
# birth_payments / marriage_transactions / death_transactions is only
# written after the ₱75 fee has already been collected and the
# transaction released (see handleCompleteTransaction in
# birth.jsx / marriage.jsx / death.jsx). status_col instead records
# whether the *searched civil registry record was found*: "positive"
# means an actual record was located and a true copy was issued;
# "negative" means no record was found and a Negative Certificate was
# issued instead -- which still costs the same ₱75 (the printed Negative
# Certificate itself shows "Amount Paid: ₱75.00").
#
# POSITIVE_PAYMENT_STATUSES / _is_positive_payment below are kept as
# general-purpose helpers (e.g. for anything that specifically needs to
# know "was the record found" vs. "not found"), but revenue calculations
# in payment_stats_today() intentionally do NOT gate on this value --
# see the FIX comment there. Gating revenue by "positive" was exactly why
# Negative Certificate transactions (a real, completed ₱75 payment) were
# being silently excluded from the revenue total while still being
# counted as a request.
# ─────────────────────────────────────────────────────────────────────────
POSITIVE_PAYMENT_STATUSES = {
    "positive", "paid", "success", "successful", "completed", "complete",
    "approved", "verified", "released", "confirmed", "confirm", "done",
    "true", "1", "yes",
}


# ══════════════════════════════════════════════════════════════════════════
# DATE PARSING HELPERS
# ══════════════════════════════════════════════════════════════════════════

def _parse_month_value(val):
    """Accepts numeric ('3'), zero-padded ('03'), or name ('March'/'mar') months."""
    if val is None:
        return None
    s = str(val).strip().lower()
    if not s:
        return None
    if s.isdigit():
        n = int(s)
        return n if 1 <= n <= 12 else None
    return MONTH_NAME_TO_NUM.get(s)


def _parse_int_year(val):
    if val is None:
        return None
    s = str(val).strip()
    if not s or not s.isdigit():
        return None
    n = int(s)
    return n if 1900 <= n <= 2100 else None


def parse_flexible_date(date_val):
    """
    Best-effort (year, month) extraction from a date/datetime/text value.
    Handles: real date/datetime objects, ISO strings, common written formats,
    and loose text containing a 4-digit year plus a month name.
    """
    if not date_val:
        return None

    # Real date/datetime objects (e.g. Postgres 'date' columns come back this way sometimes)
    if isinstance(date_val, datetime):
        return (date_val.year, date_val.month)

    s = str(date_val).strip()
    if not s or s.lower() in ("none", "null", "n/a", "na", "-", ""):
        return None

    # ISO-ish: 2023-05-... or 2023/05/...
    m = re.match(r"^(\d{4})[-/](\d{1,2})", s)
    if m:
        yr, mo = int(m.group(1)), int(m.group(2))
        if 1900 <= yr <= 2100 and 1 <= mo <= 12:
            return (yr, mo)

    for fmt in (
        "%B %d, %Y", "%b %d, %Y", "%B %d %Y", "%d %B %Y",
        "%d %b %Y", "%m/%d/%Y", "%d/%m/%Y", "%Y/%m/%d",
        "%m-%d-%Y", "%d-%m-%Y",
    ):
        try:
            dt = datetime.strptime(s, fmt)
            return (dt.year, dt.month)
        except ValueError:
            continue

    # Loose fallback: find a plausible year, then look for a month name nearby
    yr_match = re.search(r"(19|20)\d{2}", s)
    if yr_match:
        yr = int(yr_match.group(0))
        low = s.lower()
        for name, num in MONTH_NAME_TO_NUM.items():
            if re.search(rf"\b{name}\b", low):
                if 1900 <= yr <= 2100:
                    return (yr, num)
                break
        # Year found but no month text -> default to January so the record
        # still counts somewhere instead of being dropped entirely.
        if 1900 <= yr <= 2100:
            return (yr, 1)

    return None


def _resolve_upload_ym(row):
    """
    (year, month) the record was uploaded into the system. This is what
    "records uploaded" charts should track -- NOT the person's
    birth/marriage/death date, which reflects their life event, not
    system activity. Kept separate from EVENT_RESOLVERS below so the two
    concepts never get mixed again.
    """
    return parse_flexible_date(row.get(UPLOAD_COL))


def _resolve_transaction_ym(record_table_name, row):
    """
    (year, month) an actual certificate *request* happened, resolved from
    the request's own payment/transaction table (birth_payments /
    marriage_transactions / death_transactions) using that table's own
    date column (payment_date / created_at) -- NOT from the record tables'
    uploaded_at.

    FIX: growth-rate / requests-by-year / requests-by-month previously
    counted rows from birth_records / marriage_records / death_records
    (i.e. "records uploaded"), which is a different thing from "requests
    made". That mismatch is exactly why the Growth Rate tab could show a
    "reqs" figure that didn't reflect real request volume for the month
    (e.g. everything piling up into the most recent month uploads
    happened, instead of reflecting when requests were actually placed).
    Use this resolver everywhere a *request* count is needed.
    """
    cfg = PAYMENT_TABLES[record_table_name]
    return parse_flexible_date(row.get(cfg["date_col"]))


def _month_add(year, month, delta_months):
    """Adds delta_months (can be negative) to a (year, month) pair."""
    idx = year * 12 + (month - 1) + delta_months
    return idx // 12, idx % 12 + 1


def _rolling_months(n, anchor=None):
    """Returns the last n (year, month) tuples ending at `anchor` (defaults
    to the current UTC month), oldest first."""
    anchor = anchor or datetime.now(timezone.utc)
    return [_month_add(anchor.year, anchor.month, -i) for i in range(n - 1, -1, -1)]


def _resolve_birth_ym(row):
    r = parse_flexible_date(row.get("birth_date"))
    if r:
        return r
    yr = _parse_int_year(row.get("birth_year"))
    if yr:
        return (yr, _parse_month_value(row.get("birth_month")) or 1)
    return parse_flexible_date(row.get(UPLOAD_COL))


def _resolve_marriage_ym(row):
    yr = _parse_int_year(row.get("marriage_year"))
    if yr:
        return (yr, _parse_month_value(row.get("marriage_month")) or 1)
    return parse_flexible_date(row.get(UPLOAD_COL))


def _resolve_death_ym(row):
    r = parse_flexible_date(row.get("date_of_death"))
    if r:
        return r
    return parse_flexible_date(row.get(UPLOAD_COL))


EVENT_RESOLVERS = {
    "birth_records": _resolve_birth_ym,
    "marriage_records": _resolve_marriage_ym,
    "death_records": _resolve_death_ym,
}
# NOTE: EVENT_RESOLVERS resolve each person's actual vital-event date (birth/
# marriage/death). They are intentionally NOT used by records-by-year,
# records-by-month, growth-rate, or requests-by-* below -- those charts are
# either about system activity ("records uploaded", via _resolve_upload_ym)
# or about actual requests ("requests made", via _resolve_transaction_ym).
# EVENT_RESOLVERS is kept here in case a future "demographic seasonality"
# report (e.g. "what month are most babies actually born") is wanted --
# that would be a different, new endpoint.


def _resolve_place(table_name, row):
    for col in PLACE_COLUMNS[table_name]:
        val = row.get(col)
        if val and str(val).strip():
            return str(val).strip().title()
    return "Unspecified"


# ─────────────────────────────────────────────────────────────────────────
# FIX: LOCAL-TIME / UTC MISMATCH — THE ACTUAL CAUSE OF "TODAY" SHOWING 0
# FOR BIRTH, MARRIAGE, AND DEATH TRANSACTIONS
#
# Symptom: Birth/Marriage/Death Verifier transactions clearly exist
# (confirmed directly in birth_payments / marriage_transactions /
# death_transactions via the Supabase table editor, including rows dated
# "today"), but the Dashboard's "Today" tab (Requests Today, Revenue
# Today, Business window transactions) showed 0 for all three modules.
#
# Root cause: routes/Birth.py, routes/Death.py (now_dt()), and
# routes/marriage.py all timestamp payment_date / created_at using plain
# `datetime.now()` -- Python's naive LOCAL server clock. This is
# confirmed by the birth_payments table itself: a row's `payment_date`
# (app-written) and that same row's DB-generated `created_at` (Postgres
# default, effectively UTC) are exactly 8 hours apart -- i.e. the app
# server's local clock is Philippines time (UTC+8).
#
# _parse_uploaded_at() then took that naive LOCAL timestamp and stamped
# it with `tzinfo=timezone.utc` -- treating "10:15 local" as if it meant
# "10:15 UTC" (8 hours ahead of the real UTC instant). Meanwhile
# _business_day_window() computed its start/end boundaries from the
# REAL current UTC time (`datetime.now(timezone.utc)`). Comparing a
# timestamp that's artificially 8 hours in the future against a
# correctly-computed UTC window pushed almost every same-day local
# transaction outside of "today's" window -- so it silently didn't
# count, exactly the reported symptom, even though the same rows are
# correctly included in totals elsewhere (which don't do this "today"
# comparison).
#
# Fix: stop mixing a naive-local timestamp with a UTC-based window.
# PH_LOCAL_OFFSET matches the fixed UTC+8 offset already evidenced by
# the data (Philippines has no DST, so this never changes). The
# business-day window is now computed in that same local time, and
# naive timestamps are parsed and compared as local time directly (no
# incorrect relabeling as UTC). This only changes how analytics.py
# *interprets* existing timestamps for "today" bucketing -- it does not
# change how Birth/Marriage/Death write their timestamps, and it applies
# identically to all three modules, so all three are fixed together and
# nothing is double-counted (each payment/transaction table is still
# read exactly once, exactly as before).
# ─────────────────────────────────────────────────────────────────────────

PH_LOCAL_OFFSET = timedelta(hours=8)  # Asia/Manila, fixed offset (no DST)


def _now_local():
    """Current local (Asia/Manila, UTC+8) time as a naive datetime, matching
    the naive datetime.now() timestamps written by the Birth/Marriage/Death
    upload and transaction routes."""
    return datetime.now(timezone.utc).replace(tzinfo=None) + PH_LOCAL_OFFSET


def _business_day_window():
    """Business day runs 6:00 AM -> next 6:00 AM, in local (Asia/Manila)
    time -- matching the naive local timestamps stored by the Birth/
    Marriage/Death routes (see FIX note above)."""
    now = _now_local()
    start = now.replace(hour=6, minute=0, second=0, microsecond=0)
    if now < start:
        start -= timedelta(days=1)
    end = start + timedelta(days=1)
    return start, end


def _parse_uploaded_at(val):
    """
    Parses a stored timestamp into a naive LOCAL (Asia/Manila) datetime so
    it can be compared directly against the local business-day window
    returned by _business_day_window(). See the FIX note above
    _business_day_window() for why this must stay local rather than being
    incorrectly re-labelled as UTC.
    """
    if not val:
        return None
    if isinstance(val, datetime):
        if val.tzinfo:
            # Rare case: value already carries real tzinfo -- convert it
            # properly to local time instead of assuming it's already local.
            return val.astimezone(timezone.utc).replace(tzinfo=None) + PH_LOCAL_OFFSET
        return val
    s = str(val).strip()
    if not s:
        return None
    try:
        s2 = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s2)
        if dt.tzinfo:
            return dt.astimezone(timezone.utc).replace(tzinfo=None) + PH_LOCAL_OFFSET
        return dt
    except ValueError:
        return None


def _to_amount(val):
    """
    Parses a payment amount that may come back as a float, int, or a
    numeric-looking string (Supabase returns NUMERIC/DECIMAL columns as
    strings in some client versions).

    FIX: previously this only tried a plain float(val) cast, so any amount
    value that ever included formatting -- a "₱" currency symbol, a
    thousands separator ("1,000.00"), or stray surrounding whitespace --
    would raise ValueError and silently fall back to 0.0. That meant a
    genuinely successful transaction could be logged and even counted in
    "transactions today", while contributing nothing to the revenue total,
    which is exactly the symptom of new payments not increasing revenue.
    Now common formatting is stripped before parsing.
    """
    if val is None:
        return 0.0
    if isinstance(val, (int, float)):
        try:
            return float(val)
        except (TypeError, ValueError):
            return 0.0
    # Strip anything that isn't a digit, minus sign, or decimal point
    # (currency symbols, thousands separators, whitespace, stray text).
    cleaned = re.sub(r"[^0-9.\-]", "", str(val))
    if not cleaned or cleaned in ("-", "."):
        return 0.0
    try:
        return float(cleaned)
    except (TypeError, ValueError):
        return 0.0


def _is_positive_payment(val):
    """
    True if `val` represents a successfully completed payment.

    FIX: POSITIVE_PAYMENT_STATUSES previously only recognized a few exact
    words ("positive"/"paid"/"success"/"completed"). Any other legitimate
    "this succeeded" status label used elsewhere in the app (e.g.
    "approved", "verified", "released", "confirmed", or a boolean-ish
    "true"/"1"/"yes") fell through and was treated as a non-payment,
    contributing ₱0 to revenue even though the row was a real, successful
    transaction (and was still being counted in transactions_today). The
    whitelist below now covers those common variants; anything not on the
    list (e.g. "negative", "pending", "failed", "declined") still
    correctly contributes $0.
    """
    if val is None:
        return False
    return str(val).strip().lower() in POSITIVE_PAYMENT_STATUSES


def _to_bool_or_none(val):
    """
    Normalizes is_archived across the various shapes Postgrest/Supabase can
    hand back: native bool, None, or (less commonly, e.g. after a manual CSV
    import or a text-typed column) the strings 'true'/'false'/'t'/'f' or the
    ints 1/0. Anything unrecognized is treated as "unknown" (None).

    Still used by /debug-counts to report the raw breakdown of is_archived
    values per table -- just no longer used to exclude rows from the main
    analytics totals (see _is_active below).
    """
    if val is None:
        return None
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    s = str(val).strip().lower()
    if s in ("true", "t", "1", "yes"):
        return True
    if s in ("false", "f", "0", "no", ""):
        return False
    return None


# ══════════════════════════════════════════════════════════════════════════
# DATA FETCHING (single source of truth per table, per request)
# ══════════════════════════════════════════════════════════════════════════
#
# On total failure, _fetch_paginated RAISES instead of swallowing the
# error. Every route below already wraps its body in try/except and returns
# jsonify({"error": ...}), 500 on exception -- so a real fetch failure
# surfaces as a real error to the frontend (which displays it in the
# an-error-banner), instead of a misleading "0".
#
# For the one place where you genuinely want to inspect broken tables
# without the whole request 500-ing (the /debug-counts diagnostic route),
# use _fetch_paginated_safe, which catches the raise and returns the error
# message alongside whatever rows (if any) it could get.
# ══════════════════════════════════════════════════════════════════════════

# Substrings that identify a *transient* network/socket hiccup rather than a
# real credentials/RLS/schema problem. WinError 10035 (WSAEWOULDBLOCK) shows
# up on Windows dev machines when many requests fire on the same process at
# once (exactly what happens here: the frontend calls all 8 analytics
# endpoints in parallel, and several of them independently fetch the same
# tables) -- it means "the socket wasn't ready yet", not "this failed for
# good". These are worth a quick retry before giving up; anything else
# (auth errors, bad table/column names, DNS failures) is not retried and
# surfaces immediately.
_RETRYABLE_ERROR_SUBSTRINGS = (
    "10035",           # WSAEWOULDBLOCK (Windows)
    "would block",
    "wouldblock",
    "timed out",
    "timeout",
    "connection reset",
    "connection aborted",
    "remote end closed",
    "econnreset",
)

_MAX_FETCH_RETRIES = 3
_RETRY_BACKOFF_SECONDS = 0.4  # multiplied by attempt number


def _is_retryable_error(exc):
    msg = str(exc).lower()
    return any(sub in msg for sub in _RETRYABLE_ERROR_SUBSTRINGS)


def _fetch_paginated(table_name, preferred_columns):
    """
    Paginates through Supabase to fetch every row of `table_name`.

    Tries `preferred_columns` first; if Postgrest rejects that column list
    (e.g. it drifted from the live schema), retries once with `select(*)`
    so a bad column list degrades gracefully instead of silently zeroing
    out the whole table.

    Each individual page request is additionally wrapped with a short
    retry-with-backoff for transient socket-level errors (see
    _is_retryable_error) -- e.g. WinError 10035 on Windows when many
    requests hit Supabase concurrently from the same process. Non-retryable
    errors (bad credentials, bad column names, etc.) fail immediately as
    before.

    Raises RuntimeError if all attempts fail, so the caller's error
    handling (route-level try/except, or _fetch_paginated_safe) can report
    the real cause instead of pretending the table is empty.
    """
    batch_size = 1000
    last_error = None

    for cols in (preferred_columns, "*"):
        all_rows = []
        offset = 0
        try:
            while True:
                page_attempt = 0
                while True:
                    try:
                        res = (
                            supabase.table(table_name)
                            .select(cols)
                            .range(offset, offset + batch_size - 1)
                            .execute()
                        )
                        break
                    except Exception as page_err:
                        page_attempt += 1
                        if (
                            _is_retryable_error(page_err)
                            and page_attempt < _MAX_FETCH_RETRIES
                        ):
                            wait = _RETRY_BACKOFF_SECONDS * page_attempt
                            print(
                                f"[Analytics] Transient error fetching {table_name} "
                                f"(attempt {page_attempt}/{_MAX_FETCH_RETRIES}), "
                                f"retrying in {wait:.1f}s: {page_err}"
                            )
                            time.sleep(wait)
                            continue
                        raise

                data = res.data or []
                all_rows.extend(data)
                if len(data) < batch_size:
                    break
                offset += batch_size
            return all_rows
        except Exception as e:
            last_error = e
            print(f"[Analytics] Error fetching rows for {table_name} "
                  f"with select('{cols}'): {e}")
            continue

    # Both attempts failed -- don't pretend the table is empty.
    print(f"[Analytics] ERROR: could not fetch any rows for {table_name}; "
          f"last error: {last_error}")
    raise RuntimeError(
        f"Could not read table '{table_name}' from Supabase "
        f"(check credentials/RLS policies/network): {last_error}"
    ) from last_error


def _fetch_paginated_safe(table_name, preferred_columns):
    """
    Same as _fetch_paginated but never raises -- returns (rows, error_str).
    Used only by the /debug-counts diagnostic route, which needs to report
    on broken tables without 500-ing the whole request.
    """
    try:
        rows = _fetch_paginated(table_name, preferred_columns)
        return rows, None
    except Exception as e:
        return [], str(e)


def fetch_all_rows(table_name):
    """Paginates through Supabase to fetch every row (archived + active) of a record table."""
    return _fetch_paginated(table_name, SELECT_COLUMNS[table_name])


def fetch_payment_rows(record_table_name):
    """Paginates through Supabase to fetch every row of the payment/transaction
    table associated with the given record table (birth_records -> birth_payments, etc)."""
    cfg = PAYMENT_TABLES[record_table_name]
    return _fetch_paginated(cfg["table"], cfg["columns"])


# ─────────────────────────────────────────────────────────────────────────
# FIX: is_archived is a WORKFLOW state (birth.py / the Archive tab use it to
# mean "uploaded, not yet selected for a transaction" vs "currently being
# processed") -- it is NOT a validity flag. A record sitting in Archive is
# still a real, valid civil registry entry and must count toward Dashboard
# totals.
#
# Previously _is_active() excluded any row with is_archived = true from
# every analytics endpoint (summary, records-by-year, growth-rate, etc).
# That caused a tug-of-war between the Archive tab and the Dashboard: an
# admin would archive/restore records to fix one screen, which would
# immediately zero out or double the other, because both screens were
# reading the exact same flag with opposite expectations
# ("is_archived = valid-for-Archive-tab" vs "is_archived = invalid-for-Dashboard").
#
# Fix: analytics totals now always include every row, regardless of
# is_archived. The Archive tab (birth.py / marriage.py / death.py --
# untouched by this file) keeps filtering by is_archived exactly as before,
# so its behavior as an "uploaded, awaiting selection" inbox is unaffected.
# The two screens can no longer fight over this column because Dashboard
# stops looking at it entirely.
# ─────────────────────────────────────────────────────────────────────────

def _is_active(row, include_archived):
    # include_archived is kept as a parameter for call-site clarity / any
    # future need to re-introduce filtering, but no longer changes the
    # result -- every row counts.
    return True


def active_rows(table_name, include_archived=True):
    return [r for r in fetch_all_rows(table_name) if _is_active(r, include_archived)]


def table_counts(table_name, include_archived=True):
    """Returns (total_count, today_count) computed from one fetch."""
    rows = active_rows(table_name, include_archived)
    start, end = _business_day_window()
    today = 0
    for r in rows:
        dt = _parse_uploaded_at(r.get(UPLOAD_COL))
        if dt and start <= dt < end:
            today += 1
    return len(rows), today


def payment_stats_today(record_table_name):
    """
    Returns (transactions_today, revenue_today) for the payment/transaction
    table tied to `record_table_name`, restricted to the current business
    day.

    FIX (the actual revenue-not-summing bug): `revenue_today` previously
    only summed rows whose status_col matched POSITIVE_PAYMENT_STATUSES
    (e.g. "positive"), on the assumption that status_col meant "was this
    payment successful". It does not. Looking at how the frontend actually
    writes these rows (birth.jsx / marriage.jsx / death.jsx
    handleCompleteTransaction -> POST /records/complete), status_col
    records whether the *searched civil registry record was found*
    ("positive") or issued as a Negative Certificate because no matching
    record exists ("negative") -- it has nothing to do with whether the
    ₱75 fee was actually paid. The Negative Certificate document itself
    still prints "Amount Paid: ₱75.00" (see NegativeCertPreview /
    NegativeCertDocument in every registry's frontend), because that fee
    IS collected either way before a row is ever written to
    birth_payments / marriage_transactions / death_transactions.
    In other words: every row in these tables already represents a real,
    completed monetary transaction (there is no "pending"/"failed"
    payment state in this data model -- a row is only inserted after the
    fee is paid and the transaction is released). So gating revenue by
    "positive" status was silently dropping every Negative Certificate
    transaction's ₱75 from the total, which is exactly the symptom
    reported: request counts include both positive and negative-cert
    transactions, but revenue only reflected the positive ones.
    Fix: sum the amount of every transaction row in the window,
    unconditionally -- `transactions_today` and `revenue_today` now always
    move together.

    ALSO FIXES: the local-time/UTC mismatch described above
    _business_day_window() -- since this function's window/date comparison
    now both live in the same local timeline, today's Birth, Marriage, and
    Death transactions are correctly included instead of being pushed out
    of the window.
    """
    cfg = PAYMENT_TABLES[record_table_name]
    rows = fetch_payment_rows(record_table_name)
    start, end = _business_day_window()

    transactions_today = 0
    revenue_today = 0.0
    for r in rows:
        dt = _parse_uploaded_at(r.get(cfg["date_col"]))
        if not (dt and start <= dt < end):
            continue
        transactions_today += 1
        revenue_today += _to_amount(r.get(cfg["amount_col"]))

    return transactions_today, round(revenue_today, 2)


# ══════════════════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════════════════

@analytics_bp.route("/api/analytics/summary", methods=["GET"])
def summary():
    try:
        birth_total, b_today = table_counts("birth_records")
        marriage_total, m_today = table_counts("marriage_records")
        death_total, d_today = table_counts("death_records")

        total_all = birth_total + marriage_total + death_total
        today_total = b_today + m_today + d_today

        return jsonify({
            "total_records": total_all,
            "active_records": total_all,
            "archived_records": 0,
            "total_birth_records": birth_total,
            "total_marriage_records": marriage_total,
            "total_death_records": death_total,
            "uploaded_today": today_total,
            "uploaded_today_breakdown": {
                "birth": b_today,
                "marriage": m_today,
                "death": d_today,
            },
            "record_breakdown": [
                {"label": "Birth", "count": birth_total},
                {"label": "Marriage", "count": marriage_total},
                {"label": "Death", "count": death_total},
            ],
        }), 200
    except Exception as e:
        print(f"[Analytics] /summary error: {e}")
        return jsonify({"error": str(e)}), 500


@analytics_bp.route("/api/analytics/document-types", methods=["GET"])
def document_types():
    try:
        result = []
        for tbl in RECORD_TABLES:
            total, _ = table_counts(tbl)
            result.append({"label": TYPE_LABELS[tbl], "count": total})
        return jsonify(result), 200
    except Exception as e:
        print(f"[Analytics] /document-types error: {e}")
        return jsonify({"error": str(e)}), 500


@analytics_bp.route("/api/analytics/records-by-year", methods=["GET"])
def records_by_year():
    try:
        years_map = defaultdict(int)

        for tbl in RECORD_TABLES:
            rows = active_rows(tbl)
            for r in rows:
                try:
                    ym = _resolve_upload_ym(r)
                except Exception as e:
                    print(f"[Analytics] records-by-year: skipping bad row in {tbl}: {e}")
                    continue
                if ym:
                    years_map[ym[0]] += 1

        result = [{"year": yr, "count": cnt} for yr, cnt in sorted(years_map.items())]
        return jsonify(result), 200
    except Exception as e:
        print(f"[Analytics] /records-by-year error: {e}")
        return jsonify({"error": str(e)}), 500


@analytics_bp.route("/api/analytics/records-by-month", methods=["GET"])
def records_by_month():
    try:
        months_map = {m: 0 for m in range(1, 13)}

        for tbl in RECORD_TABLES:
            rows = active_rows(tbl)
            for r in rows:
                try:
                    ym = _resolve_upload_ym(r)
                except Exception as e:
                    print(f"[Analytics] records-by-month: skipping bad row in {tbl}: {e}")
                    continue
                if ym:
                    months_map[ym[1]] += 1

        result = [
            {"month_num": m_num, "month_name": MONTH_NAMES[m_num], "count": cnt}
            for m_num, cnt in months_map.items()
        ]
        return jsonify(result), 200
    except Exception as e:
        print(f"[Analytics] /records-by-month error: {e}")
        return jsonify({"error": str(e)}), 500


@analytics_bp.route("/api/analytics/top-municipalities", methods=["GET"])
def top_municipalities():
    try:
        muni_map = {}

        for tbl in RECORD_TABLES:
            rows = active_rows(tbl)
            type_label = TYPE_LABELS[tbl]
            for r in rows:
                muni = _resolve_place(tbl, r)

                if muni not in muni_map:
                    muni_map[muni] = {"cnt": 0, "Birth": 0, "Marriage": 0, "Death": 0}

                muni_map[muni]["cnt"] += 1
                muni_map[muni][type_label] += 1

        sorted_muni = sorted(muni_map.items(), key=lambda x: x[1]["cnt"], reverse=True)[:20]

        result = [
            {"name": name, "cnt": data["cnt"], "Birth": data["Birth"],
             "Marriage": data["Marriage"], "Death": data["Death"]}
            for name, data in sorted_muni
        ]
        return jsonify(result), 200
    except Exception as e:
        print(f"[Analytics] /top-municipalities error: {e}")
        return jsonify({"error": str(e)}), 500


@analytics_bp.route("/api/analytics/dashboard-today", methods=["GET"])
def dashboard_today():
    try:
        start, end = _business_day_window()

        # ─────────────────────────────────────────────────────────────
        # FIX: "Requests today" must count actual certificate requests
        # (i.e. transactions/payment attempts logged in birth_payments /
        # marriage_transactions / death_transactions), not new rows
        # uploaded into birth_records / marriage_records / death_records.
        #
        # Previously requests_today/requests_breakdown came from
        # table_counts() on the *record* tables (filtered by their
        # uploaded_at), which is a completely different metric from a
        # "request". That caused the exact bug seen on the Today tab:
        # Business window correctly showed "2 transactions" and Revenue
        # today correctly showed ₱75 (both derived from
        # payment_stats_today / the transaction tables), while Requests
        # today and its Birth/Marriage/Death pills all showed 0, because
        # no new records happened to be uploaded today even though real
        # requests (transactions) occurred.
        #
        # Fix: reuse the same b_txn/m_txn/d_txn transaction counts already
        # computed for revenue so "Requests today" and "Business window"
        # always agree with each other.
        #
        # This, together with the local-time fix in payment_stats_today()
        # above, is what makes Birth, Marriage, and Death transactions all
        # correctly appear here as soon as they're completed.
        # ─────────────────────────────────────────────────────────────
        b_txn, b_revenue = payment_stats_today("birth_records")
        m_txn, m_revenue = payment_stats_today("marriage_records")
        d_txn, d_revenue = payment_stats_today("death_records")

        return jsonify({
            "business_day_start": start.isoformat(),
            "business_day_end": end.isoformat(),
            "requests_today": b_txn + m_txn + d_txn,
            "requests_breakdown": [
                {"label": "Birth", "count": b_txn},
                {"label": "Marriage", "count": m_txn},
                {"label": "Death", "count": d_txn},
            ],
            "payments_today": b_txn + m_txn + d_txn,
            "payments_amount_today": round(b_revenue + m_revenue + d_revenue, 2),
            "payments_breakdown": [
                {"label": "Birth", "count": b_txn, "amount": b_revenue},
                {"label": "Marriage", "count": m_txn, "amount": m_revenue},
                {"label": "Death", "count": d_txn, "amount": d_revenue},
            ],
        }), 200
    except Exception as e:
        print(f"[Analytics] /dashboard-today error: {e}")
        return jsonify({"error": str(e)}), 500


@analytics_bp.route("/api/analytics/requests-by-year", methods=["GET"])
def requests_by_year():
    # ─────────────────────────────────────────────────────────────────
    # FIX: this endpoint used to just alias records_by_year(), which
    # counts rows uploaded into birth_records / marriage_records /
    # death_records -- i.e. "records uploaded", not "requests made".
    # It now counts actual request rows from each type's
    # payment/transaction table (birth_payments / marriage_transactions /
    # death_transactions), bucketed by that table's own date column via
    # _resolve_transaction_ym, so "Certificate requests per year" reflects
    # real request activity instead of upload activity.
    # ─────────────────────────────────────────────────────────────────
    try:
        years_map = defaultdict(int)

        for tbl in RECORD_TABLES:
            rows = fetch_payment_rows(tbl)
            for r in rows:
                try:
                    ym = _resolve_transaction_ym(tbl, r)
                except Exception as e:
                    print(f"[Analytics] requests-by-year: skipping bad row in "
                          f"{PAYMENT_TABLES[tbl]['table']}: {e}")
                    continue
                if ym:
                    years_map[ym[0]] += 1

        result = [{"year": yr, "count": cnt} for yr, cnt in sorted(years_map.items())]
        return jsonify(result), 200
    except Exception as e:
        print(f"[Analytics] /requests-by-year error: {e}")
        return jsonify({"error": str(e)}), 500


@analytics_bp.route("/api/analytics/requests-by-month", methods=["GET"])
def requests_by_month():
    # See FIX note in requests_by_year() above -- same change applied here,
    # bucketing actual request/transaction rows by month instead of
    # aliasing records_by_month() (records uploaded).
    try:
        months_map = {m: 0 for m in range(1, 13)}

        for tbl in RECORD_TABLES:
            rows = fetch_payment_rows(tbl)
            for r in rows:
                try:
                    ym = _resolve_transaction_ym(tbl, r)
                except Exception as e:
                    print(f"[Analytics] requests-by-month: skipping bad row in "
                          f"{PAYMENT_TABLES[tbl]['table']}: {e}")
                    continue
                if ym:
                    months_map[ym[1]] += 1

        result = [
            {"month_num": m_num, "month_name": MONTH_NAMES[m_num], "count": cnt}
            for m_num, cnt in months_map.items()
        ]
        return jsonify(result), 200
    except Exception as e:
        print(f"[Analytics] /requests-by-month error: {e}")
        return jsonify({"error": str(e)}), 500


@analytics_bp.route("/api/analytics/growth-rate", methods=["GET"])
def growth_rate():
    # ─────────────────────────────────────────────────────────────────
    # FIX: this previously counted rows from birth_records /
    # marriage_records / death_records bucketed by _resolve_upload_ym
    # (i.e. "records uploaded"), and labeled the result "reqs" / "request
    # volume" on the frontend. That mismatch is why the Growth Rate tab's
    # "This month vs last" KPI and the monthly trend line didn't reflect
    # real request activity per month -- it reflected upload activity.
    #
    # Fix: source per-month, per-type counts from each type's own
    # payment/transaction table (birth_payments / marriage_transactions /
    # death_transactions) via _resolve_transaction_ym, so "reqs" here
    # actually means requests made in that month.
    # ─────────────────────────────────────────────────────────────────
    try:
        months = _rolling_months(24)  # oldest -> newest, always a real 24-month window
        buckets = {ym: {"Birth": 0, "Marriage": 0, "Death": 0} for ym in months}
        month_set = set(months)

        for tbl in RECORD_TABLES:
            rows = fetch_payment_rows(tbl)
            type_label = TYPE_LABELS[tbl]
            for r in rows:
                try:
                    ym = _resolve_transaction_ym(tbl, r)
                except Exception as e:
                    print(f"[Analytics] growth-rate: skipping bad row in "
                          f"{PAYMENT_TABLES[tbl]['table']}: {e}")
                    continue
                if ym in month_set:
                    buckets[ym][type_label] += 1

        result = []
        prev_count = None
        for ym in months:
            yr, mo = ym
            b = buckets[ym]
            total = b["Birth"] + b["Marriage"] + b["Death"]
            label = f"{MONTH_NAMES[mo][:3]} {yr}"

            mom_growth = None
            if prev_count is not None and prev_count > 0:
                mom_growth = round(((total - prev_count) / prev_count) * 100, 1)

            result.append({
                "label": label,
                "year": yr,
                "month": mo,
                "count": total,
                "Birth": b["Birth"],
                "Marriage": b["Marriage"],
                "Death": b["Death"],
                "mom_growth": mom_growth,
            })
            prev_count = total

        return jsonify(result), 200
    except Exception as e:
        print(f"[Analytics] /growth-rate error: {e}")
        return jsonify({"error": str(e)}), 500


@analytics_bp.route("/api/analytics/debug-counts", methods=["GET"])
def debug_counts():
    """
    Diagnostic endpoint: shows raw total / active / archived counts per table
    straight from Supabase, with zero filtering assumptions. Use this to
    confirm whether undercounts are caused by is_archived values, a fetch
    failure (check the "fetch_error" field), or something else
    (wrong project/env, RLS, etc), or a genuinely empty table.

    Unlike the other routes, this one never 500s -- it uses
    _fetch_paginated_safe so a broken table shows up as
    fetch_error != null instead of the whole request failing.
    """
    try:
        result = {}
        for tbl in RECORD_TABLES:
            rows, fetch_error = _fetch_paginated_safe(tbl, SELECT_COLUMNS[tbl])
            archived_true = sum(1 for r in rows if _to_bool_or_none(r.get(ARCHIVED_COL)) is True)
            archived_false = sum(1 for r in rows if _to_bool_or_none(r.get(ARCHIVED_COL)) is False)
            archived_null = sum(1 for r in rows if _to_bool_or_none(r.get(ARCHIVED_COL)) is None)
            result[tbl] = {
                "total_rows_in_table": len(rows),
                "is_archived_true": archived_true,
                "is_archived_false": archived_false,
                "is_archived_null_or_unrecognized": archived_null,
                "would_count_as_active": archived_false + archived_null,
                "sample_row": rows[0] if rows else None,
                "fetch_returned_zero_rows": len(rows) == 0,
                "fetch_error": fetch_error,
            }
        return jsonify(result), 200
    except Exception as e:
        print(f"[Analytics] /debug-counts error: {e}")
        return jsonify({"error": str(e)}), 500