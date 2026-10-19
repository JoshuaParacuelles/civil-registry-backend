import re
import threading
import time
from flask import Blueprint, jsonify, session
from supabase_client import supabase
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from security import login_required_hook

analytics_bp = Blueprint("analytics", __name__)

# Every analytics route requires a logged-in session. Runs before any route
# and before any cached value is returned, so caching cannot leak data to
# unauthenticated callers.
analytics_bp.before_request(login_required_hook)

# ══════════════════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════════════════

# Set True ONLY if records' `uploaded_at` is a `timestamp WITHOUT time zone`
# column filled by a UTC default (e.g. now() on a server running in UTC).
# In that case naive values are UTC and must be shifted to Manila time.
# If uploaded_at is timestamptz (has +00:00 in the API output) or is written
# by the app with datetime.now() (local), leave this False. (item 5)
NAIVE_UPLOADED_AT_IS_UTC = False

# Cache TTLs (seconds)
TTL_RECORDS = 120          # raw record rows
TTL_PAYMENTS = 60          # raw payment rows
TTL_RECENT = 10            # "today" slices (kept short on purpose)
TTL_COUNT = 30             # exact counts
TTL_AGG_HEAVY = 60         # computed aggregates (year/month/municipality/growth)
TTL_AGG_TODAY = 10         # computed "today" dashboard
MAX_STALE_SECONDS = 600    # never serve cached data older than this on failure (item 4)

# Per-user rate limit for /refresh. Every dashboard user triggers it, so it is
# limited per user rather than restricted to admins. Counted per worker process.
REFRESH_WINDOW_SECONDS = 60
REFRESH_MAX_PER_WINDOW = 6

# Archive definition — MUST match the Vital Records archive endpoints:
#   archived  = is_archived is TRUE or NULL
#   active    = is_archived is FALSE
ARCHIVED_OR_FILTER = "is_archived.eq.true,is_archived.is.null"

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

# Each record type has its own payment/transaction table.
PAYMENT_TABLES = {
    "birth_records": {
        "table": "birth_payments",
        "columns": "amount, payment_status, payment_date, payment_method",
        "amount_col": "amount",
        "date_col": "payment_date",
    },
    "marriage_records": {
        "table": "marriage_transactions",
        "columns": "payment_amount, record_status, created_at, payment_method",
        "amount_col": "payment_amount",
        "date_col": "created_at",
    },
    "death_records": {
        "table": "death_transactions",
        "columns": "payment_amount, record_status, created_at, payment_method",
        "amount_col": "payment_amount",
        "date_col": "created_at",
    },
}


# ══════════════════════════════════════════════════════════════════════════
# CACHE
# ══════════════════════════════════════════════════════════════════════════
#
# The cache is PER WORKER PROCESS. With several gunicorn workers,
# each worker relies on the short TTLs. Use Redis if strict consistency is needed.

_CACHE = {}
_CACHE_LOCKS = {}
_CACHE_GUARD = threading.Lock()
_CACHE_MAX_ENTRIES = 64

# Bumped on every invalidation. A load that started before an invalidation
# must NOT store its (possibly pre-delete) result afterwards.
_CACHE_GEN = 0


def cached(key, ttl, loader, max_stale=MAX_STALE_SECONDS):
    """
    Cache a worker-local value and coalesce concurrent loads for its key.
    If a reload fails, serve the previous value only if it is younger than
    `max_stale` seconds; otherwise re-raise so the real failure is surfaced.
    """
    now = time.monotonic()
    with _CACHE_GUARD:
        hit = _CACHE.get(key)
        lock = _CACHE_LOCKS.setdefault(key, threading.Lock())
    if hit and now - hit[0] < ttl:
        return hit[1]

    with lock:
        now = time.monotonic()
        with _CACHE_GUARD:
            hit = _CACHE.get(key)
            gen_at_start = _CACHE_GEN
        if hit and now - hit[0] < ttl:
            return hit[1]

        try:
            value = loader()
        except Exception:
            if hit and (now - hit[0]) < max_stale:
                print(f"[Analytics] Serving stale cache for {key!r} "
                      f"({now - hit[0]:.0f}s old) after load failure")
                return hit[1]
            raise

        with _CACHE_GUARD:
            # Only store if nothing was invalidated while we were loading.
            if gen_at_start == _CACHE_GEN:
                _CACHE[key] = (time.monotonic(), value)
                while len(_CACHE) > _CACHE_MAX_ENTRIES:
                    oldest_key = min(_CACHE, key=lambda k: _CACHE[k][0])
                    _CACHE.pop(oldest_key, None)
                    if oldest_key != key:
                        _CACHE_LOCKS.pop(oldest_key, None)
        return value


def invalidate_analytics_cache(record_table=None):
    """
    Drop cached analytics data.
    - No argument: clears everything (used by the /refresh endpoint).
    - record_table given: clears that table's raw/count caches plus all
      aggregates (aggregates depend on every table).
    """
    global _CACHE_GEN
    with _CACHE_GUARD:
        _CACHE_GEN += 1
        for key in list(_CACHE):
            if (
                record_table is None
                or key[0] == "agg"
                or (len(key) > 1 and key[1] == record_table)
            ):
                _CACHE.pop(key, None)


# ══════════════════════════════════════════════════════════════════════════
# DATE PARSING HELPERS
# ══════════════════════════════════════════════════════════════════════════

def parse_flexible_date(date_val):
    """
    Best-effort (year, month) extraction from a date/datetime/text value.
    Handles real date/datetime objects, ISO strings, common written formats,
    and loose text containing a 4-digit year plus a month name.
    """
    if not date_val:
        return None

    if isinstance(date_val, datetime):
        return (date_val.year, date_val.month)

    s = str(date_val).strip()
    if not s or s.lower() in ("none", "null", "n/a", "na", "-", ""):
        return None

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

    yr_match = re.search(r"(19|20)\d{2}", s)
    if yr_match:
        yr = int(yr_match.group(0))
        low = s.lower()
        for name, num in MONTH_NAME_TO_NUM.items():
            if re.search(rf"\b{name}\b", low):
                if 1900 <= yr <= 2100:
                    return (yr, num)
                break
        if 1900 <= yr <= 2100:
            return (yr, 1)

    return None


# ─────────────────────────────────────────────────────────────────────────
# LOCAL TIME (Asia/Manila, UTC+8, no DST)
#
# Birth/Marriage/Death routes write naive local datetime.now() timestamps.
# The business-day window is computed in the same local time, and naive
# timestamps are compared as local time (never relabelled as UTC).
# ─────────────────────────────────────────────────────────────────────────

PH_LOCAL_OFFSET = timedelta(hours=8)


def _now_local():
    """Current Asia/Manila time as a naive datetime."""
    return datetime.now(timezone.utc).replace(tzinfo=None) + PH_LOCAL_OFFSET


def _business_day_window():
    """Business day runs 6:00 AM -> next 6:00 AM, local (Asia/Manila) time."""
    now = _now_local()
    start = now.replace(hour=6, minute=0, second=0, microsecond=0)
    if now < start:
        start -= timedelta(days=1)
    end = start + timedelta(days=1)
    return start, end


def _parse_uploaded_at(val, naive_is_utc=False):
    """
    Parses a stored timestamp into a naive LOCAL (Asia/Manila) datetime.
    - tz-aware values are converted properly to local time.
    - naive values are assumed to already be local, unless naive_is_utc=True
      (for columns filled by a UTC database default).
    """
    if not val:
        return None

    def _finish(dt):
        if dt.tzinfo:
            return dt.astimezone(timezone.utc).replace(tzinfo=None) + PH_LOCAL_OFFSET
        return dt + PH_LOCAL_OFFSET if naive_is_utc else dt

    if isinstance(val, datetime):
        return _finish(val)
    s = str(val).strip()
    if not s:
        return None
    try:
        return _finish(datetime.fromisoformat(s.replace("Z", "+00:00")))
    except ValueError:
        return None


def _local_ym(val, naive_is_utc=False):
    """(year, month) in LOCAL time; falls back to text parsing for odd formats."""
    dt = _parse_uploaded_at(val, naive_is_utc)
    if dt:
        return (dt.year, dt.month)
    return parse_flexible_date(val)


def _resolve_upload_ym(row):
    """(year, month) the record was uploaded into the system, in local time."""
    return _local_ym(row.get(UPLOAD_COL), NAIVE_UPLOADED_AT_IS_UTC)


def _resolve_transaction_ym(record_table_name, row):
    """
    (year, month) an actual certificate REQUEST happened, from that type's
    payment/transaction table date column, in local time (so a request made
    at 6 AM Manila on the 1st isn't bucketed into the previous UTC month).
    """
    cfg = PAYMENT_TABLES[record_table_name]
    return _local_ym(row.get(cfg["date_col"]))


def _month_add(year, month, delta_months):
    idx = year * 12 + (month - 1) + delta_months
    return idx // 12, idx % 12 + 1


def _rolling_months(n, anchor=None):
    """Last n (year, month) tuples ending at the current LOCAL month, oldest first."""
    anchor = anchor or _now_local()
    return [_month_add(anchor.year, anchor.month, -i) for i in range(n - 1, -1, -1)]


def _resolve_place(table_name, row):
    for col in PLACE_COLUMNS[table_name]:
        val = row.get(col)
        if val and str(val).strip():
            return str(val).strip().title()
    return "Unspecified"


def _to_amount(val):
    """Parses amounts that may be float/int or formatted strings ("₱1,000.00")."""
    if val is None:
        return 0.0
    if isinstance(val, (int, float)):
        try:
            return float(val)
        except (TypeError, ValueError):
            return 0.0
    cleaned = re.sub(r"[^0-9.\-]", "", str(val))
    if not cleaned or cleaned in ("-", "."):
        return 0.0
    try:
        return float(cleaned)
    except (TypeError, ValueError):
        return 0.0


def _to_bool_or_none(val):
    """Normalizes is_archived (bool / None / 'true'/'f' / 1/0)."""
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
# DATA FETCHING
# ══════════════════════════════════════════════════════════════════════════
#
# Fetch failures RAISE (instead of returning a misleading 0). Every route
# wraps its body in try/except and returns {"error": ...}, 500.
# ══════════════════════════════════════════════════════════════════════════

# Transient socket hiccups worth a quick retry (e.g. WinError 10035 on Windows
# when many requests hit Supabase at once).
_RETRYABLE_ERROR_SUBSTRINGS = (
    "10035",
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


def _execute_with_retry(build_query, label):
    """Runs build_query().execute(), retrying transient socket errors with backoff."""
    attempt = 0
    while True:
        try:
            return build_query().execute()
        except Exception as err:
            attempt += 1
            if _is_retryable_error(err) and attempt < _MAX_FETCH_RETRIES:
                wait = _RETRY_BACKOFF_SECONDS * attempt
                print(f"[Analytics] Transient error on {label} "
                      f"(attempt {attempt}/{_MAX_FETCH_RETRIES}), "
                      f"retrying in {wait:.1f}s: {err}")
                time.sleep(wait)
                continue
            raise


def _fetch_paginated(table_name, preferred_columns, gte=None, order_col="id"):
    """
    Paginates through Supabase to fetch every matching row of `table_name`.

    Uses `preferred_columns` only. A select('*') fallback is deliberately NOT
    used: record tables hold base64 PDF blobs, so a wildcard select would pull
    the entire archive into memory. Transient socket errors are retried per
    page. Raises RuntimeError if the fetch fails so the real cause is reported.
    """
    batch_size = 1000
    cols = preferred_columns
    all_rows = []
    offset = 0
    try:
        while True:
            def build(offset=offset):
                query = supabase.table(table_name).select(cols)
                if gte:
                    query = query.gte(*gte)
                if order_col:
                    query = query.order(order_col)
                    if order_col != "id":
                        query = query.order("id")
                return query.range(offset, offset + batch_size - 1)

            res = _execute_with_retry(build, table_name)
            data = res.data or []
            all_rows.extend(data)
            if len(data) < batch_size:
                break
            offset += batch_size
        return all_rows
    except Exception as e:
        print(f"[Analytics] ERROR: could not fetch rows for {table_name} "
              f"with select('{cols}'): {e}")
        raise RuntimeError(
            f"Could not read table '{table_name}' from Supabase "
            f"(check credentials/RLS policies/network/column names): {e}"
        ) from e


def fetch_all_rows(table_name):
    """Every row (archived + active) of a record table."""
    return cached(
        ("records", table_name),
        TTL_RECORDS,
        lambda: _fetch_paginated(table_name, SELECT_COLUMNS[table_name]),
    )


def active_rows(table_name):
    """Return all rows; archive state does not exclude analytics records."""
    return fetch_all_rows(table_name)


def fetch_payment_rows(record_table_name):
    """Every row of the payment/transaction table for the given record table."""
    cfg = PAYMENT_TABLES[record_table_name]
    return cached(
        ("payments", record_table_name),
        TTL_PAYMENTS,
        lambda: _fetch_paginated(cfg["table"], cfg["columns"]),
    )


def _fetch_recent_payment_rows(record_table_name):
    """Payment rows from ~1 day before today's business window (the extra day
    covers any UTC/local skew; exact filtering still happens in Python)."""
    cfg = PAYMENT_TABLES[record_table_name]
    start, _ = _business_day_window()
    cutoff = (start - timedelta(days=1)).isoformat()
    return cached(
        ("recent-payments", record_table_name),
        TTL_RECENT,
        lambda: _fetch_paginated(
            cfg["table"],
            cfg["columns"],
            gte=(cfg["date_col"], cutoff),
            order_col=cfg["date_col"],
        ),
    )


def _fetch_recent_record_rows(table_name):
    """Record rows uploaded since ~1 day before today's business window."""
    start, _ = _business_day_window()
    cutoff = (start - timedelta(days=1)).isoformat()
    return cached(
        ("recent-records", table_name),
        TTL_RECENT,
        lambda: _fetch_paginated(
            table_name,
            UPLOAD_COL,
            gte=(UPLOAD_COL, cutoff),
            order_col=UPLOAD_COL,
        ),
    )


def _count_exact(table_name):
    """Total row count (archived + active) WITHOUT downloading the rows."""
    def load():
        try:
            res = _execute_with_retry(
                lambda: supabase.table(table_name)
                .select("id", count="exact")
                .limit(1),
                f"{table_name} count",
            )
            if res.count is not None:
                return int(res.count)
        except Exception as e:
            print(f"[Analytics] exact count failed for {table_name}, "
                  f"falling back to full fetch: {e}")
        # Fallback keeps the old (correct but heavier) behaviour.
        return len(fetch_all_rows(table_name))

    return cached(("count", table_name), TTL_COUNT, load)


def _count_by_archive(table_name, archived):
    """
    Exact count of ARCHIVED (is_archived TRUE or NULL) or ACTIVE
    (is_archived FALSE) rows. Uses the same definition as the Vital Records
    archive endpoints, so the dashboard and the Archive tab always agree.
    """
    key_name = "count-archived" if archived else "count-active"

    def load():
        def build():
            q = supabase.table(table_name).select("id", count="exact")
            if archived:
                q = q.or_(ARCHIVED_OR_FILTER)
            else:
                q = q.eq(ARCHIVED_COL, "false")
            return q.limit(1)

        try:
            res = _execute_with_retry(build, f"{table_name} {key_name}")
            if res.count is not None:
                return int(res.count)
        except Exception as e:
            print(f"[Analytics] {key_name} count failed for {table_name}, "
                  f"falling back to full fetch: {e}")

        rows = fetch_all_rows(table_name)
        total = 0
        for r in rows:
            flag = _to_bool_or_none(r.get(ARCHIVED_COL))
            is_archived_row = flag is not False  # True or unrecognised/NULL
            if is_archived_row == archived:
                total += 1
        return total

    return cached((key_name, table_name), TTL_COUNT, load)


def _uploaded_today_count(table_name):
    """Number of rows uploaded inside the current business-day window."""
    start, end = _business_day_window()
    today = 0
    for r in _fetch_recent_record_rows(table_name):
        dt = _parse_uploaded_at(r.get(UPLOAD_COL), NAIVE_UPLOADED_AT_IS_UTC)
        if dt and start <= dt < end:
            today += 1
    return today


def payment_stats_today(record_table_name):
    """
    Returns (transactions_today, revenue_today) for the current business day.

    Revenue sums EVERY transaction row in the window (positive records and
    Negative Certificates both cost the same fee), so transactions_today and
    revenue_today always move together.
    """
    cfg = PAYMENT_TABLES[record_table_name]
    rows = _fetch_recent_payment_rows(record_table_name)
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
# COMPUTE FUNCTIONS (results are cached under ("agg", name))
# ══════════════════════════════════════════════════════════════════════════

def _compute_summary():
    totals = {tbl: _count_exact(tbl) for tbl in RECORD_TABLES}
    active = {tbl: _count_by_archive(tbl, archived=False) for tbl in RECORD_TABLES}
    archived = {tbl: _count_by_archive(tbl, archived=True) for tbl in RECORD_TABLES}
    today = {tbl: _uploaded_today_count(tbl) for tbl in RECORD_TABLES}

    birth_total = totals["birth_records"]
    marriage_total = totals["marriage_records"]
    death_total = totals["death_records"]
    total_all = birth_total + marriage_total + death_total

    active_all = sum(active.values())
    archived_all = sum(archived.values())

    return {
        "total_records": total_all,
        "active_records": active_all,
        "archived_records": archived_all,
        "total_birth_records": birth_total,
        "total_marriage_records": marriage_total,
        "total_death_records": death_total,
        "active_by_type": {
            "birth": active["birth_records"],
            "marriage": active["marriage_records"],
            "death": active["death_records"],
        },
        "archived_by_type": {
            "birth": archived["birth_records"],
            "marriage": archived["marriage_records"],
            "death": archived["death_records"],
        },
        "uploaded_today": sum(today.values()),
        "uploaded_today_breakdown": {
            "birth": today["birth_records"],
            "marriage": today["marriage_records"],
            "death": today["death_records"],
        },
        "record_breakdown": [
            {"label": "Birth", "count": birth_total},
            {"label": "Marriage", "count": marriage_total},
            {"label": "Death", "count": death_total},
        ],
    }


def _compute_document_types():
    return [
        {"label": TYPE_LABELS[tbl], "count": _count_exact(tbl)}
        for tbl in RECORD_TABLES
    ]


def _compute_records_by_year():
    years_map = defaultdict(int)
    for tbl in RECORD_TABLES:
        for r in active_rows(tbl):
            try:
                ym = _resolve_upload_ym(r)
            except Exception as e:
                print(f"[Analytics] records-by-year: skipping bad row in {tbl}: {e}")
                continue
            if ym:
                years_map[ym[0]] += 1
    return [{"year": yr, "count": cnt} for yr, cnt in sorted(years_map.items())]


def _compute_records_by_month():
    months_map = {m: 0 for m in range(1, 13)}
    for tbl in RECORD_TABLES:
        for r in active_rows(tbl):
            try:
                ym = _resolve_upload_ym(r)
            except Exception as e:
                print(f"[Analytics] records-by-month: skipping bad row in {tbl}: {e}")
                continue
            if ym:
                months_map[ym[1]] += 1
    return [
        {"month_num": m_num, "month_name": MONTH_NAMES[m_num], "count": cnt}
        for m_num, cnt in months_map.items()
    ]


def _compute_top_municipalities():
    muni_map = {}
    for tbl in RECORD_TABLES:
        type_label = TYPE_LABELS[tbl]
        for r in active_rows(tbl):
            muni = _resolve_place(tbl, r)
            if muni not in muni_map:
                muni_map[muni] = {"cnt": 0, "Birth": 0, "Marriage": 0, "Death": 0}
            muni_map[muni]["cnt"] += 1
            muni_map[muni][type_label] += 1

    sorted_muni = sorted(muni_map.items(), key=lambda x: x[1]["cnt"], reverse=True)[:20]
    return [
        {"name": name, "cnt": d["cnt"], "Birth": d["Birth"],
         "Marriage": d["Marriage"], "Death": d["Death"]}
        for name, d in sorted_muni
    ]


def _compute_dashboard_today():
    start, end = _business_day_window()

    # "Requests today" = transactions logged in the payment tables (NOT newly
    # uploaded record rows), so it always agrees with revenue / business window.
    b_txn, b_revenue = payment_stats_today("birth_records")
    m_txn, m_revenue = payment_stats_today("marriage_records")
    d_txn, d_revenue = payment_stats_today("death_records")

    return {
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
    }


def _compute_requests_by_year():
    years_map = defaultdict(int)
    for tbl in RECORD_TABLES:
        for r in fetch_payment_rows(tbl):
            try:
                ym = _resolve_transaction_ym(tbl, r)
            except Exception as e:
                print(f"[Analytics] requests-by-year: skipping bad row in "
                      f"{PAYMENT_TABLES[tbl]['table']}: {e}")
                continue
            if ym:
                years_map[ym[0]] += 1
    return [{"year": yr, "count": cnt} for yr, cnt in sorted(years_map.items())]


def _compute_requests_by_month():
    months_map = {m: 0 for m in range(1, 13)}
    for tbl in RECORD_TABLES:
        for r in fetch_payment_rows(tbl):
            try:
                ym = _resolve_transaction_ym(tbl, r)
            except Exception as e:
                print(f"[Analytics] requests-by-month: skipping bad row in "
                      f"{PAYMENT_TABLES[tbl]['table']}: {e}")
                continue
            if ym:
                months_map[ym[1]] += 1
    return [
        {"month_num": m_num, "month_name": MONTH_NAMES[m_num], "count": cnt}
        for m_num, cnt in months_map.items()
    ]


def _compute_growth_rate():
    months = _rolling_months(24)  # oldest -> newest, real 24-month local window
    buckets = {ym: {"Birth": 0, "Marriage": 0, "Death": 0} for ym in months}
    month_set = set(months)

    for tbl in RECORD_TABLES:
        type_label = TYPE_LABELS[tbl]
        for r in fetch_payment_rows(tbl):
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

        mom_growth = None
        if prev_count is not None and prev_count > 0:
            mom_growth = round(((total - prev_count) / prev_count) * 100, 1)

        result.append({
            "label": f"{MONTH_NAMES[mo][:3]} {yr}",
            "year": yr,
            "month": mo,
            "count": total,
            "Birth": b["Birth"],
            "Marriage": b["Marriage"],
            "Death": b["Death"],
            "mom_growth": mom_growth,
        })
        prev_count = total
    return result


# ══════════════════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════════════════

# Substrings that indicate the BACKEND cannot reach Supabase at all (DNS
# failure, refused/reset connection, timeout). The frontend uses the 503 +
# {"offline": true} response to fall back to its locally saved data.
_OFFLINE_HINTS = (
    "getaddrinfo", "11001", "name or service not known",
    "temporary failure in name resolution", "connection refused",
    "connection reset", "timed out", "max retries", "unreachable",
)


def _looks_offline(e):
    msg = str(e).lower()
    return any(h in msg for h in _OFFLINE_HINTS)


def _cached_route(name, ttl, compute, label):
    """Shared wrapper: cache the computed result, return JSON, report errors."""
    try:
        return jsonify(cached(("agg", name), ttl, compute)), 200
    except Exception as e:
        print(f"[Analytics] /{label} error: {e}")
        if _looks_offline(e):
            return jsonify({"error": "Database unreachable", "offline": True}), 503
        return jsonify({"error": str(e)}), 500


@analytics_bp.route("/api/analytics/summary", methods=["GET"])
def summary():
    return _cached_route("summary", TTL_AGG_TODAY, _compute_summary, "summary")


@analytics_bp.route("/api/analytics/records-by-year", methods=["GET"])
def records_by_year():
    return _cached_route("records-by-year", TTL_AGG_HEAVY, _compute_records_by_year, "records-by-year")


@analytics_bp.route("/api/analytics/records-by-month", methods=["GET"])
def records_by_month():
    return _cached_route("records-by-month", TTL_AGG_HEAVY, _compute_records_by_month, "records-by-month")


@analytics_bp.route("/api/analytics/top-municipalities", methods=["GET"])
def top_municipalities():
    return _cached_route("top-municipalities", TTL_AGG_HEAVY, _compute_top_municipalities, "top-municipalities")


@analytics_bp.route("/api/analytics/dashboard-today", methods=["GET"])
def dashboard_today():
    return _cached_route("dashboard-today", TTL_AGG_TODAY, _compute_dashboard_today, "dashboard-today")


@analytics_bp.route("/api/analytics/requests-by-year", methods=["GET"])
def requests_by_year():
    return _cached_route("requests-by-year", TTL_AGG_HEAVY, _compute_requests_by_year, "requests-by-year")


@analytics_bp.route("/api/analytics/requests-by-month", methods=["GET"])
def requests_by_month():
    return _cached_route("requests-by-month", TTL_AGG_HEAVY, _compute_requests_by_month, "requests-by-month")


@analytics_bp.route("/api/analytics/growth-rate", methods=["GET"])
def growth_rate():
    return _cached_route("growth-rate", TTL_AGG_HEAVY, _compute_growth_rate, "growth-rate")


@analytics_bp.route("/api/analytics/document-types", methods=["GET"])
def document_types():
    return _cached_route("document-types", TTL_COUNT, _compute_document_types, "document-types")


# ─────────────────────────────────────────────────────────────────────────
# /refresh rate limit (per user, per worker process)
# ─────────────────────────────────────────────────────────────────────────

_refresh_hits = defaultdict(list)
_refresh_guard = threading.Lock()


def _refresh_rate_limited(username):
    """True when this user has already used up their /refresh quota for the window."""
    now = time.monotonic()
    key = (username or "").lower()
    with _refresh_guard:
        recent = [t for t in _refresh_hits[key] if now - t < REFRESH_WINDOW_SECONDS]
        if len(recent) >= REFRESH_MAX_PER_WINDOW:
            _refresh_hits[key] = recent
            return True
        recent.append(now)
        _refresh_hits[key] = recent
        return False


@analytics_bp.route("/api/analytics/refresh", methods=["POST"])
def refresh_cache():
    """
    Clears the worker-local analytics cache so the next dashboard fetch
    reads fresh data. Login is enforced by the blueprint-wide guard, and each
    user is rate limited so one user cannot hammer the database.
    """
    if _refresh_rate_limited(session.get("username")):
        resp = jsonify({
            "ok": False,
            "error": "Too many refreshes. Please wait a minute and try again.",
        })
        resp.headers["Retry-After"] = str(REFRESH_WINDOW_SECONDS)
        return resp, 429

    try:
        invalidate_analytics_cache()
        return jsonify({"ok": True}), 200
    except Exception as e:
        print(f"[Analytics] /refresh error: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500