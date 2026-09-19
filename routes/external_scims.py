import os
import requests
from flask import Blueprint, jsonify, request

external_bp = Blueprint("external", __name__, url_prefix="/api/external")

SCIMS_BASE_URL = os.getenv("SCIMS_API_BASE_URL", "https://cictd.app/api/scims").rstrip("/")
SCIMS_TOKEN    = os.getenv("SCIMS_API_TOKEN", "")  # optional — API works without it
SCIMS_TIMEOUT  = float(os.getenv("SCIMS_API_TIMEOUT", "10"))
MAX_SEARCH_PAGES = int(os.getenv("SCIMS_API_MAX_PAGES", "50"))  # cap for auto-paginated search only

# Placeholder junk the source API sometimes puts in real fields
# (e.g. tel_no: "None"/"none"/"-", suffix: "N/A"). Normalized to None
# so the frontend can treat them as empty consistently.
_EMPTY_VALUES = {"", "none", "n/a", "-", "null", "undefined"}


def _scims_headers():
    headers = {"Accept": "application/json"}
    if SCIMS_TOKEN:
        headers["Authorization"] = f"Bearer {SCIMS_TOKEN}"
    return headers


def _scims_get(path, params=None):
    """
    Low-level GET against the SCIMS API.
    Returns (json_or_None, error_dict_or_None, http_status_to_return_to_client)
    """
    headers = _scims_headers()
    url = f"{SCIMS_BASE_URL}{path}"
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=SCIMS_TIMEOUT)
    except requests.exceptions.Timeout:
        return None, {"error": "The external API did not respond in time."}, 504
    except requests.exceptions.ConnectionError:
        return None, {"error": "Could not reach the external API."}, 502
    except requests.exceptions.RequestException as e:
        print(f"[external_scims] request error: {e}")
        return None, {"error": "External API request failed."}, 502

    if resp.status_code in (401, 403):
        print(f"[external_scims] rejected: {resp.status_code} {resp.text[:200]}")
        return None, {"error": "External API rejected the request."}, resp.status_code

    if resp.status_code == 404:
        return None, {"error": "External API resource not found."}, 404

    if not resp.ok:
        print(f"[external_scims] non-OK status {resp.status_code}: {resp.text[:200]}")
        return None, {"error": f"External API returned status {resp.status_code}."}, 502

    try:
        return resp.json(), None, 200
    except ValueError:
        return None, {"error": "External API returned an invalid response."}, 502


def _clean(val):
    """Turn placeholder junk ('None', '-', 'N/A', ...) into a real None."""
    if val is None:
        return None
    s = str(val).strip()
    if s.lower() in _EMPTY_VALUES:
        return None
    return s


def _normalize_individual(item: dict) -> dict:
    """
    SCIMS returns JSON:API style objects:
        {"id": "GLPLCA5343", "type": "individuals", "attributes": {...}}
    The real fields live under 'attributes', not at the top level.
    This flattens EVERY field seen in the live payload so the frontend
    always has the complete record at the top level, and degrades
    gracefully (never crashes) if a field is renamed/missing upstream.
    The original payload is still kept under 'raw' as a safety net for
    anything not explicitly mapped here.
    """
    if not isinstance(item, dict):
        return {}

    attrs = item.get("attributes") if isinstance(item.get("attributes"), dict) else item

    first  = _clean(attrs.get("first_name"))
    middle = _clean(attrs.get("middle_name"))
    last   = _clean(attrs.get("last_name"))
    prefix = _clean(attrs.get("prefix"))
    suffix = _clean(attrs.get("suffix"))

    # Prefer an explicit full_name from the API if present, else build one.
    full_name = _clean(attrs.get("full_name"))
    if not full_name:
        name_parts = [p for p in [prefix, first, middle, last, suffix] if p]
        full_name = " ".join(name_parts) if name_parts else None

    return {
        # Identification
        "entity_no":    _clean(attrs.get("entity_no")) or item.get("id"),
        "prefix":       prefix,
        "first_name":   first,
        "middle_name":  middle,
        "last_name":    last,
        "suffix":       suffix,
        "full_name":    full_name,
        "status":       _clean(attrs.get("status")),

        # Personal information
        "gender":       _clean(attrs.get("gender")),
        "birth_date":   _clean(attrs.get("birth_date")),
        "place_birth":  _clean(attrs.get("place_birth")),
        "civil_status": _clean(attrs.get("civil_status")),
        "citizenship":  _clean(attrs.get("citizenship")),
        "religion":     _clean(attrs.get("religion")),
        "blood_type":   _clean(attrs.get("blood_type")),
        "height":       _clean(attrs.get("height")),
        "weight":       _clean(attrs.get("weight")),

        # Contact information
        "mobile_no":    _clean(attrs.get("mobile_no")),
        "tel_no":       _clean(attrs.get("tel_no")),
        "fax_no":       _clean(attrs.get("fax_no")),
        "email_add":    _clean(attrs.get("email_add")),
        "website":      _clean(attrs.get("website")),

        # Misc
        "photo":        _clean(attrs.get("photo")),

        # Safety net — full original payload for anything not mapped above
        "raw": item,
    }


def _extract_meta(data: dict) -> dict:
    """Pull just the pagination fields the frontend needs to render a pager."""
    meta = data.get("meta") if isinstance(data, dict) else None
    if not isinstance(meta, dict):
        return {}
    return {
        "current_page": meta.get("current_page"),
        "last_page":    meta.get("last_page"),
        "per_page":     meta.get("per_page"),
        "total":        meta.get("total"),
    }


def _fetch_all_matching(params=None):
    """
    Walks every page of a FILTERED (search) query so the caller gets the
    complete result set, not just page 1. Search results are small
    relative to the full masterlist, so this stays fast. Hard-capped at
    MAX_SEARCH_PAGES so a misbehaving API/filter can't loop forever.
    Intentionally NOT used for the unfiltered masterlist — 1,884+ pages
    would be far too slow to walk on every request.
    """
    all_items = []
    page = 1
    params = dict(params or {})

    while page <= MAX_SEARCH_PAGES:
        params["page"] = page
        data, err, status = _scims_get("/individual", params=params)
        if err:
            return all_items, err, status

        items = data.get("data") if isinstance(data, dict) else None
        items = items or []
        all_items.extend(items)

        last_page = _extract_meta(data).get("last_page")
        if not last_page or page >= last_page:
            break
        page += 1

    return all_items, None, 200


@external_bp.route("/entities", methods=["GET"])
def get_entities():
    """
    GET /api/external/entities                    -> page 1 of the full masterlist (browsing)
    GET /api/external/entities?page=5              -> a specific page of the masterlist
    GET /api/external/entities?page=5&per_page=25  -> passed straight through to SCIMS
    GET /api/external/entities?search=dela+cruz    -> ALL matching pages, fully collected

    The masterlist has tens of thousands of records across many pages, so
    without a search term this only fetches ONE page at a time (page/per_page
    are passed straight through to SCIMS) and returns pagination info so the
    frontend can build a pager. With a search term, results are usually
    few, so every matching page is walked and returned at once.
    """
    search = request.args.get("search", "").strip()

    if search:
        items, err, status = _fetch_all_matching(params={"filter[search]": search})
        if err:
            return jsonify(err), status
        return jsonify({
            "mode": "search",
            "count": len(items),
            "entities": [_normalize_individual(i) for i in items],
        })

    # No search -> browse mode, one SCIMS page per request
    page     = request.args.get("page", "1")
    per_page = request.args.get("per_page")
    params = {"page": page}
    if per_page:
        params["per_page"] = per_page

    data, err, status = _scims_get("/individual", params=params)
    if err:
        return jsonify(err), status

    items = (data.get("data") or []) if isinstance(data, dict) else []
    return jsonify({
        "mode": "browse",
        "count": len(items),
        "entities": [_normalize_individual(i) for i in items],
        "pagination": _extract_meta(data),
    })


@external_bp.route("/entities/<id>", methods=["GET"])
def get_entity(id):
    """
    GET /api/external/entities/<id>
    Fetch a single individual by SCIMS entity_no/ID — returns the FULL
    normalized record (every field explicitly present) for the detail
    modal on the frontend.
    """
    data, err, status = _scims_get(f"/individual/{id}")
    if err:
        return jsonify(err), status

    raw = data.get("data") if isinstance(data, dict) and "data" in data else data
    if not raw:
        return jsonify({"error": "Individual not found."}), 404

    return jsonify(_normalize_individual(raw))


@external_bp.route("/health", methods=["GET"])
def health_check():
    """Quick check that the integration is reachable."""
    data, err, status = _scims_get("/individual", params={"page": 1})
    return jsonify({
        "reachable": err is None,
        "base_url": SCIMS_BASE_URL,
        "auth_mode": "bearer_token" if SCIMS_TOKEN else "none (public endpoint)",
        "detail": err["error"] if err else "OK",
    }), (200 if err is None else status)