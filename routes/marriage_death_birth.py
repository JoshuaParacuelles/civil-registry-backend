import io
import re
import os
import json
import uuid
import base64
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import bcrypt
from flask import Blueprint, jsonify, request, send_file, session
from werkzeug.utils import secure_filename
from pypdf import PdfReader
from postgrest.exceptions import APIError

from supabase_client import supabase
from routes.notification import push_notification
from logs.Audits import record_action


# =============================================================================
# ONLINE-REQUEST DETECTION — shared by Birth/Death/Marriage "complete
# transaction" / "create payment" routes below.
#
# WHY THIS WAS ADDED: push_notification() was previously called any time a
# transaction matched an EXISTING record in birth_records / death_records /
# marriage_records (record_status "ACTIVE"/"POSITIVE") — regardless of
# whether that record was ever submitted through the public Online Request
# system, or was simply looked up/processed directly from the Birth/
# Marriage/Death data by staff. That meant processing an existing record
# (e.g. "John Doe") straight from the archive triggered the exact same
# client-facing notification as an actual online citizen submission, even
# though nobody submitted anything online and there is no client to notify.
#
# Fix: before any push_notification() call below, check whether a matching
# row actually exists in `civil_registry_request` — the table the public
# Online Request system writes to (see routes/citizen_requests.py) — for
# this same person and record type. Only when such a row exists do we treat
# the transaction as originating from an online request and fire the
# notification. A record processed directly from Birth/Marriage/Death data,
# with no corresponding online submission, now never triggers a
# notification (no email, no SMS, no admin/client alert of any kind).
#
# Matching is done two ways, either of which is sufficient:
#   1. By control number, if the payment/OR reference passed in happens to
#      match an actual online request's control_no.
#   2. By name, against the same columns citizen_requests.py's own search
#      already uses (child_firstname/child_surname for birth,
#      deceased_firstname/deceased_surname for death, husband_fullname /
#      wife_maiden_name for marriage).
#
# Any lookup failure (e.g. a transient DB error) fails CLOSED — i.e. no
# notification — since the requirement is that notifications only ever go
# out for confirmed online requests, never "notify by default".
# =============================================================================

CIVIL_REGISTRY_REQUEST_TABLE = "civil_registry_request"


def _matches_online_birth_request(first_name: Optional[str], last_name: Optional[str],
                                   control_no: Optional[str] = None) -> bool:
    try:
        if control_no:
            res = supabase.table(CIVIL_REGISTRY_REQUEST_TABLE).select("id") \
                .eq("record_type", "birth").eq("control_no", control_no).limit(1).execute()
            if res.data:
                return True
        if first_name and last_name:
            res = supabase.table(CIVIL_REGISTRY_REQUEST_TABLE).select("id") \
                .eq("record_type", "birth") \
                .ilike("child_firstname", first_name.strip()) \
                .ilike("child_surname", last_name.strip()) \
                .limit(1).execute()
            return bool(res.data)
        return False
    except Exception:
        return False


def _matches_online_death_request(first_name: Optional[str], last_name: Optional[str],
                                   control_no: Optional[str] = None) -> bool:
    try:
        if control_no:
            res = supabase.table(CIVIL_REGISTRY_REQUEST_TABLE).select("id") \
                .eq("record_type", "death").eq("control_no", control_no).limit(1).execute()
            if res.data:
                return True
        if first_name and last_name:
            res = supabase.table(CIVIL_REGISTRY_REQUEST_TABLE).select("id") \
                .eq("record_type", "death") \
                .ilike("deceased_firstname", first_name.strip()) \
                .ilike("deceased_surname", last_name.strip()) \
                .limit(1).execute()
            return bool(res.data)
        return False
    except Exception:
        return False


def _matches_online_marriage_request(groom_full_name: Optional[str] = None,
                                      bride_full_name: Optional[str] = None,
                                      control_no: Optional[str] = None) -> bool:
    try:
        if control_no:
            res = supabase.table(CIVIL_REGISTRY_REQUEST_TABLE).select("id") \
                .eq("record_type", "marriage").eq("control_no", control_no).limit(1).execute()
            if res.data:
                return True
        if groom_full_name:
            res = supabase.table(CIVIL_REGISTRY_REQUEST_TABLE).select("id") \
                .eq("record_type", "marriage") \
                .ilike("husband_fullname", groom_full_name.strip()) \
                .limit(1).execute()
            if res.data:
                return True
        if bride_full_name:
            res = supabase.table(CIVIL_REGISTRY_REQUEST_TABLE).select("id") \
                .eq("record_type", "marriage") \
                .ilike("wife_maiden_name", bride_full_name.strip()) \
                .limit(1).execute()
            return bool(res.data)
        return False
    except Exception:
        return False


# #############################################################################
# ############################  DEATH  BACKEND  ##############################
# (originally routes/Death.py)
# #############################################################################

death_bp = Blueprint("death", __name__, url_prefix="/api/death")

# NOTE: renamed from ALLOWED_EXTENSIONS / MAX_FILE_SIZE_MB / MAX_FILE_SIZE_BYTES
# to DEATH_* to avoid clashing with marriage.py's identically-named
# module-level constants now that both live in this one file.
DEATH_ALLOWED_EXTENSIONS = {"pdf"}
DEATH_MAX_FILE_SIZE_MB = 20
DEATH_MAX_FILE_SIZE_BYTES = DEATH_MAX_FILE_SIZE_MB * 1024 * 1024


def init_death_db():
    """No-op: death_records / death_transactions / module_passwords tables
    are created via Supabase SQL Editor, not dynamically from Python."""
    print("[DEATH] Using Supabase tables 'death_records' / 'death_transactions'")


# =============================================================================
# UTILS (Death)
# =============================================================================

def now_dt() -> datetime:
    return datetime.now()


def death_allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in DEATH_ALLOWED_EXTENSIONS


def safe_stem(filename: str) -> str:
    filename = filename.strip()
    if "." in filename:
        return filename.rsplit(".", 1)[0]
    return filename


def title_case(value: Optional[str]) -> str:
    if not value:
        return ""
    return " ".join(word.capitalize() for word in str(value).strip().split())


def normalize_spaces(value: Optional[str]) -> str:
    if not value:
        return ""
    return re.sub(r"\s+", " ", str(value)).strip()


def normalize_yes_no(value: str) -> str:
    v = normalize_spaces(value).upper()
    if v in {"YES", "Y"}:
        return "Yes"
    if v in {"NO", "N"}:
        return "No"
    return normalize_spaces(value)


def to_base64_pdf(pdf_b64: str) -> str:
    return f"data:application/pdf;base64,{pdf_b64}"


def _serialise_dt(value) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%dT%H:%M:%S")
    s = str(value).strip()
    if not s:
        return None
    return s.replace(" ", "T")


def parse_date_flexible(value: str) -> Optional[datetime]:
    if not value:
        return None
    value = normalize_spaces(value)
    formats = [
        "%d %B %Y", "%d %b %Y", "%B %d %Y", "%b %d %Y",
        "%Y-%m-%d", "%m/%d/%Y", "%d/%m/%Y",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except Exception:
            pass
    return None


def find_first(values: List[str], predicate) -> str:
    for v in values:
        if predicate(v):
            return v
    return ""


def serialize_fields(fields: List[Dict[str, str]]) -> str:
    return json.dumps(fields, ensure_ascii=False)


# =============================================================================
# PASSWORD VERIFICATION HELPER (Death)
# =============================================================================

def verify_module_password(module_key: str, password: str) -> bool:
    if not module_key or not password:
        return False
    try:
        res = supabase.table("module_passwords").select("password_hash").eq("module_key", module_key).limit(1).execute()
        if not res.data:
            return False
        stored_hash = res.data[0]["password_hash"]
        if isinstance(stored_hash, str):
            stored_hash = stored_hash.encode("utf-8")
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash)
    except Exception:
        return False


# =============================================================================
# SHARED SELECT COLUMNS (Supabase select string, no pdf_file/raw blob)
#
# NOTE: renamed from RECORD_SELECT_COLS to DEATH_RECORD_SELECT_COLS to avoid
# clashing with marriage.py's identically-named module-level constant.
# =============================================================================

DEATH_RECORD_SELECT_COLS = (
    "id, file_name, original_file_name, "
    "province, city_municipality, registry_no, "
    "deceased_first_name, deceased_middle_name, deceased_last_name, deceased_full_name, "
    "sex, date_of_death, date_of_birth, age_at_death, place_of_death, "
    "civil_status, religion, citizenship, residence, occupation, "
    "father_name, mother_name, "
    "cause_immediate, cause_antecedent, cause_underlying, cause_other, "
    "manner_of_death, place_of_occurrence, autopsy, "
    "raw_text, raw_fields_json, "
    "is_archived, uploaded_at, archived_at, created_at, updated_at"
)

# =============================================================================
# PDF PARSER (unchanged logic) (Death)
# =============================================================================

def extract_pdf_text_and_fields_from_bytes(pdf_bytes: bytes) -> Tuple[str, List[Dict[str, str]]]:
    reader = PdfReader(io.BytesIO(pdf_bytes))
    all_text = []
    ordered_fields = []

    for page in reader.pages:
        try:
            text = page.extract_text() or ""
        except Exception:
            text = ""
        all_text.append(text)

        annots = page.get("/Annots", [])
        for annot_ref in annots:
            try:
                annot = annot_ref.get_object()
                field_name  = annot.get("/T", "")
                field_value = annot.get("/V", "")
                if field_value is None:
                    continue
                value = str(field_value).strip()
                if not value:
                    continue
                ordered_fields.append({"name": str(field_name), "value": value})
            except Exception:
                continue

    return "\n".join(all_text), ordered_fields


def parse_death_certificate_from_bytes(pdf_bytes: bytes) -> Dict:
    text, ordered_fields = extract_pdf_text_and_fields_from_bytes(pdf_bytes)
    values = [normalize_spaces(item["value"]) for item in ordered_fields if normalize_spaces(item["value"])]

    result = {
        "province": "", "city_municipality": "", "registry_no": "",
        "deceased_first_name": "", "deceased_middle_name": "", "deceased_last_name": "",
        "deceased_full_name": "", "sex": "",
        "date_of_death": "", "date_of_birth": "", "age_at_death": "",
        "place_of_death": "", "civil_status": "", "religion": "",
        "citizenship": "", "residence": "", "occupation": "",
        "father_name": "", "mother_name": "",
        "cause_immediate": "", "cause_antecedent": "", "cause_underlying": "",
        "cause_other": "", "manner_of_death": "", "place_of_occurrence": "",
        "autopsy": "",
        "raw_text": text,
        "raw_fields_json": serialize_fields(ordered_fields),
    }

    if len(values) >= 6:
        result["province"]              = values[0]
        result["city_municipality"]     = values[1]
        result["registry_no"]           = values[2]
        result["deceased_first_name"]   = title_case(values[3])
        result["deceased_middle_name"]  = title_case(values[4])
        result["deceased_last_name"]    = title_case(values[5])

    result["deceased_full_name"] = normalize_spaces(
        f'{result["deceased_first_name"]} {result["deceased_middle_name"]} {result["deceased_last_name"]}'
    )
    result["sex"] = title_case(find_first(values, lambda v: v.upper() in {"MALE", "FEMALE"}))

    if not result["registry_no"]:
        result["registry_no"] = find_first(values, lambda v: re.fullmatch(r"\d{4}-[\w\-]+", v) is not None)

    result["citizenship"] = find_first(values, lambda v: v.upper() == "FILIPINO")
    result["civil_status"] = title_case(find_first(
        values,
        lambda v: v.upper() in {"SINGLE", "MARRIED", "WIDOW", "WIDOWER", "ANNULLED", "DIVORCED"}
    ))

    date_candidates = []
    for v in values:
        parsed = parse_date_flexible(v)
        if parsed:
            date_candidates.append((v, parsed))

    if len(date_candidates) >= 2:
        sorted_dates = sorted(date_candidates, key=lambda x: x[1])
        result["date_of_birth"] = sorted_dates[0][0]
        result["date_of_death"] = sorted_dates[-1][0]

    result["age_at_death"] = find_first(
        values,
        lambda v: bool(re.search(r"\b\d+\s*(YEAR|YEARS|YRS?)\b", v.upper()))
    )

    yes_no_values = [v for v in values if v.upper() in {"YES", "NO", "Y", "N"}]
    if yes_no_values:
        result["autopsy"] = normalize_yes_no(yes_no_values[-1])

    result["manner_of_death"] = title_case(find_first(
        values,
        lambda v: v.upper() in {
            "NATURAL", "ACCIDENT", "HOMICIDE", "SUICIDE",
            "PENDING INVESTIGATION", "LEGAL INTERVENTION"
        }
    ))
    result["place_of_occurrence"] = find_first(
        values,
        lambda v: v.upper() == "N/A" or v.upper() in {"HOME", "HOSPITAL", "FARM", "FACTORY", "STREET", "SEA"}
    )

    fallbacks = [
        (6,  "citizenship"), (7, "religion"), (8, "residence"), (9, "occupation"),
        (10, "father_name"), (11, "mother_name"), (12, "place_of_death"),
        (13, "date_of_birth"), (14, "date_of_death"), (16, "age_at_death"),
        (21, "cause_immediate"), (22, "cause_antecedent"), (23, "cause_other"),
        (24, "manner_of_death"), (25, "place_of_occurrence"), (26, "autopsy"),
        (27, "cause_underlying"),
    ]
    for idx, key in fallbacks:
        if len(values) > idx and not result[key]:
            val = values[idx]
            if key in ("father_name", "mother_name"):
                result[key] = title_case(val)
            elif key == "autopsy":
                result[key] = normalize_yes_no(val)
            elif key in ("manner_of_death",):
                result[key] = title_case(val)
            else:
                result[key] = val

    for key in list(result.keys()):
        if isinstance(result[key], str):
            result[key] = normalize_spaces(result[key])

    result["deceased_full_name"] = normalize_spaces(
        f'{result["deceased_first_name"]} {result["deceased_middle_name"]} {result["deceased_last_name"]}'
    )

    return result


# =============================================================================
# API ROUTES (Death)
# =============================================================================

@death_bp.route("/records", methods=["GET"])
def get_records():
    res = supabase.table("death_records").select(DEATH_RECORD_SELECT_COLS) \
        .order("uploaded_at", desc=True).order("id", desc=True).execute()
    return jsonify(res.data)


# =============================================================================
# ARCHIVE-FILTER FIX (Death) — same class of bug already fixed for Birth
# (BIRTH_ARCHIVED_FILTER) and Marriage (MARRIAGE_ARCHIVED_FILTER).
#
# Symptom: rows inserted directly via the Supabase table editor / a raw
# SQL import never have is_archived explicitly set, so it's NULL. A plain
#     .eq("is_archived", True)
# never matches NULL (NULL = true is unknown/false in SQL), so those rows
# were invisible in the Archive tab even though they're in the table.
#
# The raw Python `True` here also has the same serialization problem
# documented in Birth's _bool_filter() docstring: postgrest-py's .eq()
# stringifies a Python bool as "True"/"False" (capitalized), which
# PostgREST's boolean parser rejects — so this line could 500 on its own
# even before the NULL issue ever came into play.
#
# Fix: go through _bool_filter() for a PostgREST-safe lowercase string,
# and use .or_() so NULL rows are treated as archived too — Death uploads
# always set is_archived = True at insert time (see upload_record()
# above), same as Birth, so an un-flagged row is far more consistent with
# "archived" than "active" here.
# =============================================================================

DEATH_ARCHIVED_FILTER = "is_archived.eq.true,is_archived.is.null"


@death_bp.route("/archived", methods=["GET"])
def get_archived_records():
    try:
        res = supabase.table("death_records").select(DEATH_RECORD_SELECT_COLS) \
            .or_(DEATH_ARCHIVED_FILTER) \
            .order("archived_at", desc=True).order("id", desc=True).execute()
        return jsonify(res.data)
    except Exception as e:
        import traceback
        traceback.print_exc()  # surfaces the real PostgREST error server-side instead of hiding it
        return jsonify({"error": f"Failed to load archived records: {e}"}), 500


@death_bp.route("/records", methods=["POST"])
def upload_record():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    file = request.files["file"]
    if not file or not file.filename:
        return jsonify({"error": "No selected file."}), 400
    if not death_allowed_file(file.filename):
        return jsonify({"error": "Only PDF files are allowed."}), 400

    file_bytes = file.read()
    if not file_bytes:
        return jsonify({"error": "Uploaded file is empty."}), 400
    if len(file_bytes) > DEATH_MAX_FILE_SIZE_BYTES:
        return jsonify({"error": f"File exceeds {DEATH_MAX_FILE_SIZE_MB} MB limit."}), 400

    original_file_name = file.filename.strip()
    file_stem          = safe_stem(original_file_name)

    try:
        parsed       = parse_death_certificate_from_bytes(file_bytes)
        current_time = now_dt().isoformat()
        pdf_b64      = base64.b64encode(file_bytes).decode("utf-8")

        insert_payload = {
            "file_name": file_stem,
            "original_file_name": original_file_name,
            "pdf_file": pdf_b64,
            "pdf_mime_type": "application/pdf",
            "stored_file_name": original_file_name,
            "file_path": "",
            **parsed,
            "is_archived": True,
            "uploaded_at": current_time,
            "archived_at": current_time,
            "created_at": current_time,
            "updated_at": current_time,
        }

        res = supabase.table("death_records").insert(insert_payload).execute()

        if not res.data:
            return jsonify({"error": "Failed to insert record."}), 500

        record_id = res.data[0]["id"]

        fetch_res = supabase.table("death_records").select(DEATH_RECORD_SELECT_COLS).eq("id", record_id).single().execute()
        return jsonify(fetch_res.data), 201

    except Exception as e:
        return jsonify({"error": f"Failed to process PDF: {str(e)}"}), 500


@death_bp.route("/records/<int:record_id>", methods=["GET"])
def get_record_pdf(record_id: int):
    res = supabase.table("death_records").select("*").eq("id", record_id).limit(1).execute()

    if not res.data:
        return jsonify({"error": "Record not found."}), 404

    data = res.data[0]
    pdf_b64 = data.get("pdf_file")
    if not pdf_b64:
        return jsonify({"error": "PDF file not found in database."}), 404

    data = {k: v for k, v in data.items() if k != "pdf_file"}
    data["pdf_data"] = to_base64_pdf(pdf_b64)
    return jsonify(data)


@death_bp.route("/records/<int:record_id>/download", methods=["GET"])
def download_record_pdf(record_id: int):
    res = supabase.table("death_records").select("original_file_name, pdf_file, pdf_mime_type").eq("id", record_id).limit(1).execute()

    if not res.data:
        return jsonify({"error": "Record not found."}), 404

    row = res.data[0]
    pdf_b64 = row.get("pdf_file")
    if not pdf_b64:
        return jsonify({"error": "PDF file not found in database."}), 404

    pdf_bytes = base64.b64decode(pdf_b64)

    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype=row.get("pdf_mime_type") or "application/pdf",
        as_attachment=True,
        download_name=row.get("original_file_name") or f"death_record_{record_id}.pdf"
    )


@death_bp.route("/records/<int:record_id>/archive", methods=["PUT", "POST"])
def archive_record(record_id: int):
    try:
        current_time = now_dt().isoformat()
        res = supabase.table("death_records").update({
            "is_archived": True,
            "archived_at": current_time,
            "updated_at": current_time
        }).eq("id", record_id).execute()

        if not res.data:
            return jsonify({"error": "Record not found."}), 404

        # FIX (audit trail — prevents the archive bug from recurring
        # unnoticed): log every archive action, mirroring Birth's
        # archive_record(). This endpoint is only ever supposed to be
        # called by an explicit admin action; logging it means any
        # unexpected/automatic call (e.g. a future frontend regression)
        # shows up immediately in the audit log instead of going
        # unnoticed for days or months like the original bug did.
        archived_row = res.data[0] if res.data else {}
        record_action(
            "ARCHIVE",
            f"Archived death record: '{archived_row.get('file_name', record_id)}'",
            username=get_user(),
            meta={"record_id": record_id, "file_name": archived_row.get("file_name")},
            ip=request.remote_addr
        )

        return jsonify({"success": True, "message": "Record archived successfully."}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to archive record: {str(e)}"}), 500


@death_bp.route("/records/<int:record_id>/restore", methods=["PUT", "POST"])
def restore_record(record_id: int):
    try:
        current_time = now_dt().isoformat()
        res = supabase.table("death_records").update({
            "is_archived": False,
            "archived_at": None,
            "updated_at": current_time
        }).eq("id", record_id).execute()

        if not res.data:
            return jsonify({"error": "Archived record not found."}), 404

        # FIX (audit trail — prevents the archive bug from recurring
        # unnoticed): log every restore action, mirroring Birth's
        # restore_record(). is_archived should only ever flip to FALSE
        # here, in response to an explicit admin "Restore" click. Logging
        # every call — who triggered it, when, and which record — means
        # that if this endpoint is ever hit unexpectedly again (e.g. a
        # future frontend bug re-introducing an implicit restore call),
        # it will be immediately visible in the audit trail instead of
        # silently un-archiving records for weeks before anyone notices.
        restored_row = res.data[0] if res.data else {}
        record_action(
            "RESTORE",
            f"Restored death record: '{restored_row.get('file_name', record_id)}'",
            username=get_user(),
            meta={"record_id": record_id, "file_name": restored_row.get("file_name")},
            ip=request.remote_addr
        )

        return jsonify({"success": True, "message": "Record restored successfully."}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to restore record: {str(e)}"}), 500


@death_bp.route("/records/<int:record_id>", methods=["DELETE"])
def delete_record(record_id: int):
    try:
        res = supabase.table("death_records").delete().eq("id", record_id).execute()
        if not res.data:
            return jsonify({"error": "Record not found."}), 404
        return jsonify({"success": True, "message": "Record deleted permanently."}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to delete record: {str(e)}"}), 500


@death_bp.route("/records/complete", methods=["POST"])
def complete_transaction():
    data = request.get_json(silent=True) or {}

    raw_status    = normalize_spaces(data.get("recordStatus", ""))
    record_status = raw_status.upper() if raw_status else "UNKNOWN"

    try:
        first_name  = normalize_spaces(data.get("first_name",  data.get("firstName",  "")))
        middle_name = normalize_spaces(data.get("middle_name", data.get("middleName", "")))
        last_name   = normalize_spaces(data.get("last_name",   data.get("lastName",   "")))

        record_id_raw = data.get("recordId")
        record_id: Optional[int] = None
        if record_id_raw not in (None, "", "null", "undefined"):
            try:
                record_id = int(record_id_raw)
            except (TypeError, ValueError):
                record_id = None

        if record_id and not (first_name or last_name):
            rec_res = supabase.table("death_records").select(
                "deceased_first_name, deceased_middle_name, deceased_last_name"
            ).eq("id", record_id).limit(1).execute()
            if rec_res.data:
                row = rec_res.data[0]
                first_name  = normalize_spaces(row.get("deceased_first_name") or "")
                middle_name = normalize_spaces(row.get("deceased_middle_name") or "")
                last_name   = normalize_spaces(row.get("deceased_last_name") or "")

        search_operator   = normalize_spaces(data.get("searchOperator", ""))
        payment_reference = normalize_spaces(data.get("paymentReference", ""))
        payment_amount    = float(data.get("paymentAmount", 0) or 0)

        insert_res = supabase.table("death_transactions").insert({
            "search_operator": search_operator,
            "record_status": record_status,
            "record_id": record_id,
            "payment_method": normalize_spaces(data.get("paymentMethod", "")),
            "payment_reference": payment_reference,
            "payment_amount": payment_amount,
            "document_type": normalize_spaces(data.get("documentType", "")),
            "document_issued": normalize_spaces(data.get("documentIssued", "")),
            "first_name": first_name,
            "middle_name": middle_name,
            "last_name": last_name,
            "created_at": now_dt().isoformat()
        }).execute()

        # ── NOTIFICATION: only fire when record was FOUND in the database
        # AND that record was originally submitted through the Online
        # Request system (see _matches_online_death_request() /
        # CIVIL_REGISTRY_REQUEST_TABLE at the top of this file). Processing
        # an existing death record directly from the Death data — with no
        # matching online request — no longer sends any notification. ──
        if record_status in ("ACTIVE", "POSITIVE") and _matches_online_death_request(
            first_name, last_name, control_no=payment_reference or None
        ):
            full_name_parts = [p for p in [first_name, middle_name, last_name] if p]
            subject = " ".join(full_name_parts) if full_name_parts else (search_operator or "Unknown")
            push_notification(
                record_type="DEATH",
                record_id=record_id,
                control_no=payment_reference or search_operator or None,
                message=f"Death certificate issued for '{subject}'",
                notif_type="death",
            )

        return jsonify({"success": True, "message": "Transaction saved successfully."}), 200

    except Exception as e:
        return jsonify({"error": f"Failed to save transaction: {str(e)}"}), 500


# =============================================================================
# PAYMENT STATUS NORMALISATION (Death)
# =============================================================================

def _normalize_payment_status(record_status: str) -> str:
    if not record_status:
        return "Paid"
    upper = record_status.strip().upper()
    if upper == "POSITIVE":  return "Positive"
    if upper == "NEGATIVE":  return "Negative"
    if upper == "ACTIVE":    return "Positive"
    return record_status.strip().title() or "Paid"


@death_bp.route("/payments", methods=["GET"])
def get_payments():
    limit_param = request.args.get("limit")

    query = supabase.table("death_transactions").select(
        "id, search_operator, record_status, record_id, "
        "payment_method, payment_reference, payment_amount, "
        "document_type, document_issued, "
        "first_name, middle_name, last_name, created_at"
    ).order("created_at", desc=True).order("id", desc=True)

    if limit_param and limit_param.isdigit():
        query = query.limit(int(limit_param))

    res = query.execute()
    rows = res.data

    agg_res = supabase.table("death_transactions").select("payment_amount").execute()
    total_requests = len(agg_res.data)
    total_payments = sum(float(r.get("payment_amount") or 0) for r in agg_res.data)

    payments = []
    for item in rows:
        item = dict(item)
        raw_amount            = item.pop("payment_amount", None)
        item["amount"]        = float(raw_amount) if raw_amount is not None else 0.0
        serialised_at         = _serialise_dt(item.get("created_at"))
        item["created_at"]    = serialised_at
        item["payment_date"]  = serialised_at
        item["payment_status"] = _normalize_payment_status(item.get("record_status", ""))
        item["first_name"]    = item.get("first_name")  or ""
        item["middle_name"]   = item.get("middle_name") or ""
        item["last_name"]     = item.get("last_name")   or ""
        payments.append(item)

    return jsonify({
        "payments":       payments,
        "total_requests": total_requests,
        "total_payments": total_payments,
    }), 200


@death_bp.route("/stats", methods=["GET"])
def get_stats():
    res = supabase.table("death_transactions").select("payment_amount").execute()
    total_requests = len(res.data)
    total_payments = sum(float(r.get("payment_amount") or 0) for r in res.data)
    return jsonify({
        "total_requests": total_requests,
        "total_payments": total_payments,
    }), 200


# =============================================================================
# AUTH (Death)
# =============================================================================

@death_bp.route("/auth/verify", methods=["POST"])
def verify_password():
    data     = request.get_json(silent=True) or {}
    module   = normalize_spaces(data.get("module",   ""))
    password = data.get("password", "")

    if not module or not password:
        return jsonify({"success": False, "message": "Module and password are required."}), 400

    if verify_module_password(module, password):
        return jsonify({"success": True}), 200

    return jsonify({"success": False, "message": "Incorrect password."}), 401


# #############################################################################
# ############################  BIRTH  BACKEND  ##############################
# (originally routes/birth.py)
# #############################################################################

birth_bp = Blueprint('birth', __name__)


def get_user():
    return session.get("username", "System")


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS (unchanged — pure text/PDF-parsing logic, no DB involved)
# ─────────────────────────────────────────────────────────────────────────────

def _clean_text(value):
    if value is None:
        return None
    value = str(value).strip()
    return value if value else None


def _clean_upper(value):
    value = _clean_text(value)
    return value.upper() if value else None


def _clean_title(value):
    value = _clean_text(value)
    return value.title() if value else None


def _clean_int(value):
    value = _clean_text(value)
    if not value:
        return None
    digits = re.sub(r'[^0-9]', '', value)
    return int(digits) if digits else None


def _build_full_name(first, middle, last):
    """Always builds full name in correct order: First Middle Last"""
    parts = [p for p in [first, middle, last] if p]
    return " ".join(parts) if parts else None


def _parse_birth_date(day, month, year):
    if not day or not month or not year:
        return None
    try:
        month_map = {
            'january': 1, 'february': 2, 'march': 3, 'april': 4,
            'may': 5, 'june': 6, 'july': 7, 'august': 8,
            'september': 9, 'october': 10, 'november': 11, 'december': 12
        }
        m = month_map.get(str(month).strip().lower())
        d = int(str(day).strip())
        y = int(str(year).strip())
        if m:
            return datetime(y, m, d).date()
    except Exception:
        return None
    return None


# ─────────────────────────────────────────────────────────────────────────────
# BOOLEAN FILTER HELPER — THE ACTUAL FIX FOR THE 500s ON
# /api/birth/records AND /api/birth/archived
#
# Symptom: both list endpoints returned 500 on every load.
#
# Root cause: postgrest-py's QueryRequestBuilder.eq() serializes whatever
# value you pass it with str(value). Passed a Python bool, str(True) /
# str(False) produce "True" / "False" (capitalized). PostgREST's boolean
# input parser only accepts lowercase true/false, so
#     .eq("is_archived", False)
# was sent on the wire as `is_archived=eq.False`, PostgREST rejected it
# with an "invalid input syntax for type boolean" error, and that
# exception bubbled up through our try/except as a 500.
#
# The analytics endpoints never hit this because they deliberately fetch
# every row and filter client-side in Python (see analytics.py's
# _to_bool_or_none) instead of filtering via .eq() on this column — which
# is exactly why Marriage/Death counts kept working while Birth's list
# endpoints broke.
#
# Fix: never pass a raw Python bool into .eq()/.neq() etc. Always go
# through _bool_filter() below, which gives PostgREST the lowercase
# string it expects.
#
# NOTE: this helper is byte-for-byte identical to the one that used to be
# separately defined in marriage.py. Since both blueprints now live in
# the same module, it is defined ONCE here and reused by the Marriage
# section below — this changes nothing about either blueprint's behavior.
# ─────────────────────────────────────────────────────────────────────────────

def _bool_filter(value: bool) -> str:
    return "true" if value else "false"


# ─────────────────────────────────────────────────────────────────────────────
# ARCHIVED-FILTER HELPER — FIX FOR "RECORDS EXIST IN THE DATABASE BUT DON'T
# SHOW UP IN THE ARCHIVE TAB" (Birth)
#
# Symptom: rows are visible in the Supabase table editor for
# birth_records, but GET /api/birth/archived returns an empty list even
# though those rows are clearly meant to be archived.
#
# Root cause: same class of bug already identified and fixed for
# marriage_records below (see ACTIVE_FILTER / the "ACTUAL ROOT CAUSE OF
# 'NO MARRIAGE DATA DISPLAYED'" comment in the Marriage section). The
# birth_records.is_archived column is defined as
#     is_archived BOOLEAN DEFAULT FALSE
# (nullable — no NOT NULL constraint). Any row whose is_archived was
# never explicitly set on insert (e.g. inserted directly via the
# Supabase table editor, imported from another system, or produced by an
# older insert path that predates this column) ends up with
# is_archived = NULL rather than TRUE or FALSE. In SQL, `NULL = true` and
# `NULL = false` are both unknown/false, so a plain
#     .eq("is_archived", _bool_filter(True))
# silently excludes those NULL rows — they match neither the active query
# (eq false) nor the archived query (eq true), and effectively disappear
# from the whole app even though they're sitting right there in the
# table.
#
# Unlike Marriage (where an unset flag is treated as "active"), every
# Birth upload explicitly sets is_archived = True at insert time (see
# upload_record() below) — newly added birth records always start in the
# Archive tab and are only moved to Active once explicitly matched/
# restored during a transaction. So for Birth, a row with no explicit
# is_archived value is far more consistent with "archived" (the default
# starting state) than with "active", and should surface in the Archive
# tab rather than nowhere at all.
#
# Fix: get_archived_records() below now matches is_archived = TRUE
# *or* is_archived IS NULL via an .or_() filter, so previously-invisible
# NULL rows now show up in the Archive tab. get_records() (the active
# list) is intentionally left untouched — it still requires an explicit
# is_archived = FALSE — so these rows don't end up duplicated in both
# tabs.
# ─────────────────────────────────────────────────────────────────────────────

BIRTH_ARCHIVED_FILTER = "is_archived.eq.true,is_archived.is.null"


# ─────────────────────────────────────────────────────────────────────────────
# PDF NORMALIZATION
#
# Symptom: the in-app PDF viewer shows Chrome's native
# "Failed to load PDF document." error.
#
# Root cause: `pdf_data` is coming back double base64-encoded for at
# least some rows. This happens when the underlying Postgres column is
# typed `bytea` (instead of the intended `text`). When a plain base64
# *string* is inserted into a `bytea` column without an explicit
# `\x`-hex/octal escape, Postgres's "escape" input format stores the
# literal ASCII bytes of that base64 string — not the decoded PDF bytes.
# Later, when PostgREST reads it back, you get one of two shapes:
#   1. A `\x...` hex string, whose decoded bytes are themselves an ASCII
#      base64 string (not %PDF) — because that's literally what got
#      stored.
#   2. A plain base64 string that, once decoded, yields ANOTHER base64
#      string instead of %PDF bytes (same root problem via a different
#      code path/migration).
#
# `_to_base64_pdf` and `_decode_pdf_data` below now detect this and peel
# off the extra layer of encoding automatically, so previously-corrupted
# rows self-heal on read without needing a manual data migration. New
# uploads (which store a single clean base64 string) pass straight
# through unaffected.
#
# NOTE: if the underlying `pdf_data` column is confirmed (via the
# Supabase table editor or `\d birth_records` in psql) to really be
# `bytea` rather than `text`, it's worth running the following one-time
# migration so future rows don't need the double-decode workaround at
# all — only do this after confirming the column type:
#   ALTER TABLE birth_records ALTER COLUMN pdf_data TYPE text USING encode(pdf_data, 'escape');
# ─────────────────────────────────────────────────────────────────────────────

def _looks_like_pdf(raw_bytes):
    return isinstance(raw_bytes, (bytes, bytearray)) and raw_bytes[:4] == b'%PDF'


def _to_base64_pdf(raw):
    """
    Normalize whatever Postgres/PostgREST handed us for pdf_data into a
    clean base64 string that decodes to real PDF bytes (starts with
    %PDF), regardless of the underlying storage quirk:
      - plain base64 text (the intended, correct format)
      - a data-URI-prefixed base64 string
      - Postgres bytea hex format, e.g. "\\x255044462d312e34..."
      - base64 that was accidentally base64-encoded TWICE (see module
        docstring above)
    """
    if raw is None:
        return None
    if not isinstance(raw, str):
        return None

    value = raw.strip()
    if not value:
        return None

    if value.startswith('data:application/pdf;base64,'):
        value = value[len('data:application/pdf;base64,'):].strip()
        if not value:
            return None

    # Postgres bytea hex format, e.g. "\x255044462d312e34..."
    if value.startswith('\\x'):
        hex_str = value[2:]
        try:
            raw_bytes = bytes.fromhex(hex_str)
        except ValueError:
            return None

        if _looks_like_pdf(raw_bytes):
            return base64.b64encode(raw_bytes).decode('utf-8')

        # The hex-decoded bytes aren't a PDF — they're probably the raw
        # ASCII bytes of a base64 string that got stuffed into a bytea
        # column verbatim. Try treating them as such.
        try:
            inner_b64 = raw_bytes.decode('ascii').strip()
            inner_bytes = base64.b64decode(inner_b64, validate=True)
            if _looks_like_pdf(inner_bytes):
                return inner_b64
        except Exception:
            pass

        # Give up gracefully — return the plain base64 re-encoding of
        # whatever we found, so downstream validation reports a clear
        # "invalid PDF" error instead of throwing here.
        return base64.b64encode(raw_bytes).decode('utf-8')

    # Plain text column holding base64 (the intended path) — but guard
    # against the case where it was accidentally double base64-encoded.
    try:
        decoded_once = base64.b64decode(value, validate=True)
    except Exception:
        # Not valid base64 at all — pass through, let downstream
        # validation raise a clear, user-facing error.
        return value

    if _looks_like_pdf(decoded_once):
        return value

    try:
        decoded_text = decoded_once.decode('ascii').strip()
        double_decoded = base64.b64decode(decoded_text, validate=True)
        if _looks_like_pdf(double_decoded):
            return decoded_text
    except Exception:
        pass

    return value


def _serialize_record(record: dict) -> dict:
    """
    Serialize a Supabase row — pdf_data should be plain base64 text (no
    more bytes/bytearray from a MySQL LONGBLOB), so this normalizes it
    (see _to_base64_pdf) and adds the data-URI prefix back on for the
    frontend.
    """
    if not record:
        return record
    record = dict(record)

    b64 = _to_base64_pdf(record.get('pdf_data'))
    record['pdf_data'] = f"data:application/pdf;base64,{b64}" if b64 else None

    return record


def _serialize_record_no_pdf(record: dict) -> dict:
    """Strip pdf_data to keep list responses light."""
    if not record:
        return record
    return {k: v for k, v in record.items() if k != 'pdf_data'}


def _decode_pdf_data(raw_pdf):
    """
    Shared helper for the /view and /download routes.
    Strips a data-URI prefix if present, base64-decodes, and validates that
    the result is actually a PDF. If the first decode doesn't look like a
    PDF, tries peeling off one more layer of base64 (see module docstring
    on the double-encoding bug) before giving up. Raises ValueError with a
    user-facing message on any failure instead of silently returning
    empty/garbage bytes (which is what was producing
    "Unable to display PDF: empty or invalid" / the browser's native
    "Failed to load PDF document" error in the frontend viewer).
    """
    if not raw_pdf:
        raise ValueError("No PDF data found for this record.")

    b64_str = raw_pdf[len('data:application/pdf;base64,'):] if raw_pdf.startswith('data:') else raw_pdf
    b64_str = b64_str.strip()

    if not b64_str:
        raise ValueError("No PDF data found for this record.")

    try:
        pdf_bytes = base64.b64decode(b64_str, validate=True)
    except Exception:
        raise ValueError("Stored PDF data is corrupted and could not be decoded.")

    if not _looks_like_pdf(pdf_bytes):
        # Possibly double base64-encoded — try one more decode pass.
        try:
            inner = pdf_bytes.decode('ascii').strip()
            pdf_bytes = base64.b64decode(inner, validate=True)
        except Exception:
            raise ValueError("Stored PDF data is invalid.")

        if not _looks_like_pdf(pdf_bytes):
            raise ValueError("Stored PDF data is invalid.")

    return pdf_bytes


def extract_birth_data_from_pdf(pdf_bytes):
    result = {
        "registry_no": None, "province": None, "city_municipality": None,
        "child_first_name": None, "child_middle_name": None, "child_last_name": None,
        "child_full_name": None, "sex": None,
        "birth_day": None, "birth_month": None, "birth_year": None, "birth_date": None,
        "place_of_birth": None, "type_of_birth": None, "multiple_birth_order": None,
        "birth_order": None, "weight_at_birth": None,
        "mother_first_name": None, "mother_middle_name": None, "mother_last_name": None,
        "mother_full_name": None, "mother_citizenship": None, "mother_religion": None,
        "mother_occupation": None, "mother_age": None, "mother_residence": None,
        "father_first_name": None, "father_middle_name": None, "father_last_name": None,
        "father_full_name": None, "father_citizenship": None, "father_religion": None,
        "father_occupation": None, "father_age": None, "father_residence": None,
        "extraction_status": "FAILED", "extraction_error": None
    }

    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        fields = reader.get_fields() or {}

        form_values = {}
        for key, meta in fields.items():
            value = None
            if isinstance(meta, dict):
                value = meta.get('/V')
            else:
                value = meta
            form_values[key] = _clean_text(value)

        result["province"]          = _clean_title(form_values.get("text_1hcvm"))
        result["city_municipality"] = _clean_title(form_values.get("text_3bbxl"))
        result["registry_no"]       = _clean_text(form_values.get("text_4isav"))

        result["child_first_name"]  = _clean_title(form_values.get("text_5be"))
        result["child_middle_name"] = _clean_title(form_values.get("text_6xmqw"))
        result["child_last_name"]   = _clean_title(form_values.get("text_8sonj"))
        result["sex"]               = _clean_upper(form_values.get("text_9ufvf"))

        result["birth_day"]   = _clean_text(form_values.get("text_10igxv"))
        result["birth_month"] = _clean_title(form_values.get("text_11ayig"))
        result["birth_year"]  = _clean_text(form_values.get("text_12ddjw"))
        result["birth_date"]  = _parse_birth_date(
            result["birth_day"], result["birth_month"], result["birth_year"]
        )

        clinic   = _clean_title(form_values.get("text_40teom"))
        city     = _clean_title(form_values.get("text_41whju"))
        province = _clean_title(form_values.get("text_42nogj"))
        result["place_of_birth"] = ", ".join([x for x in [clinic, city, province] if x]) or None

        result["type_of_birth"]        = _clean_title(form_values.get("text_13zosg"))
        result["multiple_birth_order"] = _clean_title(form_values.get("text_14ulve"))
        result["birth_order"]          = _clean_text(form_values.get("text_15uwue"))
        result["weight_at_birth"]      = _clean_text(form_values.get("text_16ymth"))

        result["mother_first_name"]  = _clean_title(form_values.get("text_17tfut"))
        result["mother_middle_name"] = _clean_title(form_values.get("text_19kupm"))
        result["mother_last_name"]   = _clean_title(form_values.get("text_20vqkl"))
        result["mother_citizenship"] = _clean_title(form_values.get("text_21nanb"))
        result["mother_religion"]    = _clean_title(form_values.get("text_22zatm"))
        result["mother_occupation"]  = _clean_title(form_values.get("text_26kizn"))
        result["mother_age"]         = _clean_int(form_values.get("text_28eoyi"))

        mother_brgy     = _clean_title(form_values.get("text_29trzr"))
        mother_city     = _clean_title(form_values.get("text_30iggg"))
        mother_province = _clean_title(form_values.get("text_31nwr"))
        mother_country  = _clean_title(form_values.get("text_32htdf"))
        result["mother_residence"] = ", ".join(
            [x for x in [mother_brgy, mother_city, mother_province, mother_country] if x]
        ) or None

        result["father_first_name"]  = _clean_title(form_values.get("text_33ytsv"))
        result["father_middle_name"] = _clean_title(form_values.get("text_34gjnu"))
        result["father_last_name"]   = _clean_title(form_values.get("text_35enqa"))
        result["father_citizenship"] = _clean_title(form_values.get("text_36ofon"))
        result["father_religion"]    = _clean_title(form_values.get("text_37olbs"))
        result["father_occupation"]  = _clean_title(form_values.get("text_38phix"))
        result["father_age"]         = _clean_int(form_values.get("text_39mnkf"))

        father_brgy     = _clean_title(form_values.get("text_40vrnc"))
        father_city     = _clean_title(form_values.get("text_41yrbj"))
        father_province = _clean_title(form_values.get("text_42lyhq"))
        father_country  = _clean_title(form_values.get("text_43zigj"))
        result["father_residence"] = ", ".join(
            [x for x in [father_brgy, father_city, father_province, father_country] if x]
        ) or None

        result["child_full_name"] = _build_full_name(
            result["child_first_name"], result["child_middle_name"], result["child_last_name"]
        )
        result["mother_full_name"] = _build_full_name(
            result["mother_first_name"], result["mother_middle_name"], result["mother_last_name"]
        )
        result["father_full_name"] = _build_full_name(
            result["father_first_name"], result["father_middle_name"], result["father_last_name"]
        )

        result["extraction_status"] = "SUCCESS"
        result["extraction_error"]  = None
        return result

    except Exception as e:
        result["extraction_status"] = "FAILED"
        result["extraction_error"]  = str(e)
        return result


# ─────────────────────────────────────────────────────────────────────────────
# HEALTH CHECK (Birth)
# ─────────────────────────────────────────────────────────────────────────────

@birth_bp.route('/api/birth/health', methods=['GET'])
def health_check():
    return jsonify({"status": "ok", "message": "Birth registration service is running"})


# NOTE: ensure_pdf_column_is_blob() and its call at import time are gone.
# The Supabase schema (birth_schema.sql) defines pdf_data as text up front,
# so there's no dynamic ALTER TABLE to run on every boot, and nothing here
# executes at import time anymore — that's what was crashing your app.py.
#
# IMPORTANT: If PDFs are still failing to decode after this fix, double
# check in the Supabase table editor (or `\d birth_records` in psql) that
# `pdf_data` is genuinely `text` and not `bytea`. The normalization below
# self-heals already-corrupted rows on read, but the column type should
# still be `text` going forward:
#   ALTER TABLE birth_records ALTER COLUMN pdf_data TYPE text USING encode(pdf_data, 'escape');
# (only run this if the column really is bytea — check first!)


# ─────────────────────────────────────────────────────────────────────────────
# ACTIVE RECORDS (Birth)
# ─────────────────────────────────────────────────────────────────────────────

LIST_FIELDS = (
    "id, file_name, uploaded_at, updated_at, "
    "child_first_name, child_middle_name, child_last_name, child_full_name, "
    "father_first_name, father_middle_name, father_last_name, father_full_name, "
    "mother_first_name, mother_middle_name, mother_last_name, mother_full_name, "
    "sex, birth_date, place_of_birth, extraction_status"
)

ARCHIVED_FIELDS = LIST_FIELDS.replace("updated_at", "archived_at")


@birth_bp.route('/api/birth/records', methods=['GET'])
def get_records():
    try:
        search = request.args.get('search', '').strip()

        q = supabase.table("birth_records").select(LIST_FIELDS)
        if search:
            like = f"%{search}%"
            q = q.or_(
                f"file_name.ilike.{like},child_full_name.ilike.{like},"
                f"father_full_name.ilike.{like},mother_full_name.ilike.{like}"
            )
        # FIX: was .eq("is_archived", False) — postgrest-py serializes a
        # Python bool via str(), sending "eq.False" (capitalized) which
        # PostgREST's boolean parser rejects, causing a 500 on every load.
        # See the _bool_filter() docstring above for the full explanation.
        #
        # NOTE: intentionally left as a strict eq(false) — see the
        # BIRTH_ARCHIVED_FILTER comment above for why rows with no
        # explicit is_archived value belong in the Archive tab (below),
        # not here.
        q = q.eq("is_archived", _bool_filter(False))
        rows = q.order("uploaded_at", desc=True).execute().data or []

        return jsonify([_serialize_record_no_pdf(r) for r in rows])

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# ARCHIVED RECORDS (Birth)
# ─────────────────────────────────────────────────────────────────────────────

@birth_bp.route('/api/birth/archived', methods=['GET'])
def get_archived_records():
    try:
        search = request.args.get('search', '').strip()

        q = supabase.table("birth_records").select(ARCHIVED_FIELDS)
        if search:
            like = f"%{search}%"
            q = q.or_(
                f"file_name.ilike.{like},child_full_name.ilike.{like},"
                f"father_full_name.ilike.{like},mother_full_name.ilike.{like}"
            )
        # FIX: was .eq("is_archived", _bool_filter(True)), which excludes
        # rows where is_archived is NULL (never explicitly set — e.g. a
        # row added directly via the Supabase table editor, or left over
        # from an older insert path). NULL never equals true OR false in
        # SQL, so those rows were invisible in BOTH this list and the
        # active list above, even though they were sitting right there in
        # the birth_records table. See the BIRTH_ARCHIVED_FILTER comment
        # above for the full explanation of why NULL is treated as
        # "archived" here (mirroring Birth's own upload behavior, where
        # every new record starts out archived).
        q = q.or_(BIRTH_ARCHIVED_FILTER)
        rows = q.order("archived_at", desc=True).execute().data or []

        return jsonify([_serialize_record_no_pdf(r) for r in rows])

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# UPLOAD + EXTRACT PDF (Birth)
# ─────────────────────────────────────────────────────────────────────────────

@birth_bp.route('/api/birth/records', methods=['POST'])
def upload_record():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    if not file.filename.lower().endswith('.pdf'):
        return jsonify({"error": "Only PDF files are allowed"}), 400

    try:
        pdf_bytes = file.read()

        if not pdf_bytes.startswith(b'%PDF'):
            return jsonify({"error": "Uploaded file does not appear to be a valid PDF."}), 400

        file_name = os.path.splitext(secure_filename(file.filename))[0]

        file_size_bytes = len(pdf_bytes)
        file_size_kb    = round(file_size_bytes / 1024, 2)
        file_size_mb    = round(file_size_bytes / (1024 * 1024), 2)

        if file_size_mb > 20:
            return jsonify({"error": "File exceeds the 20 MB limit."}), 400

        extracted = extract_birth_data_from_pdf(pdf_bytes)

        father_first_name  = _clean_title(request.form.get('father_first_name'))  or extracted["father_first_name"]
        father_middle_name = _clean_title(request.form.get('father_middle_name')) or extracted["father_middle_name"]
        father_last_name   = _clean_title(request.form.get('father_last_name'))   or extracted["father_last_name"]

        mother_first_name  = _clean_title(request.form.get('mother_first_name'))  or extracted["mother_first_name"]
        mother_middle_name = _clean_title(request.form.get('mother_middle_name')) or extracted["mother_middle_name"]
        mother_last_name   = _clean_title(request.form.get('mother_last_name'))   or extracted["mother_last_name"]

        extracted["father_first_name"]  = father_first_name
        extracted["father_middle_name"] = father_middle_name
        extracted["father_last_name"]   = father_last_name
        extracted["father_full_name"]   = _build_full_name(father_first_name, father_middle_name, father_last_name)
        extracted["mother_first_name"]  = mother_first_name
        extracted["mother_middle_name"] = mother_middle_name
        extracted["mother_last_name"]   = mother_last_name
        extracted["mother_full_name"]   = _build_full_name(mother_first_name, mother_middle_name, mother_last_name)

        now = datetime.now().isoformat()

        # Store a single, clean base64 string. Do NOT let this go into a
        # bytea column without proper hex/`\x` handling on the DB side —
        # see the note above LIST_FIELDS for how to check/fix the column
        # type if PDFs are still failing to load after this patch.
        pdf_b64 = base64.b64encode(pdf_bytes).decode('utf-8')

        insert_payload = {
            "file_name": file_name,
            "pdf_data": pdf_b64,
            "registry_no": extracted["registry_no"], "province": extracted["province"],
            "city_municipality": extracted["city_municipality"],
            "child_first_name": extracted["child_first_name"], "child_middle_name": extracted["child_middle_name"],
            "child_last_name": extracted["child_last_name"], "child_full_name": extracted["child_full_name"],
            "sex": extracted["sex"],
            "birth_day": extracted["birth_day"], "birth_month": extracted["birth_month"],
            "birth_year": extracted["birth_year"],
            "birth_date": extracted["birth_date"].isoformat() if extracted["birth_date"] else None,
            "place_of_birth": extracted["place_of_birth"], "type_of_birth": extracted["type_of_birth"],
            "multiple_birth_order": extracted["multiple_birth_order"], "birth_order": extracted["birth_order"],
            "weight_at_birth": extracted["weight_at_birth"],
            "mother_first_name": extracted["mother_first_name"], "mother_middle_name": extracted["mother_middle_name"],
            "mother_last_name": extracted["mother_last_name"], "mother_full_name": extracted["mother_full_name"],
            "mother_citizenship": extracted["mother_citizenship"], "mother_religion": extracted["mother_religion"],
            "mother_occupation": extracted["mother_occupation"], "mother_age": extracted["mother_age"],
            "mother_residence": extracted["mother_residence"],
            "father_first_name": extracted["father_first_name"], "father_middle_name": extracted["father_middle_name"],
            "father_last_name": extracted["father_last_name"], "father_full_name": extracted["father_full_name"],
            "father_citizenship": extracted["father_citizenship"], "father_religion": extracted["father_religion"],
            "father_occupation": extracted["father_occupation"], "father_age": extracted["father_age"],
            "father_residence": extracted["father_residence"],
            "extraction_status": extracted["extraction_status"], "extraction_error": extracted["extraction_error"],
            "uploaded_at": now, "is_archived": True, "archived_at": now,
            "file_size_bytes": file_size_bytes, "file_size_kb": file_size_kb, "file_size_mb": file_size_mb,
        }

        try:
            resp = supabase.table("birth_records").insert(insert_payload).execute()
        except APIError as e:
            # Same duplicate-detection pattern used in marriage.py: catch the
            # unique-constraint violation on file_name instead of MySQL's
            # IntegrityError, and check the constraint name in the message.
            if "file_name" in str(e) or "duplicate" in str(e).lower():
                return jsonify({"error": f"'{file_name}' already exists."}), 409
            raise

        record_id = resp.data[0]["id"] if resp.data else None

        # NOTE: No notification on upload — notifications fire only when a
        # matching record is found and a transaction is completed (ACTIVE/positive).

        record_action(
            "UPLOAD",
            f"Uploaded birth record to archive: '{file_name}'",
            username=get_user(),
            meta={
                "file_name": file_name,
                "record_id": record_id,
                "child_full_name":   extracted["child_full_name"],
                "mother_full_name":  extracted["mother_full_name"],
                "father_full_name":  extracted["father_full_name"],
                "extraction_status": extracted["extraction_status"]
            },
            ip=request.remote_addr
        )

        return jsonify({
            "message": "Record uploaded to archive successfully",
            "id": record_id,
            "file_name": file_name,
            "child_first_name":  extracted["child_first_name"],
            "child_middle_name": extracted["child_middle_name"],
            "child_last_name":   extracted["child_last_name"],
            "child_full_name":   extracted["child_full_name"],
            "father_first_name":  extracted["father_first_name"],
            "father_middle_name": extracted["father_middle_name"],
            "father_last_name":   extracted["father_last_name"],
            "father_full_name":   extracted["father_full_name"],
            "mother_first_name":  extracted["mother_first_name"],
            "mother_middle_name": extracted["mother_middle_name"],
            "mother_last_name":   extracted["mother_last_name"],
            "mother_full_name":   extracted["mother_full_name"],
            "extraction_status":  extracted["extraction_status"],
            "archived_at": now,
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# UPDATE RELATIVES (Birth)
# ─────────────────────────────────────────────────────────────────────────────

@birth_bp.route('/api/birth/records/<int:record_id>/relatives', methods=['PATCH'])
def update_relatives(record_id):
    try:
        data = request.get_json() or {}

        father_first_name  = _clean_title(data.get('father_first_name'))
        father_middle_name = _clean_title(data.get('father_middle_name'))
        father_last_name   = _clean_title(data.get('father_last_name'))
        mother_first_name  = _clean_title(data.get('mother_first_name'))
        mother_middle_name = _clean_title(data.get('mother_middle_name'))
        mother_last_name   = _clean_title(data.get('mother_last_name'))

        father_full_name = _build_full_name(father_first_name, father_middle_name, father_last_name)
        mother_full_name = _build_full_name(mother_first_name, mother_middle_name, mother_last_name)

        existing = supabase.table("birth_records").select("id, file_name").eq("id", record_id).limit(1).execute().data
        if not existing:
            return jsonify({"error": "Record not found"}), 404
        record = existing[0]

        supabase.table("birth_records").update({
            "father_first_name": father_first_name, "father_middle_name": father_middle_name,
            "father_last_name": father_last_name, "father_full_name": father_full_name,
            "mother_first_name": mother_first_name, "mother_middle_name": mother_middle_name,
            "mother_last_name": mother_last_name, "mother_full_name": mother_full_name,
            "updated_at": datetime.now().isoformat(),
        }).eq("id", record_id).execute()

        record_action(
            "UPDATE_RELATIVES",
            f"Updated relatives for birth record: '{record['file_name']}'",
            username=get_user(),
            meta={
                "record_id": record_id,
                "file_name": record["file_name"],
                "father_full_name": father_full_name,
                "mother_full_name": mother_full_name
            },
            ip=request.remote_addr
        )

        return jsonify({
            "message": "Relatives updated successfully",
            "record_id": record_id,
            "father_first_name": father_first_name, "father_middle_name": father_middle_name,
            "father_last_name":  father_last_name,  "father_full_name":   father_full_name,
            "mother_first_name": mother_first_name, "mother_middle_name": mother_middle_name,
            "mother_last_name":  mother_last_name,  "mother_full_name":   mother_full_name,
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# COMPLETE TRANSACTION (Birth)
# ─────────────────────────────────────────────────────────────────────────────

@birth_bp.route('/api/birth/records/complete', methods=['POST'])
def complete_transaction():
    try:
        data = request.get_json() or {}

        search_operator = data.get('searchOperator', '').strip()
        name_parts  = search_operator.split()
        first_name  = name_parts[0] if name_parts else ''
        last_name   = ' '.join(name_parts[1:]) if len(name_parts) > 1 else ''

        record_status     = data.get('recordStatus', 'NOT_FOUND')
        record_id         = data.get('recordId')
        payment_method    = data.get('paymentMethod', 'cash')
        payment_reference = data.get('paymentReference', '')
        payment_amount    = float(data.get('paymentAmount', 75))
        document_issued   = data.get('documentIssued', '')
        payment_status    = 'positive' if record_status == 'ACTIVE' else 'negative'
        payment_date      = datetime.now()
        processed_by      = get_user()

        resp = supabase.table("birth_payments").insert({
            "first_name": first_name, "last_name": last_name,
            "payment_status": payment_status, "amount": payment_amount,
            "payment_method": payment_method, "payment_reference": payment_reference or None,
            "birth_record_id": record_id, "document_issued": document_issued or None,
            "payment_date": payment_date.isoformat(), "processed_by": processed_by,
        }).execute()
        payment_id = resp.data[0]["id"] if resp.data else None

        # ── NOTIFICATION: only fire when record was FOUND in the database
        # AND that record was originally submitted through the Online
        # Request system (see _matches_online_birth_request() /
        # CIVIL_REGISTRY_REQUEST_TABLE at the top of this file). Processing
        # an existing birth record directly from the Birth data — with no
        # matching online request — no longer sends any notification.
        #
        # CLEANED UP: dropped the stray `connection` positional arg and the
        # `notif_type=` kwarg — push_notification() no longer needs a DB
        # handle, and record_type is passed the normal way. ──
        if payment_status == 'positive' and _matches_online_birth_request(
            first_name, last_name, control_no=payment_reference or None
        ):
            subject = search_operator or f"{first_name} {last_name}".strip() or "Unknown"
            push_notification(
                record_type="birth",
                record_id=record_id,
                control_no=payment_reference or None,
                title="Birth Certificate Issued",
                message=f"Birth certificate issued for '{subject}'",
            )

        record_action(
            "TRANSACTION_COMPLETE",
            f"Transaction completed for '{search_operator}' — {payment_status.upper()}",
            username=processed_by,
            meta={
                "payment_id": payment_id,
                "record_status": record_status,
                "birth_record_id": record_id,
                "payment_amount": payment_amount,
                "payment_method": payment_method,
                "payment_reference": payment_reference,
            },
            ip=request.remote_addr
        )

        return jsonify({
            "message": "Transaction completed successfully",
            "payment_id": payment_id,
            "first_name": first_name,
            "last_name": last_name,
            "payment_status": payment_status,
            "payment_date": payment_date.isoformat(),
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# VIEW SINGLE RECORD (Birth)
# ─────────────────────────────────────────────────────────────────────────────

@birth_bp.route('/api/birth/records/<int:record_id>', methods=['GET'])
def get_record(record_id):
    try:
        rows = supabase.table("birth_records").select("*").eq("id", record_id).limit(1).execute().data
        if not rows:
            return jsonify({"error": "Record not found"}), 404
        record = rows[0]

        record_action(
            "VIEW",
            f"Viewed birth record: '{record['file_name']}'",
            username=get_user(),
            meta={"record_id": record_id, "file_name": record['file_name']},
            ip=request.remote_addr
        )

        if record.get('pdf_data') is None:
            return jsonify({"error": "No PDF data found for this record."}), 404

        return jsonify(_serialize_record(record))

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# INLINE VIEW (for in-app PDF preview — does NOT force a download) (Birth)
#
# This is the fix for the "Unable to display PDF: The selected PDF is empty
# or invalid" modal. That error was happening because the frontend preview
# was almost certainly either:
#   (a) reading pdf_data off a row object that came from the LIST or SEARCH
#       endpoints (get_records / get_archived_records / verify_record),
#       which never include pdf_data at all — it's stripped by
#       _serialize_record_no_pdf() to keep list payloads light, or
#   (b) pointing its <iframe>/<embed> preview at /download, which sends
#       Content-Disposition: attachment and forces a download instead of
#       an inline render in most browsers, or
#   (c) the pdf_data was double base64-encoded (see the big comment block
#       above _to_base64_pdf) — now self-corrected on read.
#
# Point the preview modal at GET /api/birth/records/<id>/view — it serves
# the decoded PDF bytes with Content-Disposition: inline so it renders
# directly, and it now validates the decoded bytes and returns a clear
# JSON error (instead of an empty/garbage PDF blob) if pdf_data is
# missing or corrupted.
# ─────────────────────────────────────────────────────────────────────────────

@birth_bp.route('/api/birth/records/<int:record_id>/view', methods=['GET'])
def view_record_pdf(record_id):
    try:
        rows = supabase.table("birth_records").select(
            "file_name, pdf_data"
        ).eq("id", record_id).limit(1).execute().data
        if not rows:
            return jsonify({"error": "Record not found"}), 404
        record = rows[0]

        try:
            pdf_bytes = _decode_pdf_data(record.get('pdf_data'))
        except ValueError as ve:
            status = 404 if "No PDF data" in str(ve) else 500
            return jsonify({"error": str(ve)}), status

        record_action(
            "VIEW",
            f"Previewed birth record PDF: '{record['file_name']}'",
            username=get_user(),
            meta={"record_id": record_id, "file_name": record['file_name']},
            ip=request.remote_addr
        )

        pdf_io = io.BytesIO(pdf_bytes)
        pdf_io.seek(0)
        return send_file(
            pdf_io,
            mimetype='application/pdf',
            as_attachment=False,             # <-- inline, not a forced download
            download_name=f"{record['file_name']}.pdf",
            max_age=0,
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@birth_bp.route('/api/birth/records/<int:record_id>/download', methods=['GET'])
def download_record(record_id):
    try:
        rows = supabase.table("birth_records").select("file_name, pdf_data").eq("id", record_id).limit(1).execute().data
        if not rows:
            return jsonify({"error": "Record not found"}), 404
        record = rows[0]

        record_action(
            "DOWNLOAD",
            f"Downloaded birth record: '{record['file_name']}'",
            username=get_user(),
            meta={"record_id": record_id, "file_name": record['file_name']},
            ip=request.remote_addr
        )

        try:
            pdf_bytes = _decode_pdf_data(record.get('pdf_data'))
        except ValueError as ve:
            status = 404 if "No PDF data" in str(ve) else 500
            return jsonify({"error": str(ve)}), status

        pdf_io = io.BytesIO(pdf_bytes)
        pdf_io.seek(0)
        return send_file(
            pdf_io,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"{record['file_name']}.pdf"
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# ARCHIVE / RESTORE / DELETE (Birth)
# ─────────────────────────────────────────────────────────────────────────────

@birth_bp.route('/api/birth/records/<int:record_id>/archive', methods=['POST'])
def archive_record(record_id):
    try:
        rows = supabase.table("birth_records").select("id, file_name, is_archived").eq("id", record_id).limit(1).execute().data
        if not rows:
            return jsonify({"error": "Record not found"}), 404
        record = rows[0]

        if record['is_archived']:
            return jsonify({"error": "Record is already archived"}), 400

        # NOTE: this is an UPDATE body, not a filter — it goes through
        # normal JSON serialization (True -> `true`), so it was never
        # affected by the .eq() bool bug above. Left as a Python bool
        # intentionally.
        supabase.table("birth_records").update(
            {"is_archived": True, "archived_at": datetime.now().isoformat()}
        ).eq("id", record_id).execute()

        record_action(
            "ARCHIVE",
            f"Archived birth record: '{record['file_name']}'",
            username=get_user(),
            meta={"record_id": record_id, "file_name": record['file_name']},
            ip=request.remote_addr
        )

        return jsonify({"message": "Record archived successfully"})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@birth_bp.route('/api/birth/records/<int:record_id>/restore', methods=['POST'])
def restore_record(record_id):
    try:
        rows = supabase.table("birth_records").select("id, file_name, is_archived").eq("id", record_id).limit(1).execute().data
        if not rows:
            return jsonify({"error": "Record not found"}), 404
        record = rows[0]

        if not record['is_archived']:
            return jsonify({"error": "Record is not archived"}), 400

        # Same note as archive_record() above — UPDATE body, unaffected
        # by the .eq() bool bug.
        supabase.table("birth_records").update(
            {"is_archived": False, "archived_at": None}
        ).eq("id", record_id).execute()

        record_action(
            "RESTORE",
            f"Restored birth record: '{record['file_name']}'",
            username=get_user(),
            meta={"record_id": record_id, "file_name": record['file_name']},
            ip=request.remote_addr
        )

        return jsonify({"message": "Record restored successfully"})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@birth_bp.route('/api/birth/records/<int:record_id>', methods=['DELETE'])
def delete_record(record_id):
    try:
        rows = supabase.table("birth_records").select("file_name").eq("id", record_id).limit(1).execute().data
        if not rows:
            return jsonify({"error": "Record not found"}), 404
        file_name = rows[0]['file_name']

        supabase.table("birth_records").delete().eq("id", record_id).execute()

        record_action(
            "DELETE",
            f"Permanently deleted birth record: '{file_name}'",
            username=get_user(),
            meta={"record_id": record_id, "file_name": file_name},
            ip=request.remote_addr
        )

        return jsonify({"message": "Record deleted successfully"})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# VERIFY RECORD (Birth)
# ─────────────────────────────────────────────────────────────────────────────

@birth_bp.route('/api/birth/verify', methods=['POST'])
def verify_record():
    try:
        data = request.get_json() or {}
        first_name = data.get('firstName', '').strip()
        last_name  = data.get('lastName', '').strip()

        if not first_name or not last_name:
            return jsonify({"error": "First name and last name are required"}), 400

        rows = supabase.table("birth_records").select(
            "id, file_name, uploaded_at, "
            "child_first_name, child_middle_name, child_last_name, child_full_name, "
            "sex, birth_date, place_of_birth, "
            "father_first_name, father_middle_name, father_last_name, father_full_name, "
            "mother_first_name, mother_middle_name, mother_last_name, mother_full_name"
        ).ilike("child_first_name", first_name).ilike("child_last_name", last_name).eq(
            # FIX: same boolean-serialization bug as get_records() above.
            "is_archived", _bool_filter(False)
        ).order("uploaded_at", desc=True).limit(1).execute().data

        record = rows[0] if rows else None

        if record:
            record_action(
                "SEARCH",
                f"Birth record verify — FOUND: '{first_name} {last_name}'",
                username=get_user(),
                meta={"search": f"{first_name} {last_name}", "result": "ACTIVE"},
                ip=request.remote_addr
            )
            return jsonify({
                "found": True,
                "status": "ACTIVE",
                "record": _serialize_record_no_pdf(record)
            })

        record_action(
            "SEARCH",
            f"Birth record verify — NOT FOUND: '{first_name} {last_name}'",
            username=get_user(),
            meta={"search": f"{first_name} {last_name}", "result": "NOT_FOUND"},
            ip=request.remote_addr
        )
        return jsonify({
            "found": False,
            "status": "NOT_FOUND",
            "message": "No matching birth record found"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# PAYMENT PROCESSING (Birth)
# ─────────────────────────────────────────────────────────────────────────────

@birth_bp.route('/api/birth/payments', methods=['POST'])
def create_payment():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON body provided"}), 400

        first_name     = data.get('first_name', '').strip()
        last_name      = data.get('last_name', '').strip()
        payment_status = data.get('payment_status', '').strip().lower()

        if not first_name:
            return jsonify({"error": "first_name is required"}), 400
        if not last_name:
            return jsonify({"error": "last_name is required"}), 400
        if payment_status not in ('positive', 'negative'):
            return jsonify({"error": "payment_status must be 'positive' or 'negative'"}), 400

        amount            = float(data.get('amount', 75.00))
        payment_method    = data.get('payment_method', 'cash').strip()
        payment_reference = data.get('payment_reference', '').strip() or None
        birth_record_id   = data.get('birth_record_id')
        document_issued   = data.get('document_issued', '').strip() or None
        payment_date      = datetime.now()
        processed_by      = get_user()

        if payment_status == 'positive' and birth_record_id is not None:
            exists = supabase.table("birth_records").select("id").eq("id", birth_record_id).limit(1).execute().data
            if not exists:
                return jsonify({"error": f"birth_record_id {birth_record_id} not found"}), 404

        resp = supabase.table("birth_payments").insert({
            "first_name": first_name, "last_name": last_name,
            "payment_status": payment_status, "amount": amount,
            "payment_method": payment_method, "payment_reference": payment_reference,
            "birth_record_id": birth_record_id, "document_issued": document_issued,
            "payment_date": payment_date.isoformat(), "processed_by": processed_by,
        }).execute()
        payment_id = resp.data[0]["id"] if resp.data else None

        # ── NOTIFICATION: only fire when a matching record exists (positive)
        # AND that record was originally submitted through the Online
        # Request system (see _matches_online_birth_request() /
        # CIVIL_REGISTRY_REQUEST_TABLE at the top of this file). Processing
        # an existing birth record directly from the Birth data — with no
        # matching online request — no longer sends any notification. ──
        if payment_status == 'positive' and _matches_online_birth_request(
            first_name, last_name, control_no=payment_reference
        ):
            push_notification(
                record_type="birth",
                record_id=birth_record_id,
                control_no=payment_reference,
                title="Birth Certificate Issued",
                message=f"Birth certificate issued for '{first_name} {last_name}'",
            )

        record_action(
            "PAYMENT",
            f"Payment recorded for '{first_name} {last_name}' — status: {payment_status.upper()}",
            username=processed_by,
            meta={
                "payment_id": payment_id,
                "first_name": first_name,
                "last_name": last_name,
                "payment_status": payment_status,
                "amount": amount,
                "payment_reference": payment_reference,
                "birth_record_id": birth_record_id,
            },
            ip=request.remote_addr
        )

        return jsonify({
            "message": "Payment recorded successfully",
            "payment_id": payment_id,
            "first_name": first_name,
            "last_name": last_name,
            "payment_status": payment_status,
            "amount": amount,
            "payment_method": payment_method,
            "payment_reference": payment_reference,
            "birth_record_id": birth_record_id,
            "document_issued": document_issued,
            "payment_date": payment_date.isoformat(),
            "processed_by": processed_by,
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@birth_bp.route('/api/birth/payments', methods=['GET'])
def get_payments():
    try:
        search = request.args.get('search', '').strip()
        status = request.args.get('status', '').strip().lower()
        limit  = min(int(request.args.get('limit', 100)), 500)
        offset = int(request.args.get('offset', 0))

        q = supabase.table("birth_payments").select(
            "id, first_name, last_name, payment_status, amount, "
            "payment_method, payment_reference, birth_record_id, "
            "document_issued, payment_date, processed_by",
            count="exact"
        )
        if search:
            like = f"%{search}%"
            q = q.or_(f"first_name.ilike.{like},last_name.ilike.{like}")
        if status in ('positive', 'negative'):
            q = q.eq("payment_status", status)

        resp = q.order("payment_date", desc=True).range(offset, offset + limit - 1).execute()
        payments = resp.data or []
        total    = resp.count or 0

        return jsonify({"total": total, "payments": payments})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@birth_bp.route('/api/birth/payments/<int:payment_id>', methods=['GET'])
def get_payment(payment_id):
    try:
        rows = supabase.table("birth_payments").select("*").eq("id", payment_id).limit(1).execute().data
        if not rows:
            return jsonify({"error": "Payment record not found"}), 404
        payment = rows[0]

        if payment.get("birth_record_id"):
            rec = supabase.table("birth_records").select("file_name").eq(
                "id", payment["birth_record_id"]
            ).limit(1).execute().data
            payment["birth_record_file"] = rec[0]["file_name"] if rec else None
        else:
            payment["birth_record_file"] = None

        return jsonify(payment)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# #############################################################################
# ##########################  MARRIAGE  BACKEND  #############################
# (originally routes/marriage.py)
# #############################################################################

marriage_bp = Blueprint("marriage", __name__, url_prefix="/api/marriage")

# =============================================================================
# UPLOAD DIRECTORIES  (unchanged — filesystem, not MySQL)
# =============================================================================

_THIS_FILE  = os.path.abspath(__file__)
_ROUTES_DIR = os.path.dirname(_THIS_FILE)

_BACKEND_ROOT = (
    os.path.dirname(_ROUTES_DIR)
    if os.path.basename(_ROUTES_DIR).lower() in ("routes", "blueprints", "views", "api")
    else _ROUTES_DIR
)

UPLOAD_DIR         = os.path.join(_BACKEND_ROOT, "uploads", "marriage")
ARCHIVE_UPLOAD_DIR = os.path.join(_BACKEND_ROOT, "uploads", "marriage_archive")
os.makedirs(UPLOAD_DIR,         exist_ok=True)
os.makedirs(ARCHIVE_UPLOAD_DIR, exist_ok=True)

# NOTE: renamed from ALLOWED_EXTENSIONS / MAX_FILE_SIZE_MB / MAX_FILE_SIZE_BYTES
# to MARRIAGE_* to avoid clashing with Death's identically-named
# module-level constants now that both live in this one file.
MARRIAGE_ALLOWED_EXTENSIONS  = {"pdf"}
MARRIAGE_MAX_FILE_SIZE_MB    = 20
MARRIAGE_MAX_FILE_SIZE_BYTES = MARRIAGE_MAX_FILE_SIZE_MB * 1024 * 1024

# Columns returned for record listings (everything except nothing excluded here —
# marriage_records has no blob column, unlike death_records' pdf_file)
#
# NOTE: renamed from RECORD_SELECT_COLS to MARRIAGE_RECORD_SELECT_COLS to
# avoid clashing with Death's identically-named module-level constant.
MARRIAGE_RECORD_SELECT_COLS = "*"


def marriage_allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in MARRIAGE_ALLOWED_EXTENSIONS


# =============================================================================
# BOOLEAN FILTER HELPER
#
# postgrest-py's QueryRequestBuilder.eq() serializes whatever value you pass
# it with str(value). Passed a Python bool, str(True) / str(False) produce
# "True" / "False" (capitalized). PostgREST's boolean input parser only
# accepts lowercase true/false, so .eq("is_archived", False) was sent on the
# wire as `is_archived=eq.False`, which PostgREST rejects.
#
# NOTE: this used to be its own `_bool_filter()` definition here, byte-for-
# byte identical to the one in birth.py. Now that both blueprints share this
# module, it is defined once in the Birth section above and reused here —
# behavior is unchanged.
# =============================================================================


# =============================================================================
# ACTUAL ROOT CAUSE OF "NO MARRIAGE DATA DISPLAYED"
#
# Rows added directly via the Supabase table editor (or any insert that
# didn't explicitly set is_archived) end up with is_archived = NULL, not
# false. In SQL, `NULL = false` and `NULL = true` are BOTH false/unknown —
# a NULL row matches neither `.eq("is_archived", "false")` nor
# `.eq("is_archived", "true")`. That's why records existed in the database
# (visible in the Supabase table editor) but showed up in NEITHER the
# "New Transaction" search NOR the "Archive" tab.
#
# Fix: treat is_archived IS NULL the same as is_archived = false (i.e. an
# "un-flagged" record defaults to ACTIVE, not archived). We do this with an
# .or_() filter instead of a plain .eq() for the active-records query.
# =============================================================================

ACTIVE_FILTER = "is_archived.eq.false,is_archived.is.null"

# =============================================================================
# ARCHIVE-FILTER FIX — mirrors the identical fix already applied to Birth's
# get_archived_records() (see BIRTH_ARCHIVED_FILTER / the "RECORDS EXIST IN
# THE DATABASE BUT DON'T SHOW UP IN THE ARCHIVE TAB" comment in the Birth
# section).
#
# Symptom: rows are visible in the Supabase table editor for
# marriage_records (e.g. rows bulk-imported directly via SQL/table editor),
# but GET /api/marriage/archived returned them as empty / errored, even
# though those rows are clearly meant to be archived certificates.
#
# Root cause: marriage_records.is_archived is nullable. A row whose
# is_archived was never explicitly set (imported directly, or from an
# older insert path) is NULL — and a plain
#     .eq("is_archived", _bool_filter(True))
# never matches NULL, so those rows were invisible in the Archive tab.
#
# NOTE: because ACTIVE_FILTER above intentionally treats a NULL row as
# "active" (unlike Birth, where NULL defaults to "archived"), if we simply
# OR'd NULL into the archived list too, an un-flagged row would appear in
# BOTH the Active search AND the Archive tab at once. To keep the two tabs
# mutually exclusive (exactly like Birth), get_records() below has been
# tightened to require an EXPLICIT is_archived = false, and this filter
# now owns every row that is TRUE or NULL — i.e. "default to archived
# unless explicitly marked active" for records with no flag set at all.
# =============================================================================

MARRIAGE_ARCHIVED_FILTER = "is_archived.eq.true,is_archived.is.null"


# =============================================================================
# FILENAME NORMALISATION (Marriage)
# =============================================================================

def normalize_filename(filename: str) -> str:
    filename = (filename or "").strip()
    if not filename:
        return "unnamed.pdf"
    stem, dot, ext = filename.rpartition(".")
    if not dot:
        stem = filename
        ext  = "pdf"
    stem = re.sub(r"[^\w]", "_", stem)
    stem = re.sub(r"_+", "_", stem)
    stem = stem.strip("_")
    if not stem:
        stem = "unnamed"
    return f"{stem}.{ext.lower()}"


# =============================================================================
# HASH HELPER (Marriage)
# =============================================================================

def compute_file_hash(file_obj, algorithm="sha256", chunk_size=8192):
    h = hashlib.new(algorithm)
    file_obj.seek(0)
    while True:
        chunk = file_obj.read(chunk_size)
        if not chunk:
            break
        h.update(chunk)
    file_obj.seek(0)
    return h.hexdigest()


# =============================================================================
# PDF <-> BASE64 HELPERS (defensive against double-encoding) (Marriage)
# =============================================================================

def _bytes_look_like_pdf(b: bytes) -> bool:
    if not isinstance(b, (bytes, bytearray)):
        return False
    return b.lstrip()[:5] == b"%PDF-"


def file_to_base64_pdf(path: str):
    """Read a PDF from disk and return a clean base64 string.

    Normal case: the file on disk is genuine PDF bytes -> base64-encode once.
    Defensive case: the file on disk is itself a base64 (or double
    base64-encoded) string rather than real PDF bytes -> peel off up to two
    layers until we find real PDF bytes, then re-encode cleanly.
    Returns None if the file can't be read at all.
    """
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except Exception:
        return None

    if _bytes_look_like_pdf(raw):
        return base64.b64encode(raw).decode("ascii")

    candidate = raw
    for _ in range(2):
        try:
            decoded = base64.b64decode(candidate, validate=False)
        except Exception:
            break
        if _bytes_look_like_pdf(decoded):
            return base64.b64encode(decoded).decode("ascii")
        candidate = decoded

    # Couldn't recover a valid PDF — hand back what we have as base64 so the
    # frontend can still attempt its own recovery/validation and show a
    # friendly "Unable to display PDF" message rather than us guessing wrong.
    return base64.b64encode(raw).decode("ascii")


def file_is_valid_pdf(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            head = f.read(1024)
    except Exception:
        return False
    if _bytes_look_like_pdf(head):
        return True
    # could be base64 text on disk — quick check without fully decoding
    try:
        decoded_head = base64.b64decode(head + b"===", validate=False)
        return _bytes_look_like_pdf(decoded_head)
    except Exception:
        return False


# =============================================================================
# TABLE SETUP — now a no-op. Schema lives in marriage_schema.sql,
# run once in the Supabase SQL Editor. (Marriage)
# =============================================================================

def ensure_marriage_records_table():
    """No-op: marriage_records is created via Supabase SQL Editor, not here."""
    pass


def ensure_marriage_transactions_table():
    """No-op: marriage_transactions is created via Supabase SQL Editor, not here."""
    pass


def init_marriage_db():
    print("[MARRIAGE] Using Supabase tables 'marriage_records' / 'marriage_transactions'")


init_marriage_db()


# =============================================================================
# DUPLICATE-CHECK HELPER (Marriage)
# =============================================================================

def check_duplicate(original_file_name, file_hash):
    res = supabase.table("marriage_records") \
        .select("id, original_file_name, is_archived") \
        .eq("original_file_name", original_file_name) \
        .limit(1).execute()
    if res.data:
        row = res.data[0]
        location = "archive" if row["is_archived"] else "registry"
        return f'A file named "{original_file_name}" already exists in the {location}.'

    if file_hash:
        res = supabase.table("marriage_records") \
            .select("id, original_file_name, is_archived") \
            .eq("file_hash", file_hash) \
            .limit(1).execute()
        if res.data:
            row = res.data[0]
            location = "archive" if row["is_archived"] else "registry"
            existing = row["original_file_name"] or f"record #{row['id']}"
            return f'This file\'s content already exists in the {location} as "{existing}".'

    return None


# =============================================================================
# MISC HELPERS  (unchanged) (Marriage)
# =============================================================================

def clean(v):
    if v is None:
        return None
    v = str(v).strip()
    return v if v else None

def split_name(full_name):
    full_name = clean(full_name)
    if not full_name:
        return None, None, None
    parts = full_name.split()
    if len(parts) == 1:
        return parts[0], None, None
    if len(parts) == 2:
        return parts[0], None, parts[1]
    return parts[0], " ".join(parts[1:-1]), parts[-1]

def extract_pdf_fields(pdf_path):
    reader = PdfReader(pdf_path)
    fields = reader.get_fields() or {}
    values = {}
    for key, field in fields.items():
        try:
            val = field.get("/V")
        except Exception:
            val = None
        values[key] = val.strip() if isinstance(val, str) else val
    return values

def map_marriage_pdf_fields(fields):
    groom_full = clean(fields.get("text_58yuhz")) or (
        " ".join(filter(None, [clean(fields.get("text_7ubrr")), clean(fields.get("text_9rply"))]))
    )
    bride_full = clean(fields.get("text_59xbyv")) or (
        " ".join(filter(None, [
            clean(fields.get("text_10kbrv")), clean(fields.get("text_11qlvz")),
            clean(fields.get("text_12vccq")),
        ]))
    )

    gf, gm, gl = split_name(groom_full)
    bf, bm, bl = split_name(bride_full)

    groom_father = " ".join(filter(None, [clean(fields.get("text_82lsbw")), clean(fields.get("text_84hehl"))])) or None
    groom_mother = " ".join(filter(None, [clean(fields.get("text_90djme")), clean(fields.get("text_91zhnv")), clean(fields.get("text_92ebuk"))])) or None
    bride_father = " ".join(filter(None, [clean(fields.get("text_85sdxr")), clean(fields.get("text_87kkvo"))])) or None
    bride_mother = " ".join(filter(None, [clean(fields.get("text_93fdeg")), clean(fields.get("text_94wr")), clean(fields.get("text_95ziog"))])) or None

    return {
        "province":              clean(fields.get("text_4viyg")),
        "city_municipality":     clean(fields.get("text_3mlwl")),
        "registry_no":           clean(fields.get("text_6odgd")),
        "groom_first_name":      gf,
        "groom_middle_name":     gm,
        "groom_last_name":       gl,
        "groom_full_name":       groom_full,
        "bride_first_name":      bf,
        "bride_middle_name":     bm,
        "bride_last_name":       bl,
        "bride_full_name":       bride_full,
        "groom_birth_day":       clean(fields.get("text_92bqxe")),
        "groom_birth_month":     clean(fields.get("text_13mmuv")),
        "groom_birth_year":      clean(fields.get("text_16jwzf")),
        "groom_age":             clean(fields.get("text_17fzaj")),
        "bride_birth_day":       clean(fields.get("text_93vjdn")),
        "bride_birth_month":     clean(fields.get("text_20vhqm")),
        "bride_birth_year":      clean(fields.get("text_18gsnj")),
        "bride_age":             clean(fields.get("text_19mzgm")),
        "groom_place_city":      clean(fields.get("text_23xbfg")),
        "groom_place_province":  clean(fields.get("text_24ffjv")),
        "groom_place_country":   clean(fields.get("text_27pjyr")),
        "bride_place_city":      clean(fields.get("text_25kkny")),
        "bride_place_province":  clean(fields.get("text_26rilb")),
        "bride_place_country":   clean(fields.get("text_28rgip")),
        "groom_residence":       clean(fields.get("text_33ctyw")),
        "bride_residence":       clean(fields.get("text_34oogg")),
        "groom_religion":        clean(fields.get("text_35uycg")),
        "bride_religion":        clean(fields.get("text_92qovp")),
        "groom_civil_status":    clean(fields.get("text_97avdy")),
        "bride_civil_status":    clean(fields.get("text_98lfpu")),
        "groom_father_name":     groom_father,
        "groom_mother_name":     groom_mother,
        "bride_father_name":     bride_father,
        "bride_mother_name":     bride_mother,
        "place_of_marriage":     clean(fields.get("text_54qmbr")),
        "marriage_city":         clean(fields.get("text_102eomp")),
        "marriage_province":     clean(fields.get("text_103yfmm")),
        "marriage_day":          clean(fields.get("text_92kfuf")),
        "marriage_month":        clean(fields.get("text_93xjsz")),
        "marriage_year":         clean(fields.get("text_94kdif")),
        "marriage_time":         clean(fields.get("text_57joen")),
        "issued_date":           clean(fields.get("text_69rrhe")),
        "license_no":            clean(fields.get("text_71kymi")),
        "issued_city":           clean(fields.get("text_70wnsf")),
        "solemnizing_officer":   clean(fields.get("text_115fltu")),
        "solemnizing_position":  clean(fields.get("text_74peut")),
    }

def row_to_frontend(row):
    return {
        "id":                 row.get("id"),
        "file_name":          row.get("file_name"),
        "original_file_name": row.get("original_file_name"),
        "stored_file_name":   row.get("stored_file_name"),
        "file_path":          row.get("file_path"),
        "province":           row.get("province"),
        "city_municipality":  row.get("city_municipality"),
        "registry_no":        row.get("registry_no"),
        "groom_first_name":   row.get("groom_first_name"),
        "groom_middle_name":  row.get("groom_middle_name"),
        "groom_last_name":    row.get("groom_last_name"),
        "groom_full_name":    row.get("groom_full_name"),
        "bride_first_name":   row.get("bride_first_name"),
        "bride_middle_name":  row.get("bride_middle_name"),
        "bride_last_name":    row.get("bride_last_name"),
        "bride_full_name":    row.get("bride_full_name"),
        "groom_civil_status": row.get("groom_civil_status"),
        "bride_civil_status": row.get("bride_civil_status"),
        "marriage_day":       row.get("marriage_day"),
        "marriage_month":     row.get("marriage_month"),
        "marriage_year":      row.get("marriage_year"),
        "uploaded_at":  str(row.get("uploaded_at")) if row.get("uploaded_at") else None,
        "updated_at":   str(row.get("updated_at"))  if row.get("updated_at")  else None,
        "archived_at":  str(row.get("archived_at")) if row.get("archived_at") else None,
        # NOTE: a NULL is_archived is treated as "not archived" here too,
        # so the frontend's display badge/logic stays consistent with the
        # query-level fix above.
        "is_archived":  bool(row.get("is_archived") or False),
    }


def build_transaction_full_name(
    groom_first_name=None, groom_middle_name=None, groom_last_name=None,
    bride_first_name=None,  bride_middle_name=None,  bride_last_name=None,
    groom_full_name=None,  bride_full_name=None,
):
    groom_name = clean(groom_full_name)
    bride_name = clean(bride_full_name)
    if not groom_name:
        groom_name = " ".join(filter(None, [clean(groom_first_name), clean(groom_middle_name), clean(groom_last_name)])).strip() or None
    if not bride_name:
        bride_name = " ".join(filter(None, [clean(bride_first_name), clean(bride_middle_name), clean(bride_last_name)])).strip() or None
    if groom_name and bride_name:
        return f"{groom_name} & {bride_name}"
    return groom_name or bride_name or None


# =============================================================================
# FILE PATH RESOLVERS  (unchanged — filesystem, not MySQL) (Marriage)
# =============================================================================

def _key_sep(name):   return re.sub(r"[-_]+", "_", name.lower()).strip("_")
def _key_alnum(name): return re.sub(r"[^a-z0-9]", "", name.lower())
def _uuid_prefix(name):
    m = re.match(r"^([0-9a-f]{32})", name.lower())
    return m.group(1) if m else ""

def _resolve_in_dir(row, upload_dir):
    stored  = (row.get("stored_file_name") or "").strip()
    db_path = (row.get("file_path")        or "").strip()

    if stored:
        c = os.path.join(upload_dir, stored)
        if os.path.isfile(c): return c
    if db_path and os.path.isfile(db_path): return db_path
    if db_path:
        bn = os.path.basename(db_path)
        c  = os.path.join(upload_dir, bn)
        if os.path.isfile(c): return c

    if not os.path.isdir(upload_dir): return None
    ref = stored or os.path.basename(db_path)
    if not ref: return None
    all_files = os.listdir(upload_dir)

    rs = _key_sep(ref)
    for f in all_files:
        if _key_sep(f) == rs: return os.path.join(upload_dir, f)

    ra = _key_alnum(ref)
    for f in all_files:
        if _key_alnum(f) == ra: return os.path.join(upload_dir, f)

    ru = _uuid_prefix(ref)
    if ru:
        for f in all_files:
            if _uuid_prefix(f) == ru: return os.path.join(upload_dir, f)
    return None

def resolve_file_path(row):
    is_archived = bool(row.get("is_archived") or False)
    primary   = ARCHIVE_UPLOAD_DIR if is_archived else UPLOAD_DIR
    secondary = UPLOAD_DIR          if is_archived else ARCHIVE_UPLOAD_DIR
    return _resolve_in_dir(row, primary) or _resolve_in_dir(row, secondary)

def _repair_row(record_id, real_path):
    try:
        real_name = os.path.basename(real_path)
        supabase.table("marriage_records").update({
            "stored_file_name": real_name,
            "file_path": real_path,
            "updated_at": datetime.now().isoformat(),
        }).eq("id", record_id).execute()
    except Exception:
        pass


# =============================================================================
# ADMIN REPAIR (Marriage)
# =============================================================================

@marriage_bp.route("/admin/repair-paths", methods=["POST"])
def admin_repair_paths():
    try:
        res  = supabase.table("marriage_records").select(
            "id, stored_file_name, file_path, is_archived"
        ).execute()
        rows = res.data
        repaired, unresolved = [], []

        for row in rows:
            stored = (row.get("stored_file_name") or "").strip()
            ud     = ARCHIVE_UPLOAD_DIR if row.get("is_archived") else UPLOAD_DIR
            if stored and os.path.isfile(os.path.join(ud, stored)):
                continue
            rp = resolve_file_path(row)
            if rp:
                supabase.table("marriage_records").update({
                    "stored_file_name": os.path.basename(rp),
                    "file_path": rp,
                    "updated_at": datetime.now().isoformat(),
                }).eq("id", row["id"]).execute()
                repaired.append({"id": row["id"], "old": stored, "new": os.path.basename(rp)})
            else:
                unresolved.append({"id": row["id"], "stored_file_name": stored})

        return jsonify({"success": True, "repaired": len(repaired), "unresolved": len(unresolved),
                        "details": {"repaired": repaired, "unresolved": unresolved}}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@marriage_bp.route("/admin/debug-paths", methods=["GET"])
def admin_debug_paths():
    files_active  = os.listdir(UPLOAD_DIR)[:50]         if os.path.isdir(UPLOAD_DIR)         else []
    files_archive = os.listdir(ARCHIVE_UPLOAD_DIR)[:50] if os.path.isdir(ARCHIVE_UPLOAD_DIR) else []
    return jsonify({
        "upload_dir":         UPLOAD_DIR,
        "archive_upload_dir": ARCHIVE_UPLOAD_DIR,
        "active_files":       files_active,
        "archive_files":      files_archive,
    }), 200


# =============================================================================
# ADMIN — one-off backfill for rows with is_archived left NULL
# (e.g. rows inserted directly through the Supabase table editor). Run this
# once if you want existing NULL rows explicitly normalized to false in the
# database itself, instead of relying on the NULL-safe query filter above.
# (Marriage)
# =============================================================================

@marriage_bp.route("/admin/backfill-is-archived", methods=["POST"])
def admin_backfill_is_archived():
    try:
        res = supabase.table("marriage_records") \
            .select("id") \
            .is_("is_archived", "null") \
            .execute()
        ids = [r["id"] for r in (res.data or [])]
        if not ids:
            return jsonify({"success": True, "updated": 0}), 200

        for rid in ids:
            supabase.table("marriage_records").update({
                "is_archived": False,
                "updated_at": datetime.now().isoformat(),
            }).eq("id", rid).execute()

        return jsonify({"success": True, "updated": len(ids), "ids": ids}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# =============================================================================
# NEW — DIAGNOSTIC: see the *actual* is_archived value stored for every
# marriage record (Marriage)
#
# WHY THIS WAS ADDED: the "Archive tab shows nothing but Supabase shows
# rows" report traces to records (ids 26-45 in the reported case) that
# were inserted directly via the Table Editor / a raw SQL import. Those
# inserts never explicitly set is_archived, so the column's schema
# default (`DEFAULT FALSE`) kicked in — meaning those rows are NOT null,
# they are explicitly is_archived = false. That makes them ACTIVE records
# (they belong in "New Transaction" search results, not the Archive tab)
# — which is why MARRIAGE_ARCHIVED_FILTER (is_archived.eq.true OR
# is_archived.is.null) correctly excludes them: they are neither true
# nor null.
#
# This is intentionally read-only and additive — it does not change any
# existing route's behavior. Use it to confirm what's really in the
# column before deciding whether a record should be moved to Archive.
# =============================================================================

@marriage_bp.route("/admin/is-archived-status", methods=["GET"])
def admin_is_archived_status():
    try:
        res = supabase.table("marriage_records").select(
            "id, file_name, original_file_name, is_archived, uploaded_at, archived_at"
        ).order("id", desc=False).execute()
        rows = res.data or []

        summary = {"true": 0, "false": 0, "null": 0}
        for r in rows:
            v = r.get("is_archived")
            if v is True:
                summary["true"] += 1
            elif v is False:
                summary["false"] += 1
            else:
                summary["null"] += 1

        return jsonify({"summary": summary, "records": rows}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to load is_archived status: {e}"}), 500


# =============================================================================
# NEW — explicitly move specific marriage records into (or out of) the
# Archive, by id. (Marriage)
#
# Use this to fix data that was bulk-inserted with is_archived defaulting
# to false (see admin_is_archived_status above) and that you actually
# want to appear under the Archive tab. This never guesses on your
# behalf — you must pass the exact record ids you want changed.
#
# Body: { "ids": [26, 27, 28], "archived": true }
# =============================================================================

@marriage_bp.route("/admin/set-archived", methods=["POST"])
def admin_set_archived():
    try:
        data = request.get_json(force=True) or {}
        ids = data.get("ids")
        archived = data.get("archived")

        if not isinstance(ids, list) or not ids:
            return jsonify({"error": "Body must include a non-empty 'ids' array."}), 400
        if not isinstance(archived, bool):
            return jsonify({"error": "Body must include a boolean 'archived' field."}), 400

        try:
            ids = [int(i) for i in ids]
        except (TypeError, ValueError):
            return jsonify({"error": "'ids' must all be integers."}), 400

        now_iso = datetime.now().isoformat()
        update_payload = {
            "is_archived": archived,
            "updated_at": now_iso,
            "archived_at": now_iso if archived else None,
        }

        updated = []
        missing = []
        for rid in ids:
            res = supabase.table("marriage_records").update(update_payload).eq("id", rid).execute()
            if res.data:
                updated.append(rid)
            else:
                missing.append(rid)

        return jsonify({
            "success": True,
            "archived": archived,
            "updated_ids": updated,
            "not_found_ids": missing,
        }), 200
    except Exception as e:
        return jsonify({"error": f"Failed to update is_archived for records: {e}"}), 500


# =============================================================================
# ACTIVE RECORDS (Marriage)
# =============================================================================

@marriage_bp.route("/records", methods=["GET"])
def get_records():
    try:
        # FIX: now a strict eq(false) — was .or_(ACTIVE_FILTER), which also
        # matched NULL rows. Since MARRIAGE_ARCHIVED_FILTER (below) now
        # claims NULL rows as archived, this list must exclude NULL
        # explicitly so a given record can never appear in both the
        # Active search and the Archive tab at the same time.
        res = supabase.table("marriage_records").select(MARRIAGE_RECORD_SELECT_COLS) \
            .eq("is_archived", _bool_filter(False)) \
            .order("uploaded_at", desc=True).order("id", desc=True).execute()
        return jsonify([row_to_frontend(r) for r in res.data]), 200
    except Exception as e:
        import traceback
        traceback.print_exc()  # surfaces the real PostgREST error server-side instead of hiding it
        return jsonify({"error": f"Failed to load records: {e}"}), 500


# =============================================================================
# ARCHIVED RECORDS (Marriage)
# =============================================================================

def _or_escape(v: str) -> str:
    # PostgREST's or_() syntax treats comma/parentheses as separators —
    # strip them out of user search input so they can't break the filter.
    return re.sub(r"[(),]", "", v)


@marriage_bp.route("/archived", methods=["GET"])
def get_archived_records():
    try:
        search = request.args.get("search",     "").strip()
        fname  = request.args.get("first_name", "").strip()
        lname  = request.args.get("last_name",  "").strip()

        # FIX: was .eq("is_archived", _bool_filter(True)), which excludes
        # rows where is_archived is NULL — exactly the rows created by a
        # direct SQL/table-editor import (see the screenshot: rows inserted
        # without ever touching the app's upload flow). NULL never equals
        # true OR false in SQL, so those rows were invisible in the Archive
        # tab even though they're sitting right there in the table. Using
        # .or_() to also accept NULL as "archived" fixes that, mirroring the
        # identical fix already applied to Birth's archived endpoint.
        query = supabase.table("marriage_records").select(MARRIAGE_RECORD_SELECT_COLS) \
            .or_(MARRIAGE_ARCHIVED_FILTER)

        if search:
            s = _or_escape(search)
            cols = ["file_name", "original_file_name", "groom_full_name", "bride_full_name",
                    "groom_first_name", "groom_last_name", "bride_first_name", "bride_last_name",
                    "registry_no", "city_municipality", "province"]
            query = query.or_(",".join(f"{c}.ilike.%{s}%" for c in cols))

        if fname:
            f = _or_escape(fname)
            query = query.or_(f"groom_first_name.ilike.%{f}%,bride_first_name.ilike.%{f}%")

        if lname:
            l = _or_escape(lname)
            query = query.or_(f"groom_last_name.ilike.%{l}%,bride_last_name.ilike.%{l}%")

        res = query.order("archived_at", desc=True).order("id", desc=True).execute()
        return jsonify([row_to_frontend(r) for r in res.data]), 200
    except Exception as e:
        import traceback
        traceback.print_exc()  # surfaces the real PostgREST error server-side instead of hiding it
        return jsonify({"error": f"Failed to load archived records: {e}"}), 500


# =============================================================================
# UPLOAD ROUTES (Marriage)
# =============================================================================

@marriage_bp.route("/archived", methods=["POST"])
def upload_archived_shortcut():
    return _upload_pdf(target="archive")


@marriage_bp.route("/archived/upload", methods=["POST"])
def upload_to_archive():
    return _upload_pdf(target="archive")


@marriage_bp.route("/records", methods=["POST"])
def upload_record():
    return _upload_pdf(target="archive")


# =============================================================================
# ARCHIVED RECORD — view / download / delete (Marriage)
# =============================================================================

@marriage_bp.route("/archived/<int:record_id>/view", methods=["GET"])
def view_archived(record_id):
    return _serve_pdf(record_id, as_attachment=False)


@marriage_bp.route("/archived/<int:record_id>/download", methods=["GET"])
def download_archived(record_id):
    return _serve_pdf(record_id, as_attachment=True)


@marriage_bp.route("/archived/<int:record_id>", methods=["DELETE"])
def delete_archived(record_id):
    return _delete_record(record_id)


# =============================================================================
# SHARED PDF-SERVE HELPER (Marriage)
# =============================================================================

def _serve_pdf(record_id, as_attachment=False):
    try:
        res = supabase.table("marriage_records").select("*").eq("id", record_id).limit(1).execute()
        if not res.data:
            return jsonify({"error": "Record not found."}), 404
        row = res.data[0]

        is_archived  = bool(row.get("is_archived") or False)
        primary_dir  = ARCHIVE_UPLOAD_DIR if is_archived else UPLOAD_DIR
        stored       = (row.get("stored_file_name") or "").strip()
        exact_path   = os.path.join(primary_dir, stored) if stored else None
        resolved     = (exact_path if (exact_path and os.path.isfile(exact_path)) else resolve_file_path(row))
        if resolved:
            _repair_row(record_id, resolved)
        else:
            return jsonify({"error": "PDF file not found on server."}), 404

        return send_file(
            resolved,
            mimetype="application/pdf",
            as_attachment=as_attachment,
            download_name=row.get("original_file_name") or f"{row.get('file_name', 'document')}.pdf"
        )
    except Exception as e:
        return jsonify({"error": f"Failed to serve PDF: {e}"}), 500


# =============================================================================
# SHARED DELETE HELPER (Marriage)
# =============================================================================

def _delete_record(record_id):
    try:
        res = supabase.table("marriage_records").select("*").eq("id", record_id).limit(1).execute()
        if not res.data:
            return jsonify({"error": "Record not found."}), 404
        row = res.data[0]

        resolved = resolve_file_path(row)
        supabase.table("marriage_records").delete().eq("id", record_id).execute()

        if resolved and os.path.exists(resolved):
            try: os.remove(resolved)
            except Exception: pass

        return jsonify({"success": True, "message": "Record deleted successfully."}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to delete record: {e}"}), 500


# =============================================================================
# SHARED UPLOAD LOGIC (Marriage)
# =============================================================================

def _upload_pdf(target="archive"):
    tmp_path = None
    is_archived = True if target == "archive" else False
    dest_dir    = ARCHIVE_UPLOAD_DIR if is_archived else UPLOAD_DIR

    try:
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded."}), 400
        file = request.files["file"]
        if not file or file.filename == "":
            return jsonify({"error": "No file selected."}), 400
        if not marriage_allowed_file(file.filename):
            return jsonify({"error": "Only PDF files are allowed."}), 400

        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
        if size > MARRIAGE_MAX_FILE_SIZE_BYTES:
            return jsonify({"error": f"File exceeds {MARRIAGE_MAX_FILE_SIZE_MB} MB limit."}), 400

        file_hash          = compute_file_hash(file)
        original_file_name = normalize_filename(file.filename)
        file_name          = os.path.splitext(original_file_name)[0]
        stored_file_name   = f"{uuid.uuid4().hex}_{original_file_name}"
        file_path          = os.path.join(dest_dir, stored_file_name)

        dup_error = check_duplicate(original_file_name, file_hash)
        if dup_error:
            return jsonify({"error": dup_error}), 409

        tmp_path = file_path
        file.save(file_path)
        if not os.path.isfile(file_path):
            return jsonify({"error": "File was not saved correctly."}), 500

        pdf_fields = extract_pdf_fields(file_path)
        mapped     = map_marriage_pdf_fields(pdf_fields)

        now_iso = datetime.now().isoformat()
        insert_payload = {
            "file_name": file_name,
            "original_file_name": original_file_name,
            "stored_file_name": stored_file_name,
            "file_path": file_path,
            "file_hash": file_hash,
            **mapped,
            # NOTE: explicitly set is_archived (never left NULL) so this
            # exact "records exist but never show up anywhere" bug can't
            # recur for records that come through this upload path.
            "is_archived": is_archived,
            "archived_at": now_iso,
            "uploaded_at": now_iso,
            "updated_at": now_iso,
        }

        res = supabase.table("marriage_records").insert(insert_payload).execute()
        if not res.data:
            return jsonify({"error": "Failed to insert record."}), 500

        tmp_path = None
        new_row  = res.data[0]

        # NOTE: No notification on upload — notifications fire only when a
        # matching record is found and a marriage certificate is issued (ACTIVE/POSITIVE).

        return jsonify(row_to_frontend(new_row)), 201

    except APIError as e:
        msg = str(e)
        if "uq_original_file_name" in msg or "original_file_name" in msg:
            friendly = "A file with this name already exists (database constraint)."
        elif "uq_marriage_file_hash" in msg or "file_hash" in msg:
            friendly = "This file's content already exists (database constraint)."
        else:
            friendly = f"Duplicate entry detected: {msg}"
        return jsonify({"error": friendly}), 409

    except Exception as e:
        return jsonify({"error": f"Failed to process PDF: {e}"}), 500

    finally:
        if tmp_path and os.path.exists(tmp_path):
            try: os.remove(tmp_path)
            except Exception: pass


# =============================================================================
# RECORD ROUTES — view / download / delete / archive / restore (Marriage)
# =============================================================================

@marriage_bp.route("/records/<int:record_id>", methods=["GET"])
def get_record_with_pdf(record_id):
    """Returns full record metadata PLUS a base64-encoded `pdf_data` field.

    This route reads the PDF straight from disk (self-healing the stored
    path if it has drifted) and base64-encodes it, with the same
    double-encoding-safe logic used elsewhere so a malformed file on disk
    can't produce a corrupt blob on the frontend without at least
    attempting recovery first.
    """
    try:
        res = supabase.table("marriage_records").select("*").eq("id", record_id).limit(1).execute()
        if not res.data:
            return jsonify({"error": "Record not found."}), 404
        row = res.data[0]

        resolved = resolve_file_path(row)
        pdf_data = None
        pdf_error = None

        if resolved and os.path.isfile(resolved):
            _repair_row(record_id, resolved)
            pdf_data = file_to_base64_pdf(resolved)
            if pdf_data is None:
                pdf_error = "Could not read the PDF file on the server."
        else:
            pdf_error = "PDF file not found on server."

        payload = row_to_frontend(row)
        payload["pdf_data"] = pdf_data
        if pdf_error:
            payload["pdf_error"] = pdf_error
        return jsonify(payload), 200
    except Exception as e:
        return jsonify({"error": f"Failed to load record: {e}"}), 500


@marriage_bp.route("/records/<int:record_id>/view", methods=["GET"])
def view_record(record_id):
    return _serve_pdf(record_id, as_attachment=False)


@marriage_bp.route("/records/<int:record_id>/download", methods=["GET"])
def download_record(record_id):
    return _serve_pdf(record_id, as_attachment=True)


@marriage_bp.route("/records/<int:record_id>", methods=["DELETE"])
def delete_record(record_id):
    return _delete_record(record_id)


@marriage_bp.route("/records/<int:record_id>/archive", methods=["PUT"])
def archive_record(record_id):
    try:
        res = supabase.table("marriage_records").select("*").eq("id", record_id).limit(1).execute()
        if not res.data:
            return jsonify({"error": "Record not found."}), 404
        row = res.data[0]
        if row.get("is_archived"):
            return jsonify({"error": "Record is already archived."}), 400

        stored = (row.get("stored_file_name") or "").strip()
        src    = os.path.join(UPLOAD_DIR, stored) if stored else None
        new_file_path = row.get("file_path")
        if src and os.path.isfile(src):
            dst = os.path.join(ARCHIVE_UPLOAD_DIR, stored)
            try:
                os.rename(src, dst)
                new_file_path = dst
            except Exception:
                pass

        now_iso = datetime.now().isoformat()
        # NOTE: this is an UPDATE body, not a filter — it goes through
        # normal JSON serialization (True -> `true`), so it's unaffected
        # by the .eq() bool bug above. Left as a Python bool intentionally.
        supabase.table("marriage_records").update({
            "is_archived": True,
            "archived_at": now_iso,
            "updated_at": now_iso,
            "file_path": new_file_path,
        }).eq("id", record_id).execute()

        # FIX (audit trail — prevents the archive bug from recurring
        # unnoticed): log every archive action, matching Birth's
        # archive_record(). This endpoint should only ever be reached via
        # an explicit admin action; logging it means any unexpected /
        # automatic call in the future shows up immediately in the audit
        # log instead of silently going unnoticed.
        record_action(
            "ARCHIVE",
            f"Archived marriage record: '{row.get('file_name', record_id)}'",
            username=get_user(),
            meta={"record_id": record_id, "file_name": row.get("file_name")},
            ip=request.remote_addr
        )

        return jsonify({"success": True, "message": "Record archived successfully."}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to archive record: {e}"}), 500


@marriage_bp.route("/records/<int:record_id>/restore", methods=["PUT"])
def restore_record(record_id):
    try:
        res = supabase.table("marriage_records").select("*").eq("id", record_id).limit(1).execute()
        if not res.data:
            return jsonify({"error": "Record not found."}), 404
        row = res.data[0]
        if not row.get("is_archived"):
            return jsonify({"error": "Record is not archived."}), 400

        stored = (row.get("stored_file_name") or "").strip()
        src    = os.path.join(ARCHIVE_UPLOAD_DIR, stored) if stored else None
        new_file_path = row.get("file_path")
        if src and os.path.isfile(src):
            dst = os.path.join(UPLOAD_DIR, stored)
            try:
                os.rename(src, dst)
                new_file_path = dst
            except Exception:
                pass

        now_iso = datetime.now().isoformat()
        # Same note as archive_record() above — UPDATE body, unaffected
        # by the .eq() bool bug.
        supabase.table("marriage_records").update({
            "is_archived": False,
            "archived_at": None,
            "updated_at": now_iso,
            "file_path": new_file_path,
        }).eq("id", record_id).execute()

        # ─────────────────────────────────────────────────────────────
        # FIX (audit trail — prevents the archive bug from recurring
        # unnoticed): log every restore action, matching Birth's
        # restore_record(). is_archived should only ever flip to FALSE
        # here in response to an explicit admin "Restore" click in the
        # Archive tab. Logging every call — who triggered it, when, and
        # which record — means that if this endpoint is ever hit
        # unexpectedly again (e.g. a future frontend regression
        # re-introducing an implicit restore call, like the one that
        # caused this whole bug), it will be immediately visible in the
        # audit trail instead of silently un-archiving records for weeks
        # or months before anyone notices.
        # ─────────────────────────────────────────────────────────────
        record_action(
            "RESTORE",
            f"Restored marriage record: '{row.get('file_name', record_id)}'",
            username=get_user(),
            meta={"record_id": record_id, "file_name": row.get("file_name")},
            ip=request.remote_addr
        )

        return jsonify({"success": True, "message": "Record restored successfully."}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to restore record: {e}"}), 500


# =============================================================================
# UPDATE SPOUSES (Marriage)
# =============================================================================

@marriage_bp.route("/records/<int:record_id>/spouses", methods=["PATCH"])
def update_spouses(record_id):
    try:
        data = request.get_json(force=True) or {}
        exists = supabase.table("marriage_records").select("id").eq("id", record_id).limit(1).execute()
        if not exists.data:
            return jsonify({"error": "Record not found."}), 404

        fields = ["groom_first_name", "groom_middle_name", "groom_last_name",
                  "bride_first_name",  "bride_middle_name",  "bride_last_name"]
        update_payload = {f: clean(data.get(f)) for f in fields}
        update_payload["updated_at"] = datetime.now().isoformat()

        supabase.table("marriage_records").update(update_payload).eq("id", record_id).execute()
        return jsonify({"success": True}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =============================================================================
# COMPLETE TRANSACTION (Marriage)
# =============================================================================

@marriage_bp.route("/records/complete", methods=["POST"])
def complete_transaction():
    try:
        data              = request.get_json(force=True) or {}
        search_operator   = clean(data.get("searchOperator"))
        record_status     = clean(data.get("recordStatus"))
        record_id         = data.get("recordId")
        payment_method    = clean(data.get("paymentMethod"))    or "cash"
        payment_reference = clean(data.get("paymentReference"))
        payment_amount    = data.get("paymentAmount", 75)
        document_type     = clean(data.get("documentType"))     or "marriage"
        document_issued   = clean(data.get("documentIssued"))   or "Marriage Certificate"

        groom_first_name  = clean(data.get("groom_first_name")  or data.get("groomFirstName"))
        groom_middle_name = clean(data.get("groom_middle_name") or data.get("groomMiddleName"))
        groom_last_name   = clean(data.get("groom_last_name")   or data.get("groomLastName"))
        bride_first_name  = clean(data.get("bride_first_name")  or data.get("brideFirstName"))
        bride_middle_name = clean(data.get("bride_middle_name") or data.get("brideMiddleName"))
        bride_last_name   = clean(data.get("bride_last_name")   or data.get("brideLastName"))

        if not record_status:
            return jsonify({"error": "recordStatus is required."}), 400

        if not payment_reference:
            payment_reference = f"MR-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"

        try:    payment_amount = float(payment_amount)
        except: return jsonify({"error": "paymentAmount must be numeric."}), 400
        if payment_amount < 0:
            return jsonify({"error": "paymentAmount cannot be negative."}), 400

        groom_full_name = bride_full_name = None
        if record_id not in (None, "", "null", "undefined"):
            try:    record_id = int(record_id)
            except: return jsonify({"error": "recordId must be a valid integer."}), 400

            rec_res = supabase.table("marriage_records").select(
                "id, groom_first_name, groom_middle_name, groom_last_name, groom_full_name, "
                "bride_first_name, bride_middle_name, bride_last_name, bride_full_name"
            ).eq("id", record_id).limit(1).execute()
            if not rec_res.data:
                return jsonify({"error": "Selected marriage record not found."}), 404
            db_rec = rec_res.data[0]

            if not groom_first_name:  groom_first_name  = clean(db_rec.get("groom_first_name"))
            if not groom_middle_name: groom_middle_name = clean(db_rec.get("groom_middle_name"))
            if not groom_last_name:   groom_last_name   = clean(db_rec.get("groom_last_name"))
            if not bride_first_name:  bride_first_name  = clean(db_rec.get("bride_first_name"))
            if not bride_middle_name: bride_middle_name = clean(db_rec.get("bride_middle_name"))
            if not bride_last_name:   bride_last_name   = clean(db_rec.get("bride_last_name"))
            groom_full_name = clean(db_rec.get("groom_full_name"))
            bride_full_name = clean(db_rec.get("bride_full_name"))
        else:
            record_id = None

        full_name = build_transaction_full_name(
            groom_first_name=groom_first_name, groom_middle_name=groom_middle_name,
            groom_last_name=groom_last_name,   bride_first_name=bride_first_name,
            bride_middle_name=bride_middle_name, bride_last_name=bride_last_name,
            groom_full_name=groom_full_name,   bride_full_name=bride_full_name,
        ) or search_operator or "Unknown Marriage Record"

        now_iso = datetime.now().isoformat()
        insert_res = supabase.table("marriage_transactions").insert({
            "record_id": record_id,
            "full_name": full_name,
            "document_type": document_type,
            "document_issued": document_issued,
            "record_status": record_status,
            "payment_method": payment_method,
            "payment_reference": payment_reference,
            "payment_amount": payment_amount,
            "search_operator": search_operator,
            "groom_first_name": groom_first_name,
            "groom_middle_name": groom_middle_name,
            "groom_last_name": groom_last_name,
            "bride_first_name": bride_first_name,
            "bride_middle_name": bride_middle_name,
            "bride_last_name": bride_last_name,
            "created_at": now_iso,
            "updated_at": now_iso,
        }).execute()

        if not insert_res.data:
            return jsonify({"error": "Failed to save transaction."}), 500
        transaction_id = insert_res.data[0]["id"]

        # ── NOTIFICATION: only fire when record was FOUND in the database
        # AND that record was originally submitted through the Online
        # Request system (see _matches_online_marriage_request() /
        # CIVIL_REGISTRY_REQUEST_TABLE at the top of this file). Processing
        # an existing marriage record directly from the Marriage data —
        # with no matching online request — no longer sends any
        # notification. ──
        record_status_upper = (record_status or "").strip().upper()
        if record_status_upper in ("ACTIVE", "POSITIVE") and _matches_online_marriage_request(
            groom_full_name, bride_full_name, control_no=payment_reference or None
        ):
            push_notification(
                record_type="marriage",
                record_id=record_id,
                control_no=payment_reference,
                title="Marriage Certificate Issued",
                message=f"Marriage certificate issued for '{full_name}'",
            )

        return jsonify({
            "success": True, "message": "Marriage transaction completed.",
            "transaction_id": transaction_id, "record_id": record_id,
            "full_name": full_name, "document_type": document_type,
            "document_issued": document_issued, "record_status": record_status,
            "payment_method": payment_method, "payment_reference": payment_reference,
            "payment_amount": payment_amount,
        }), 201

    except Exception as e:
        return jsonify({"error": f"Failed to complete transaction: {str(e)}"}), 500


# =============================================================================
# GET PAYMENTS (Marriage)
# =============================================================================

def _normalize_payment_status_marriage(record_status):
    if not record_status: return "Paid"
    upper = record_status.strip().upper()
    if upper == "POSITIVE": return "Positive"
    if upper == "NEGATIVE": return "Negative"
    if upper == "ACTIVE":   return "Positive"
    return record_status.strip().title() or "Paid"


@marriage_bp.route("/payments", methods=["GET"])
def get_payments():
    try:
        limit = min(max(request.args.get("limit", default=500, type=int), 1), 1000)

        res = supabase.table("marriage_transactions").select(
            "id, record_id, full_name, document_type, document_issued, "
            "record_status, payment_method, payment_reference, payment_amount, "
            "search_operator, "
            "groom_first_name, groom_middle_name, groom_last_name, "
            "bride_first_name, bride_middle_name, bride_last_name, "
            "created_at, updated_at"
        ).order("created_at", desc=True).order("id", desc=True).limit(limit).execute()
        rows = res.data

        agg_res        = supabase.table("marriage_transactions").select("payment_amount").execute()
        total_requests = len(agg_res.data)
        total_payments = sum(float(r.get("payment_amount") or 0) for r in agg_res.data)

        payments = []
        for row in rows:
            row = dict(row)
            raw                   = row.get("payment_amount")
            row["amount"]         = float(raw) if raw is not None else 0.0
            row["payment_date"]   = row.get("created_at")
            row["payment_status"] = _normalize_payment_status_marriage(row.get("record_status", ""))
            for f in ("groom_first_name", "groom_middle_name", "groom_last_name",
                      "bride_first_name",  "bride_middle_name",  "bride_last_name"):
                row[f] = row.get(f) or ""
            row["full_name"] = row.get("full_name") or ""
            payments.append(row)

        return jsonify({
            "payments":       payments,
            "total_requests": total_requests,
            "total_payments": total_payments,
        }), 200
    except Exception as e:
        return jsonify({"error": f"Failed to load marriage payments: {e}"}), 500