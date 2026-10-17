"""
Detects whether an uploaded civil-registry PDF is a Birth, Marriage or Death
record, so the upload routes can store it in the correct section.

Signals, most trusted first:
  1. AcroForm field names. The Birth and Marriage parsers already depend on
     these exact field names, so a match is a reliable fingerprint.
  2. Distinctive phrases in the printed text of the form.
If neither signal is clear, the result is None ("uncertain").
"""
import io
import re
import sys
import pathlib
from typing import Optional, Tuple

from pypdf import PdfReader

BIRTH = "birth"
MARRIAGE = "marriage"
DEATH = "death"

# Field names used by the Birth and Marriage forms (same names the parsers read).
BIRTH_FIELD_FINGERPRINT = frozenset({
    "text_1hcvm", "text_8sonj", "text_13zosg", "text_40teom", "text_17tfut",
})
MARRIAGE_FIELD_FINGERPRINT = frozenset({
    "text_4viyg", "text_58yuhz", "text_59xbyv", "text_54qmbr", "text_82lsbw",
})
FIELD_MIN_HITS = 3

# Weighted phrases. Death has no known field names, so text is its main signal.
TEXT_RULES = {
    BIRTH: [
        ("CERTIFICATE OF LIVE BIRTH", 5), ("REGISTER OF BIRTHS", 4),
        ("WEIGHT AT BIRTH", 4), ("TYPE OF BIRTH", 4), ("BIRTH ORDER", 3),
        ("LIVE BIRTH", 2), ("CHILD", 1),
    ],
    MARRIAGE: [
        ("CERTIFICATE OF MARRIAGE", 5), ("REGISTER OF MARRIAGES", 4),
        ("SOLEMNIZING OFFICER", 4), ("MARRIAGE LICENSE", 3),
        ("GROOM", 2), ("BRIDE", 2), ("MARRIAGE", 1),
    ],
    DEATH: [
        ("CERTIFICATE OF DEATH", 5), ("REGISTER OF DEATHS", 4),
        ("CAUSE OF DEATH", 4), ("IMMEDIATE CAUSE", 4), ("MANNER OF DEATH", 4),
        ("AUTOPSY", 3), ("DECEASED", 3), ("DATE OF DEATH", 3),
        ("PLACE OF OCCURRENCE", 3), ("DEATH", 1),
    ],
}
MIN_SCORE = 4          # winning type needs at least this much evidence
MIN_LEAD = 2           # and must beat the runner-up by at least this much
MAX_PAGES_FOR_TEXT = 3


def _field_names(reader: PdfReader) -> set:
    try:
        return set((reader.get_fields() or {}).keys())
    except Exception:
        return set()


def _page_text(reader: PdfReader) -> str:
    parts = []
    for page in reader.pages[:MAX_PAGES_FOR_TEXT]:
        try:
            parts.append(page.extract_text() or "")
        except Exception:
            pass
    return re.sub(r"\s+", " ", " ".join(parts)).upper()


def classify_record_pdf(pdf_bytes: bytes) -> Tuple[Optional[str], str]:
    """Return (record_type or None, method). None means uncertain."""
    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
    except Exception:
        return None, "unreadable"

    names = _field_names(reader)
    birth_hits = len(names & BIRTH_FIELD_FINGERPRINT)
    marriage_hits = len(names & MARRIAGE_FIELD_FINGERPRINT)
    if birth_hits >= FIELD_MIN_HITS and marriage_hits == 0:
        return BIRTH, "form-fields"
    if marriage_hits >= FIELD_MIN_HITS and birth_hits == 0:
        return MARRIAGE, "form-fields"

    text = _page_text(reader)
    scores = {
        kind: sum(weight for phrase, weight in rules if phrase in text)
        for kind, rules in TEXT_RULES.items()
    }
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    (best_kind, best), (_, runner_up) = ranked[0], ranked[1]
    if best >= MIN_SCORE and best - runner_up >= MIN_LEAD:
        return best_kind, "text"
    return None, "uncertain"


# Audit tool: classify every PDF in a folder without touching the database.
#   python -m routes.record_classifier uploads/marriage uploads/marriage_archive
if __name__ == "__main__":
    for folder in sys.argv[1:]:
        counts = {}
        for path in sorted(pathlib.Path(folder).glob("*.pdf")):
            kind, method = classify_record_pdf(path.read_bytes())
            key = kind or "uncertain"
            counts[key] = counts.get(key, 0) + 1
            print(f"{key:10} {method:12} {path.name}")
        print(f"\n{folder}: {counts}\n")