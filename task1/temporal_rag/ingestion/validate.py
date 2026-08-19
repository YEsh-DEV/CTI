import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from config.settings import NORMALIZED_REJECTED_DIR
from schemas.normalized import NormalizedCTIEvent, NormalizedCVE
from common.logging_utils import setup_logger

logger = setup_logger("validate", "validation.log")


def record_rejection(record_id: str, record_type: str, reason: str, raw_payload: Any = None) -> None:
    """Writes a rejected item record and reason to the _rejected folder."""
    rejection_file = NORMALIZED_REJECTED_DIR / f"{record_type}_{record_id}.json"
    rejection_data = {
        "record_id": str(record_id),
        "record_type": record_type,
        "rejected_at": datetime.utcnow().isoformat(),
        "reason": reason,
        "payload": raw_payload if isinstance(raw_payload, (dict, list, str, int, float, bool)) else str(raw_payload),
    }
    try:
        with open(rejection_file, "w", encoding="utf-8") as f:
            json.dump(rejection_data, f, indent=2, default=str)
        logger.warning(f"Rejected {record_type} [{record_id}]: {reason}")
    except Exception as e:
        logger.error(f"Failed to write rejection record {record_id}: {e}")


def validate_cti_event(event: NormalizedCTIEvent) -> Tuple[bool, Optional[str]]:
    """
    Validates a NormalizedCTIEvent.
    Requires valid event.id, non-null date, and non-empty info_title.
    """
    if not event.event_id or event.event_id <= 0:
        reason = "Missing or invalid event_id"
        record_rejection(event.id or str(event.event_id), "cti", reason, event.model_dump())
        return False, reason

    if not event.date:
        reason = f"Missing date for CTI event {event.id}"
        record_rejection(event.id, "cti", reason, event.model_dump())
        return False, reason

    if not event.info_title or not event.info_title.strip():
        reason = f"Missing or empty info_title for CTI event {event.id}"
        record_rejection(event.id, "cti", reason, event.model_dump())
        return False, reason

    return True, None


def validate_cve(cve: NormalizedCVE) -> Tuple[bool, Optional[str]]:
    """
    Validates a NormalizedCVE.
    Requires cve_id and non-empty description.
    """
    if not cve.cve_id or not cve.cve_id.strip():
        reason = "Missing or empty cve_id"
        record_rejection("unknown_cve", "cve", reason, cve.model_dump())
        return False, reason

    if not cve.description or not cve.description.strip():
        reason = f"Missing or empty description for CVE {cve.cve_id}"
        record_rejection(cve.cve_id, "cve", reason, cve.model_dump())
        return False, reason

    return True, None
