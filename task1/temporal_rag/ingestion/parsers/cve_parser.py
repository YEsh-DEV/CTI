import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from schemas.normalized import NormalizedCVE
from common.logging_utils import setup_logger

logger = setup_logger("cve_parser", "cve_parser.log")


def _parse_iso_datetime(date_str: Optional[str]) -> Optional[datetime]:
    if not date_str or not isinstance(date_str, str):
        return None
    try:
        # Handle trailing Z
        cleaned = date_str.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned)
    except Exception:
        try:
            # Try YYYY-MM-DD
            return datetime.strptime(date_str[:10], "%Y-%m-%d")
        except Exception:
            return None


def parse_cve_dict(data: Dict[str, Any]) -> Optional[NormalizedCVE]:
    """
    Parses a raw CVE 5.x JSON record dictionary into a NormalizedCVE model.
    """
    cve_metadata = data.get("cveMetadata", {})
    cve_id = cve_metadata.get("cveId")
    if not cve_id:
        logger.warning("CVE record missing cveMetadata.cveId")
        return None

    date_published = _parse_iso_datetime(cve_metadata.get("datePublished"))
    if not date_published:
        # Fallback to dateReserved or current UTC time if not published yet
        date_published = _parse_iso_datetime(cve_metadata.get("dateReserved")) or datetime.utcnow()

    containers = data.get("containers", {})
    cna = containers.get("cna", {})

    title = cna.get("title")
    date_public = _parse_iso_datetime(cna.get("datePublic"))

    # Extract English description
    descriptions = cna.get("descriptions", [])
    description_text = ""
    for desc in descriptions:
        if desc.get("lang") == "en" and desc.get("value"):
            description_text = desc.get("value", "").strip()
            break
    if not description_text and descriptions:
        description_text = descriptions[0].get("value", "").strip()

    # Extract CWE problem types
    cwe_id: Optional[str] = None
    cwe_description: Optional[str] = None
    problem_types = cna.get("problemTypes", [])
    for pt in problem_types:
        for ptd in pt.get("descriptions", []):
            if not cwe_id and ptd.get("cweId"):
                cwe_id = ptd.get("cweId")
            if not cwe_description and ptd.get("description"):
                cwe_description = ptd.get("description")

    # Extract affected vendor, product, versions
    affected_vendor: Optional[str] = None
    affected_product: Optional[str] = None
    affected_versions: List[str] = []
    affected_list = cna.get("affected", [])
    for aff in affected_list:
        if not affected_vendor and aff.get("vendor"):
            affected_vendor = aff.get("vendor")
        if not affected_product and aff.get("product"):
            affected_product = aff.get("product")

        for v in aff.get("versions", []):
            ver_str = v.get("version", "")
            less_than = v.get("lessThan")
            if less_than:
                affected_versions.append(f"<{less_than}" if ver_str in ("0", "") else f"{ver_str} < {less_than}")
            elif ver_str:
                affected_versions.append(ver_str)

    # Extract CVSS metrics (Prefer CVSS 3.1 over 4.0)
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    cvss_vector: Optional[str] = None
    cvss_version: str = "none"

    metrics = cna.get("metrics", [])
    for metric in metrics:
        if "cvssV3_1" in metric:
            cvss_obj = metric["cvssV3_1"]
            cvss_score = cvss_obj.get("baseScore")
            cvss_severity = cvss_obj.get("baseSeverity")
            cvss_vector = cvss_obj.get("vectorString")
            cvss_version = "3.1"
            break  # Highest priority found

    # If cvssV3_1 wasn't found, check cvssV4_0
    if cvss_version == "none":
        for metric in metrics:
            if "cvssV4_0" in metric:
                cvss_obj = metric["cvssV4_0"]
                cvss_score = cvss_obj.get("baseScore")
                cvss_severity = cvss_obj.get("baseSeverity")
                cvss_vector = cvss_obj.get("vectorString")
                cvss_version = "4.0"
                break

    # Extract references
    references: List[str] = []
    for ref in cna.get("references", []):
        url = ref.get("url")
        if url:
            references.append(url)

    # Check containers.adp enrichment (optional CISA ADP)
    # ADP is handled gracefully; if present, we ensure references or other metrics don't crash
    adp_list = containers.get("adp", [])
    # Optional adp processing if needed in future

    return NormalizedCVE(
        cve_id=cve_id,
        date_published=date_published,
        date_public=date_public,
        title=title,
        description=description_text,
        cwe_id=cwe_id,
        cwe_description=cwe_description,
        affected_vendor=affected_vendor,
        affected_product=affected_product,
        affected_versions=affected_versions,
        cvss_score=cvss_score,
        cvss_severity=cvss_severity,
        cvss_vector=cvss_vector,
        cvss_version=cvss_version,
        references=references,
    )


def parse_cve_file(filepath: Union[Path, str]) -> Optional[NormalizedCVE]:
    """
    Reads and parses a CVE 5.x JSON file.
    """
    path = Path(filepath)
    if not path.exists():
        logger.warning(f"CVE file not found: {path}")
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return parse_cve_dict(data)
    except Exception as e:
        logger.error(f"Error parsing CVE file {path.name}: {e}")
        return None
