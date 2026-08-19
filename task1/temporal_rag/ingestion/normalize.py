import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from config.settings import (
    NORMALIZED_CTI_DIR,
    NORMALIZED_CVE_DIR,
    RAW_CTI_DIR,
    RAW_CVE_DIR,
)
from ingestion.parsers.cti_misp_xml_parser import merge_cti_events, parse_cti_xml_file
from ingestion.parsers.cve_parser import parse_cve_file
from ingestion.validate import validate_cti_event, validate_cve, record_rejection
from common.logging_utils import setup_logger

logger = setup_logger("normalize", "normalize.log")


def normalize_cti(cti_dir: Path, output_dir: Path = NORMALIZED_CTI_DIR) -> int:
    """
    Parses all XML files in cti_dir, merges events by event_id, validates,
    and writes JSON files to output_dir.
    """
    logger.info(f"Starting CTI normalization from: {cti_dir}")
    if not cti_dir.exists():
        logger.error(f"CTI source directory does not exist: {cti_dir}")
        return 0

    xml_files = sorted(list(cti_dir.glob("*.xml")))
    if not xml_files:
        logger.warning(f"No XML files found in {cti_dir}")
        return 0

    logger.info(f"Found {len(xml_files)} CTI XML files to process")
    parsed_file_data = []
    for xml_path in xml_files:
        data = parse_cti_xml_file(xml_path)
        if data:
            parsed_file_data.append(data)

    merged_events = merge_cti_events(parsed_file_data)
    valid_count = 0
    rejected_count = 0

    output_dir.mkdir(parents=True, exist_ok=True)
    # Clean up old single-integer formatted files in output_dir
    for old_f in output_dir.glob("*.json"):
        try:
            old_f.unlink()
        except OSError:
            pass

    for event in merged_events:
        is_valid, reason = validate_cti_event(event)
        if is_valid:
            out_file = output_dir / f"{event.id}.json"
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(event.model_dump(mode="json"), f, indent=2, default=str)
            valid_count += 1
        else:
            rejected_count += 1

    logger.info(
        f"CTI Normalization complete: {valid_count} saved, {rejected_count} rejected "
        f"out of {len(merged_events)} merged events."
    )
    return valid_count


def normalize_cve(cve_dir: Path, output_dir: Path = NORMALIZED_CVE_DIR) -> int:
    """
    Recursively parses all JSON files in cve_dir, validates them,
    and writes NormalizedCVE records to output_dir.
    """
    logger.info(f"Starting CVE normalization from: {cve_dir}")
    if not cve_dir.exists():
        logger.error(f"CVE source directory does not exist: {cve_dir}")
        return 0

    json_files = list(cve_dir.rglob("CVE-*.json"))
    if not json_files:
        # Fallback to any .json file if no CVE-*.json prefix
        json_files = list(cve_dir.rglob("*.json"))

    if not json_files:
        logger.warning(f"No JSON files found in {cve_dir}")
        return 0

    logger.info(f"Found {len(json_files)} CVE JSON files to process")
    valid_count = 0
    rejected_count = 0

    output_dir.mkdir(parents=True, exist_ok=True)

    for json_file in json_files:
        normalized_cve = parse_cve_file(json_file)
        if not normalized_cve:
            rejected_count += 1
            record_rejection(json_file.stem, "cve", "Failed to parse JSON file structure", str(json_file))
            continue

        is_valid, reason = validate_cve(normalized_cve)
        if is_valid:
            out_file = output_dir / f"{normalized_cve.cve_id}.json"
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(normalized_cve.model_dump(mode="json"), f, indent=2, default=str)
            valid_count += 1
        else:
            rejected_count += 1

    logger.info(
        f"CVE Normalization complete: {valid_count} saved, {rejected_count} rejected "
        f"out of {len(json_files)} files."
    )
    return valid_count


def main():
    parser = argparse.ArgumentParser(description="Normalize CTI XML and CVE JSON datasets.")
    parser.add_argument(
        "--cti-dir",
        type=str,
        default=str(RAW_CTI_DIR),
        help="Directory containing raw CTI XML files (default: data/raw/cti)",
    )
    parser.add_argument(
        "--cve-dir",
        type=str,
        default=str(RAW_CVE_DIR),
        help="Directory containing raw CVE JSON files (default: data/raw/cve)",
    )
    parser.add_argument(
        "--output-cti",
        type=str,
        default=str(NORMALIZED_CTI_DIR),
        help="Output directory for normalized CTI JSON files",
    )
    parser.add_argument(
        "--output-cve",
        type=str,
        default=str(NORMALIZED_CVE_DIR),
        help="Output directory for normalized CVE JSON files",
    )
    args = parser.parse_args()

    cti_dir = Path(args.cti_dir)
    cve_dir = Path(args.cve_dir)
    out_cti = Path(args.output_cti)
    out_cve = Path(args.output_cve)

    normalize_cti(cti_dir, out_cti)
    normalize_cve(cve_dir, out_cve)


if __name__ == "__main__":
    main()
