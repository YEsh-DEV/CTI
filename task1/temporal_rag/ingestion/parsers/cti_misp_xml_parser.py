import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime, date
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from schemas.normalized import IOC, NormalizedCTIEvent
from common.logging_utils import setup_logger

logger = setup_logger("cti_misp_xml_parser", "cti_parser.log")


def _extract_attribute_node(attr_elem: ET.Element) -> Optional[IOC]:
    """Extracts an IOC object from an Attribute or item XML element."""
    cat_elem = attr_elem.find("category")
    category = cat_elem.text.strip() if cat_elem is not None and cat_elem.text else "Other"

    type_elem = attr_elem.find("type")
    attr_type = type_elem.text.strip() if type_elem is not None and type_elem.text else "other"

    val_elem = attr_elem.find("value")
    value = val_elem.text.strip() if val_elem is not None and val_elem.text else ""

    comm_elem = attr_elem.find("comment")
    comment = comm_elem.text.strip() if comm_elem is not None and comm_elem.text else ""

    if value:
        return IOC(
            category=category,
            type=attr_type,
            value=value,
            comment=comment,
        )
    return None


def parse_cti_xml_file(filepath: Path | str) -> Dict[Tuple[int, int], Dict[str, Any]]:
    """
    Parses a single MISP-style CTIMinerDataset XML file.
    Extracts the year from the filename (e.g. CTIDataset_2019_ReportEvent.xml -> 2019).
    Returns a dictionary keyed by composite tuple: (year, event_id) -> event data dict.
    """
    path = Path(filepath)
    if not path.exists():
        logger.warning(f"File not found: {path}")
        return {}

    # Extract year from filename (e.g. CTIDataset_2019_ReportEvent.xml)
    year_match = re.search(r"(\d{4})", path.name)
    file_year = int(year_match.group(1)) if year_match else 1970

    try:
        tree = ET.parse(str(path))
        root = tree.getroot()
    except ET.ParseError as e:
        logger.error(f"XML parse error in {path.name}: {e}")
        return {}

    events_data: Dict[Tuple[int, int], Dict[str, Any]] = {}
    event_nodes = root.findall("Event")

    if not event_nodes:
        logger.warning(f"No <Event> elements found in {path.name} (root: <{root.tag}/>)")
        return {}

    for event_elem in event_nodes:
        id_elem = event_elem.find("id")
        if id_elem is None or not id_elem.text or not id_elem.text.strip():
            logger.warning(f"Event missing valid <id> in {path.name}, skipping.")
            continue

        try:
            event_id = int(id_elem.text.strip())
        except ValueError:
            logger.warning(f"Invalid event id '{id_elem.text}' in {path.name}, skipping.")
            continue

        date_elem = event_elem.find("date")
        date_str = date_elem.text.strip() if date_elem is not None and date_elem.text else "1970-01-01"
        try:
            event_date = datetime.strptime(date_str, "%Y-%m-%d").date()
        except ValueError:
            try:
                event_date = datetime.fromisoformat(date_str).date()
            except ValueError:
                logger.warning(f"Invalid date format '{date_str}' in event {event_id}, defaulting to 1970-01-01")
                event_date = date(1970, 1, 1)

        info_elem = event_elem.find("info")
        info_title = info_elem.text.strip() if info_elem is not None and info_elem.text else ""

        attributes: List[IOC] = []

        # Check direct <Attribute> tags and nested <Attribute><item> tags
        for attr_elem in event_elem.findall("Attribute"):
            items = attr_elem.findall("item")
            if items:
                for item_elem in items:
                    ioc = _extract_attribute_node(item_elem)
                    if ioc:
                        attributes.append(ioc)
            else:
                ioc = _extract_attribute_node(attr_elem)
                if ioc:
                    attributes.append(ioc)

        composite_key = (file_year, event_id)
        events_data[composite_key] = {
            "year": file_year,
            "event_id": event_id,
            "date": event_date,
            "info": info_title,
            "attributes": attributes,
            "source_file": path.name,
        }

    logger.info(f"Parsed {len(events_data)} events from {path.name} (Year: {file_year})")
    return events_data


def merge_cti_events(
    parsed_files: List[Dict[Tuple[int, int], Dict[str, Any]]]
) -> List[NormalizedCTIEvent]:
    """
    Merges multiple parsed file event dictionaries by COMPOSITE KEY: (year, event_id).
    - Merges file pairs within the same year (e.g. 2019 MalwareEvent + ReportEvent)
    - Prevents cross-year ID collisions (2013 Event 1976 stays distinct from 2019 Event 1976)
    - Creates composite ID: f"{year}_{event_id}"
    """
    merged_events: Dict[Tuple[int, int], Dict[str, Any]] = {}

    for file_data in parsed_files:
        for composite_key, event_dict in file_data.items():
            year, event_id = composite_key

            if composite_key not in merged_events:
                merged_events[composite_key] = {
                    "id": f"{year}_{event_id}",
                    "year": year,
                    "event_id": event_id,
                    "date": event_dict["date"],
                    "info_title": event_dict["info"],
                    "iocs_map": {},  # (type, value) -> IOC
                    "source_files": set(),
                }

            current_info = merged_events[composite_key]["info_title"]
            new_info = event_dict.get("info", "")
            new_date = event_dict.get("date")

            if new_info:
                if not current_info:
                    merged_events[composite_key]["info_title"] = new_info
                    if new_date and new_date != date(1970, 1, 1):
                        merged_events[composite_key]["date"] = new_date
                elif len(new_info) > len(current_info) or (" " in new_info and " " not in current_info):
                    # Prefer human-readable / narrative descriptive title and its associated date
                    merged_events[composite_key]["info_title"] = new_info
                    if new_date and new_date != date(1970, 1, 1):
                        merged_events[composite_key]["date"] = new_date

            # Track source files
            if event_dict.get("source_file"):
                merged_events[composite_key]["source_files"].add(event_dict["source_file"])

            # Merge attributes deduplicated by (type, value)
            for ioc in event_dict.get("attributes", []):
                key = (ioc.type.lower(), ioc.value.strip())
                if key not in merged_events[composite_key]["iocs_map"]:
                    merged_events[composite_key]["iocs_map"][key] = ioc
                else:
                    existing = merged_events[composite_key]["iocs_map"][key]
                    if not existing.comment and ioc.comment:
                        merged_events[composite_key]["iocs_map"][key] = ioc

    normalized_events: List[NormalizedCTIEvent] = []
    for composite_key, event_data in merged_events.items():
        iocs_list = list(event_data["iocs_map"].values())
        source_files_list = sorted(list(event_data["source_files"]))
        normalized_events.append(
            NormalizedCTIEvent(
                id=event_data["id"],
                year=event_data["year"],
                event_id=event_data["event_id"],
                date=event_data["date"],
                info_title=event_data["info_title"],
                iocs=iocs_list,
                source_files=source_files_list,
            )
        )

    logger.info(f"Merged into {len(normalized_events)} composite-keyed NormalizedCTIEvent objects")
    return normalized_events
