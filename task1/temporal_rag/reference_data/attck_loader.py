"""ATT&CK Reference Data Loader.

Loads MITRE ATT&CK technique IDs, software IDs, and group mappings from
attackmitre.xlsx to evaluate semantic similarity against ATT&CK taxonomy.
"""

import difflib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set

import openpyxl
import pandas as pd

from config.settings import ATTCK_XLSX_PATH

logger = logging.getLogger("attck_loader")
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Standard Enterprise MITRE ATT&CK Tactics
STANDARD_TACTICS: List[str] = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
    "Resource Development",
    "Reconnaissance",
]

STANDARD_TACTIC_IDS: List[str] = [
    "TA0001",
    "TA0002",
    "TA0003",
    "TA0004",
    "TA0005",
    "TA0006",
    "TA0007",
    "TA0008",
    "TA0009",
    "TA0010",
    "TA0011",
    "TA0040",
    "TA0042",
    "TA0043",
]


class ATTCKLoader:
    """Singleton loader and fuzzy matching engine for ATT&CK reference data."""

    _instance: Optional["ATTCKLoader"] = None

    def __init__(self, xlsx_path: Optional[Path] = None):
        self.xlsx_path = Path(xlsx_path) if xlsx_path else ATTCK_XLSX_PATH
        self.techniques: Set[str] = set()
        self.groups: Set[str] = set()
        self.softwares: Set[str] = set()
        self.tactics: Set[str] = set(STANDARD_TACTICS)
        self.all_reference_terms: Set[str] = set()
        self.all_reference_terms_lower: Dict[str, str] = {}
        self.column_names: List[str] = []
        self._loaded: bool = False

        self.load_reference_data()

    def load_reference_data(self) -> None:
        """Load and parse attackmitre.xlsx dataset."""
        if not self.xlsx_path.exists():
            logger.warning(
                f"ATT&CK Excel file not found at {self.xlsx_path}. Operating with standard tactics only."
            )
            self._build_index()
            return

        try:
            df = pd.read_excel(self.xlsx_path)
            self.column_names = df.columns.tolist()
            logger.info(f"Loaded ATT&CK dataset from {self.xlsx_path}")
            logger.info(f"ATT&CK Excel Columns: {self.column_names}")

            # Extract Groups
            if "APT Group Name" in df.columns:
                for grp in df["APT Group Name"].dropna().astype(str):
                    grp_clean = grp.strip()
                    if grp_clean:
                        self.groups.add(grp_clean)

            # Extract Software IDs
            if "Software ID" in df.columns:
                for sw in df["Software ID"].dropna().astype(str):
                    sw_clean = sw.strip()
                    if sw_clean:
                        self.softwares.add(sw_clean)

            # Extract Techniques
            for col in ["Group Techniques", "Software Techniques"]:
                if col in df.columns:
                    for val in df[col].dropna().astype(str):
                        for t in val.split(";"):
                            t_clean = t.strip()
                            if t_clean:
                                self.techniques.add(t_clean)

            # Tactics
            for tac in STANDARD_TACTICS + STANDARD_TACTIC_IDS:
                self.tactics.add(tac)

            self._build_index()
            self._loaded = True
            logger.info(
                f"ATT&CK Reference Summary: {len(self.techniques)} techniques, "
                f"{len(self.groups)} APT groups, {len(self.softwares)} software IDs, "
                f"{len(self.tactics)} tactics indexed."
            )

        except Exception as e:
            logger.error(f"Failed to load ATT&CK Excel file: {e}")
            self._build_index()

    def _build_index(self) -> None:
        """Build combined lookup indexes for fast matching."""
        self.all_reference_terms = (
            self.techniques | self.tactics | self.groups | self.softwares
        )
        self.all_reference_terms_lower = {
            t.lower(): t for t in self.all_reference_terms
        }

    def match_attck(self, entity_name: str) -> float:
        """Compute fuzzy similarity score for an entity against the ATT&CK taxonomy.

        Returns:
            1.0 if match score >= 80
            0.5 if partial match score in [60, 79]
            0.0 if no match (< 60)
        """
        if not entity_name or not isinstance(entity_name, str):
            return 0.0

        clean_name = entity_name.strip()
        if not clean_name:
            return 0.0

        clean_lower = clean_name.lower()

        # Exact match (Case-insensitive)
        if clean_lower in self.all_reference_terms_lower:
            return 1.0

        # Direct token check (e.g. "T1059" or "Initial Access" inside phrase)
        for ref_lower in self.all_reference_terms_lower:
            if ref_lower == clean_lower:
                return 1.0
            # Direct ID match
            if ref_lower.startswith("t1") and ref_lower in clean_lower:
                return 1.0

        # Fuzzy string similarity matching
        best_ratio = 0.0
        for ref_term in self.all_reference_terms:
            ratio = difflib.SequenceMatcher(
                None, clean_lower, ref_term.lower()
            ).ratio() * 100.0
            if ratio > best_ratio:
                best_ratio = ratio
                if best_ratio >= 80.0:
                    break

        if best_ratio >= 80.0:
            return 1.0
        elif best_ratio >= 60.0:
            return 0.5
        else:
            return 0.0


_global_loader: Optional[ATTCKLoader] = None


def get_attck_loader(xlsx_path: Optional[Path] = None) -> ATTCKLoader:
    """Get or create singleton ATTCKLoader instance."""
    global _global_loader
    if _global_loader is None or (
        xlsx_path and _global_loader.xlsx_path != xlsx_path
    ):
        _global_loader = ATTCKLoader(xlsx_path=xlsx_path)
    return _global_loader
