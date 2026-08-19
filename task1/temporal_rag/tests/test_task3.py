"""Unit and Integration Tests for Phase 3: Task 3 Trust Scoring & Temporal Verification."""

import datetime
import unittest

from config.settings import (
    SOURCE_RELIABILITY,
    TRUST_ALPHA,
    TRUST_BETA,
    TRUST_DELTA,
    TRUST_EPSILON,
    TRUST_GAMMA,
    TRUST_LAMBDA,
    TRUST_THRESHOLD,
)
from reference_data.attck_loader import ATTCKLoader, get_attck_loader
from tasks.task3_trust import (
    calculate_trust_score,
    compute_attck_similarity,
    compute_contradiction_penalty,
    compute_cross_source_support,
    compute_llm_confidence,
    compute_source_reliability,
    compute_temporal_consistency,
    TrustScoringPipeline,
)


class TestTask3TrustScoring(unittest.TestCase):
    """Test suite for Task 3 trust formula, sub-scores, and ATT&CK matching."""

    @classmethod
    def setUpClass(cls):
        cls.attck_loader = get_attck_loader()

    def test_llm_confidence_subscore(self):
        """Test s1: LLM Confidence parsing and clamping."""
        self.assertEqual(compute_llm_confidence(0.85), 0.85)
        self.assertEqual(compute_llm_confidence(1.0), 1.0)
        self.assertEqual(compute_llm_confidence(0.0), 0.0)
        self.assertEqual(compute_llm_confidence(None, default=1.0), 1.0)
        self.assertEqual(compute_llm_confidence(1.5), 1.0)  # clamped
        self.assertEqual(compute_llm_confidence(-0.2), 0.0)  # clamped

    def test_source_reliability_subscore(self):
        """Test s2: Source classification and reliability lookup."""
        # CVE authoritative source
        self.assertEqual(compute_source_reliability("CVE-2021-44228"), 0.90)

        # MISP IOC source
        self.assertEqual(
            compute_source_reliability(
                "2018_1976", head_type="IOC", rel_type="HAS_HASH"
            ),
            0.65,
        )
        self.assertEqual(
            compute_source_reliability(
                "2019_100", head_type="IOC", rel_type="COMMUNICATES_WITH"
            ),
            0.65,
        )

        # CTI Report narrative source
        self.assertEqual(
            compute_source_reliability(
                "2018_1976", head_type="ThreatActor", rel_type="USES"
            ),
            0.80,
        )
        self.assertEqual(
            compute_source_reliability(
                "2017_500", head_type="Malware", rel_type="EXPLOITS"
            ),
            0.80,
        )

        # Unknown fallback
        self.assertEqual(compute_source_reliability(""), 0.50)
        self.assertEqual(compute_source_reliability("unknown_feed"), 0.50)

    def test_attck_similarity_subscore(self):
        """Test s3: ATT&CK taxonomy matching and relation semantics."""
        # Direct technique matching
        score_tech = compute_attck_similarity(
            head_name="T1059",
            head_type="AttackTechnique",
            tail_name="Command Execution",
            tail_type="Product",
            rel_type="USES",
            attck_loader=self.attck_loader,
        )
        self.assertEqual(score_tech, 1.0)

        # Direct tactic matching
        score_tactic = compute_attck_similarity(
            head_name="APT28",
            head_type="ThreatActor",
            tail_name="Initial Access",
            tail_type="ATT&CKTactic",
            rel_type="BELONGS_TO_TACTIC",
            attck_loader=self.attck_loader,
        )
        self.assertEqual(score_tactic, 1.0)

        # Non-matching technique name
        score_nomatch = compute_attck_similarity(
            head_name="NonExistentFakeTechnique9999",
            head_type="AttackTechnique",
            tail_name="ToolXYZ",
            tail_type="Tool",
            rel_type="USES",
            attck_loader=self.attck_loader,
        )
        self.assertEqual(score_nomatch, 0.0)

        # Tactic / Technique structural relations
        self.assertEqual(
            compute_attck_similarity(
                "T1059", "Unknown", "TA0002", "Unknown", "BELONGS_TO_TACTIC", self.attck_loader
            ),
            0.9,
        )

        # IOC-only relations
        self.assertEqual(
            compute_attck_similarity(
                "malware.exe", "IOC", "d41d8cd98f00b204e9800998ecf8427e", "IOC", "HAS_HASH", self.attck_loader
            ),
            0.3,
        )

        # General semantic relations
        self.assertEqual(
            compute_attck_similarity(
                "APT28", "ThreatActor", "TargetGov", "Target", "TARGETS", self.attck_loader
            ),
            0.5,
        )

    def test_cross_source_support_subscore(self):
        """Test s4: Cross-source corroboration levels."""
        self.assertEqual(compute_cross_source_support(1), 0.3)
        self.assertEqual(compute_cross_source_support(2), 0.6)
        self.assertEqual(compute_cross_source_support(3), 1.0)
        self.assertEqual(compute_cross_source_support(10), 1.0)

    def test_temporal_consistency_subscore(self):
        """Test s5: Timeline alignment and drift penalties."""
        # Null tau
        self.assertEqual(
            compute_temporal_consistency(None, "IOC", None, None), 0.5
        )

        # Single-event IOC matching date
        d1 = datetime.date(2018, 5, 20)
        self.assertEqual(
            compute_temporal_consistency(d1, "IOC", d1, d1), 1.0
        )
        # Single-event IOC mismatching date
        d2 = datetime.date(2019, 5, 20)
        self.assertEqual(
            compute_temporal_consistency(d2, "IOC", d1, d1), 0.5
        )

        # Entity timeline: within bounds
        first_seen = datetime.date(2016, 1, 1)
        last_seen = datetime.date(2018, 1, 1)
        tau_inside = datetime.date(2017, 6, 1)
        self.assertEqual(
            compute_temporal_consistency(
                tau_inside, "ThreatActor", first_seen, last_seen
            ),
            1.0,
        )

        # Within 1-year grace period of last_seen
        tau_grace = datetime.date(2018, 6, 1)
        self.assertEqual(
            compute_temporal_consistency(
                tau_grace, "ThreatActor", first_seen, last_seen
            ),
            1.0,
        )

        # Drift <= 180 days beyond grace period
        tau_minor_drift = datetime.date(2019, 3, 1)
        self.assertEqual(
            compute_temporal_consistency(
                tau_minor_drift, "ThreatActor", first_seen, last_seen
            ),
            0.7,
        )

        # Drift > 180 days beyond grace period
        tau_major_drift = datetime.date(2021, 1, 1)
        self.assertEqual(
            compute_temporal_consistency(
                tau_major_drift, "ThreatActor", first_seen, last_seen
            ),
            0.3,
        )

    def test_contradiction_penalty_subscore(self):
        """Test s6: Contradiction detection penalty."""
        self.assertEqual(compute_contradiction_penalty(False), 0.0)
        self.assertEqual(compute_contradiction_penalty(True), 0.5)

    def test_trust_formula_combination_math(self):
        """Test exact mathematical combination and thresholding."""
        # Case 1: High trust across all factors
        # 0.20*1.0 + 0.20*0.80 + 0.20*1.0 + 0.20*0.60 + 0.20*1.0 - 0.10*0.0 = 0.88
        trust, trusted = calculate_trust_score(
            s1=1.0, s2=0.80, s3=1.0, s4=0.60, s5=1.0, s6=0.0
        )
        self.assertAlmostEqual(trust, 0.88, places=4)
        self.assertTrue(trusted)

        # Case 2: Contradiction applied
        # 0.88 - 0.10*0.5 = 0.88 - 0.05 = 0.83
        trust_c, trusted_c = calculate_trust_score(
            s1=1.0, s2=0.80, s3=1.0, s4=0.60, s5=1.0, s6=0.5
        )
        self.assertAlmostEqual(trust_c, 0.83, places=4)
        self.assertTrue(trusted_c)

        # Case 3: Standard IOC triple (untrusted under strict 0.80 threshold)
        # s1=1.0, s2=0.65 (MISP_IOC), s3=0.30 (IOC rel), s4=0.30 (1 src), s5=1.0, s6=0.0
        # Trust = 0.20(1.0 + 0.65 + 0.30 + 0.30 + 1.0) = 0.20 * 3.25 = 0.65
        trust_ioc, trusted_ioc = calculate_trust_score(
            s1=1.0, s2=0.65, s3=0.30, s4=0.30, s5=1.0, s6=0.0
        )
        self.assertAlmostEqual(trust_ioc, 0.65, places=4)
        self.assertFalse(trusted_ioc)

        # Case 4: High-corroborated CVE triple (trusted)
        # s1=1.0, s2=0.90 (CVE), s3=0.50, s4=1.0 (3+ src), s5=1.0, s6=0.0
        # Trust = 0.20(1.0 + 0.90 + 0.50 + 1.0 + 1.0) = 0.20 * 4.40 = 0.88
        trust_cve, trusted_cve = calculate_trust_score(
            s1=1.0, s2=0.90, s3=0.50, s4=1.0, s5=1.0, s6=0.0
        )
        self.assertAlmostEqual(trust_cve, 0.88, places=4)
        self.assertTrue(trusted_cve)


if __name__ == "__main__":
    unittest.main()
