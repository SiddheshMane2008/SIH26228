"""
Automated Validation Suite on Real Computer Vision Datasets & Models
Validates Data Sentinel, Model Auditor, Provenance Engine, Shift Diagnostician,
and Trust Passport against genuine real-world public images (COCO) and pretrained models.
"""

import unittest
from pathlib import Path
from PIL import Image
import numpy as np

from visionguard.core.schemas import DispositionEnum, TrustPassport
from visionguard.engine import VisionGuardEngine
from visionguard.core.config import VisionGuardConfig
from visionguard.modules.governance.passport import verify_trust_passport
from visionguard.real_assets_builder import build_real_assets


class TestRealDataValidation(unittest.TestCase):
    """Rigorous validation against real public CV images and models."""

    @classmethod
    def setUpClass(cls):
        cls.base_dir = Path("real_assets/benchmark")
        cls.assets = build_real_assets(cls.base_dir)
        cls.config = VisionGuardConfig(output_dir="runs")
        cls.engine = VisionGuardEngine(config=cls.config)

    def test_real_clean_dataset_baseline(self):
        clean_ds = self.assets["clean_real_dataset"]
        res = self.engine.run_full_audit(dataset_path=clean_ds)
        passport: TrustPassport = res["trust_passport"]
        self.assertIn(passport.overall_disposition, (DispositionEnum.ACCEPT, DispositionEnum.REVIEW))
        self.assertGreater(res["data_sentinel"].total_samples, 5)

    def test_real_label_flipping_detection(self):
        flip_ds = self.assets["poisoned_label_flip"]
        known_flips = set(self.assets.get("ground_truth_flips", []))
        res = self.engine.run_full_audit(dataset_path=flip_ds)
        ds = res["data_sentinel"]
        flagged_flips = {f.asset for f in ds.findings if "LABEL-FLIP" in f.finding_id or "MISLABEL" in f.reason.upper()}
        # Verify that at least one of the known injected label flips was flagged
        overlap = known_flips.intersection(flagged_flips)
        self.assertGreater(len(overlap), 0, f"Expected injected flips {known_flips} to be detected, found {flagged_flips}")

    def test_real_duplicate_flooding_detection(self):
        dup_ds = self.assets["poisoned_duplicate_flood"]
        res = self.engine.run_full_audit(dataset_path=dup_ds)
        ds = res["data_sentinel"]
        self.assertGreaterEqual(ds.exact_duplicates_count + ds.near_duplicates_count, 1)
        self.assertEqual(res["trust_passport"].overall_disposition, DispositionEnum.QUARANTINE)

    def test_real_ood_insertion_detection(self):
        ood_ds = self.assets["poisoned_ood_insertion"]
        res = self.engine.run_full_audit(dataset_path=ood_ds)
        ds = res["data_sentinel"]
        self.assertGreaterEqual(ds.ood_samples_count, 1)

    def test_real_trigger_patch_detection(self):
        trig_ds = self.assets["poisoned_trigger_patch"]
        res = self.engine.run_full_audit(dataset_path=trig_ds)
        ds = res["data_sentinel"]
        self.assertGreaterEqual(ds.trigger_anomalies_count, 2)
        self.assertEqual(res["trust_passport"].overall_disposition, DispositionEnum.QUARANTINE)

    def test_real_model_substitution_detection(self):
        reg_model_path = self.assets["registered_model_pt"]
        sub_model_path = self.assets["substituted_model_pt"]

        reg_model_res = self.engine.model_auditor.audit(reg_model_path)
        reg_fp = {
            "fingerprint_hash": reg_model_res.evidence_summary["fingerprint_hash"],
            "outputs": reg_model_res.evidence_summary.get("outputs", [])
        }

        res = self.engine.run_full_audit(
            model_or_path=sub_model_path,
            registered_model_fingerprint=reg_fp
        )
        ma = res["model_auditor"]
        self.assertEqual(ma.overall_disposition, DispositionEnum.QUARANTINE)
        has_sub_finding = any("SUBSTITUTION" in f.finding_id or "FINGERPRINT" in f.reason.upper() for f in ma.findings)
        self.assertTrue(has_sub_finding)

    def test_real_provenance_tampering_detection(self):
        tampered_chain = self.assets["tampered_chain"]
        clean_cp = self.assets["head_checkpoint"]
        kp = self.assets["provenance_keypair"]

        pe_res = self.engine.provenance_auditor.audit(
            records=tampered_chain.records,
            checkpoint=clean_cp,
            public_key_hex=kp.public_key_hex
        )
        self.assertEqual(pe_res.overall_disposition, DispositionEnum.QUARANTINE)
        self.assertGreater(len(pe_res.findings), 0)

    def test_real_distribution_shift_detection(self):
        base_imgs = sorted(list(self.assets["shift_baseline"].iterdir()))
        op_imgs = sorted(list(self.assets["shift_operational"].iterdir()))

        sd_res = self.engine.shift_diagnostician.audit(base_imgs, op_imgs)
        self.assertIn(sd_res.overall_disposition, (DispositionEnum.REVIEW, DispositionEnum.QUARANTINE))
        self.assertGreater(sd_res.composite_risk_score, 0.20)

    def test_real_trust_passport_generation_and_tampering(self):
        clean_ds = self.assets["clean_real_dataset"]
        res = self.engine.run_full_audit(dataset_path=clean_ds, generate_html_report=True)
        passport: TrustPassport = res["trust_passport"]

        # Valid passport must verify
        is_valid, msg = verify_trust_passport(passport)
        self.assertTrue(is_valid, f"Passport should be valid: {msg}")

        # Deliberately modify finding list in passport
        tampered_passport = passport.model_copy(deep=True)
        tampered_passport.overall_confidence = 0.05
        is_valid_tampered, _ = verify_trust_passport(tampered_passport)
        self.assertFalse(is_valid_tampered, "Tampered passport should fail signature verification")


if __name__ == "__main__":
    unittest.main()
