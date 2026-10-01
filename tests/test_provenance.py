"""
Unit and Attack Tests for Provenance Engine (Gate E)
"""

import unittest
from PIL import Image
import numpy as np

from visionguard.core.crypto import KeyPair
from visionguard.core.schemas import DispositionEnum
from visionguard.modules.provenance.chain import InferenceChain, ChainVerifier
from visionguard.modules.provenance.watermark import Watermarker, WatermarkPolicy
from visionguard.modules.provenance.sidecar import ProvenanceSidecarGenerator


class TestProvenanceEngine(unittest.TestCase):
    def setUp(self):
        self.chain = InferenceChain(chain_id="CHAIN-TEST-001")
        self.model_digest = "a" * 64

        # Build a valid 5-record chain
        for i in range(5):
            self.chain.append_record(
                input_data=f"input_image_bytes_{i}",
                model_digest=self.model_digest,
                output={"predicted_class": i, "confidence": 0.95}
            )
        self.checkpoint = self.chain.create_head_checkpoint()

    def test_valid_chain_verification(self):
        result, findings = ChainVerifier.verify(
            records=self.chain.records,
            checkpoint=self.checkpoint,
            public_key_hex=self.chain.public_key_hex
        )
        self.assertTrue(result.chain_valid)
        self.assertEqual(result.overall_disposition, DispositionEnum.ACCEPT)
        self.assertEqual(len(result.tampered_records), 0)

    def test_output_modification_attack(self):
        # Adversary modifies the predicted output of record 2
        tampered_records = [r.model_copy(deep=True) for r in self.chain.records]
        tampered_records[2].output = {"predicted_class": 999, "confidence": 0.99}  # Modified!

        result, findings = ChainVerifier.verify(
            records=tampered_records,
            checkpoint=self.checkpoint,
            public_key_hex=self.chain.public_key_hex
        )
        self.assertFalse(result.chain_valid)
        self.assertEqual(result.overall_disposition, DispositionEnum.QUARANTINE)
        self.assertIn(2, result.tampered_records)

    def test_replay_and_reordering_attack(self):
        # Adversary swaps record 1 and record 2
        tampered_records = [r.model_copy(deep=True) for r in self.chain.records]
        tampered_records[1], tampered_records[2] = tampered_records[2], tampered_records[1]

        result, findings = ChainVerifier.verify(
            records=tampered_records,
            checkpoint=self.checkpoint,
            public_key_hex=self.chain.public_key_hex
        )
        self.assertFalse(result.chain_valid)
        self.assertEqual(result.overall_disposition, DispositionEnum.QUARANTINE)
        self.assertTrue(len(result.broken_links) > 0 or len(result.replay_records) > 0)

    def test_broken_chain_deletion_attack(self):
        # Adversary deletes record 2 from the middle of the chain
        tampered_records = [self.chain.records[0], self.chain.records[1], self.chain.records[3], self.chain.records[4]]

        result, findings = ChainVerifier.verify(
            records=tampered_records,
            checkpoint=self.checkpoint,
            public_key_hex=self.chain.public_key_hex
        )
        self.assertFalse(result.chain_valid)
        self.assertEqual(result.overall_disposition, DispositionEnum.QUARANTINE)

    def test_watermark_invisible_lsb_roundtrip(self):
        img = Image.new("RGB", (100, 100), color=(100, 150, 200))
        watermarker = Watermarker(policy=WatermarkPolicy.INVISIBLE)
        record_id = "REC-INVIS-TEST-007"

        wm_img = watermarker.apply(img, record_id=record_id)
        extracted = Watermarker.extract_invisible_lsb(wm_img)
        self.assertEqual(extracted, record_id)

    def test_c2pa_inspired_sidecar(self):
        rec = self.chain.records[0]
        sidecar = ProvenanceSidecarGenerator.generate(rec, self.chain.keypair)
        self.assertEqual(sidecar["format"], "VisionGuard-C2PA-Inspired-Sidecar")
        self.assertIn("signature_hex", sidecar)
        self.assertIn("sidecar_digest", sidecar)
        self.assertIn("C2PA-inspired", sidecar["disclaimer"])


if __name__ == "__main__":
    unittest.main()
