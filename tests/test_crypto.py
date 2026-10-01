"""
Unit and Attack Tests for Cryptographic Engine and Schemas (Standard Unittest)
"""

import unittest
import json
from PIL import Image, ImageDraw
import numpy as np

from visionguard.core.crypto import (
    KeyPair,
    verify_signature,
    sha256_bytes,
    sha256_text,
    canonical_json_hash,
    compute_phash,
    phash_hamming_distance,
    compute_merkle_root,
    compute_record_hash
)
from visionguard.core.schemas import (
    Finding,
    ModuleEnum,
    SeverityEnum,
    DispositionEnum
)


class TestCryptoAndSchemas(unittest.TestCase):
    def test_ed25519_sign_and_verify(self):
        kp = KeyPair.generate()
        msg = "VisionGuard Air-Gapped Test Vector"
        sig = kp.sign(msg)
        
        # Valid verification
        self.assertTrue(verify_signature(kp.public_key_hex, msg, sig))
        
        # Tampered message must fail
        self.assertFalse(verify_signature(kp.public_key_hex, msg + "_TAMPERED", sig))
        
        # Invalid public key must fail gracefully
        other_kp = KeyPair.generate()
        self.assertFalse(verify_signature(other_kp.public_key_hex, msg, sig))
        
        # Malformed signature must fail gracefully
        self.assertFalse(verify_signature(kp.public_key_hex, msg, "bad_hex_123"))

    def test_canonical_json_hash(self):
        data1 = {"b": 2, "a": 1, "c": [1, 2, 3]}
        data2 = {"a": 1, "c": [1, 2, 3], "b": 2}
        
        s1, h1 = canonical_json_hash(data1)
        s2, h2 = canonical_json_hash(data2)
        
        self.assertEqual(s1, s2)
        self.assertEqual(h1, h2)

    def test_phash_near_duplicate(self):
        img = Image.new("RGB", (100, 100), color=(120, 150, 180))
        draw = ImageDraw.Draw(img)
        draw.rectangle([20, 20, 60, 60], fill=(240, 50, 50))
        
        h1 = compute_phash(img)
        
        # Slightly perturbed image
        img_slight = img.point(lambda p: min(255, int(p * 1.02)))
        h2 = compute_phash(img_slight)
        
        dist = phash_hamming_distance(h1, h2)
        self.assertLessEqual(dist, 5, f"Near-duplicate pHash distance {dist} should be <=5")
        
        # Completely distinct image
        img_diff = Image.new("RGB", (100, 100), color=(0, 0, 0))
        draw_diff = ImageDraw.Draw(img_diff)
        draw_diff.ellipse([10, 10, 90, 90], fill=(255, 255, 255))
        h3 = compute_phash(img_diff)
        
        dist_diff = phash_hamming_distance(h1, h3)
        self.assertGreater(dist_diff, 10, f"Different images pHash distance {dist_diff} should be large")

    def test_merkle_root(self):
        hashes = [sha256_text(f"record_{i}") for i in range(5)]
        root = compute_merkle_root(hashes)
        self.assertEqual(len(root), 64)
        
        # Altering one hash must alter root
        tampered_hashes = list(hashes)
        tampered_hashes[2] = sha256_text("tampered")
        tampered_root = compute_merkle_root(tampered_hashes)
        self.assertNotEqual(root, tampered_root)

    def test_finding_schema_validation(self):
        f = Finding(
            finding_id="FIND-TEST-001",
            module=ModuleEnum.DATA_SENTINEL,
            asset="sample_001.jpg",
            reason="Exact duplicate hash detected",
            evidence={"sha256": "abc123"},
            severity=SeverityEnum.HIGH,
            confidence=0.99,
            disposition=DispositionEnum.QUARANTINE,
            recommended_action="Remove duplicate asset from batch",
            timestamp="2026-09-30T12:00:00Z"
        )
        self.assertEqual(f.disposition, DispositionEnum.QUARANTINE)
        self.assertEqual(f.confidence, 0.99)


if __name__ == "__main__":
    unittest.main()
