"""
Unit and Attack Tests for Model Auditor (Gate D)
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path
import numpy as np
import torch
import torch.nn as nn

from visionguard.core.schemas import AccessLevelEnum, DispositionEnum
from visionguard.modules.model_auditor.auditor import ModelAuditor


class SimpleTestCNN(nn.Module):
    """Deterministic lightweight CNN for testing."""
    def __init__(self, num_classes=10):
        super().__init__()
        self.conv1 = nn.Conv2d(3, 16, kernel_size=3, padding=1)
        self.relu = nn.ReLU()
        self.pool = nn.AdaptiveAvgPool2d((1, 1))
        self.fc = nn.Linear(16, num_classes)

    def forward(self, x):
        x = self.relu(self.conv1(x))
        x = self.pool(x)
        x = torch.flatten(x, 1)
        return self.fc(x)


class TestModelAuditor(unittest.TestCase):
    def setUp(self):
        torch.manual_seed(42)
        self.test_dir = tempfile.mkdtemp(prefix="vg_test_ma_")
        self.auditor = ModelAuditor()

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_clean_model_whitebox_audit(self):
        model = SimpleTestCNN()
        result = self.auditor.audit(model, model_name="Clean_CNN")

        self.assertEqual(result.access_level, AccessLevelEnum.WHITE_BOX)
        self.assertIsNotNone(result.weight_digest)
        self.assertIsNotNone(result.graph_hash)
        self.assertIsNotNone(result.parameter_stats)
        self.assertEqual(result.overall_disposition, DispositionEnum.ACCEPT)
        self.assertTrue(len(result.limitations) > 0)

    def test_model_substitution_detection(self):
        model_v1 = SimpleTestCNN()
        # Audit v1 to get baseline fingerprint
        res_v1 = self.auditor.audit(model_v1, model_name="CNN_v1")
        reg_fingerprint = {
            "fingerprint_hash": res_v1.evidence_summary["fingerprint_hash"],
            "outputs": res_v1.evidence_summary.get("outputs", [])
        }

        # Model v2 with altered weights (different seed)
        torch.manual_seed(999)
        model_v2 = SimpleTestCNN()

        # Audit v2 against v1's registered fingerprint
        res_v2 = self.auditor.audit(model_v2, model_name="CNN_v2", registered_fingerprint=reg_fingerprint)
        
        # Mismatch must be detected
        self.assertIn(res_v2.overall_disposition, (DispositionEnum.QUARANTINE, DispositionEnum.REVIEW))
        sub_findings = [f for f in res_v2.findings if "SUBSTITUTION" in f.finding_id or "MISMATCH" in f.finding_id]
        self.assertGreaterEqual(len(sub_findings), 1)

    def test_nan_weight_corruption_detection(self):
        model = SimpleTestCNN()
        # Inject NaN into a weight tensor
        with torch.no_grad():
            model.fc.weight[0, 0] = float("nan")

        result = self.auditor.audit(model, model_name="Corrupt_CNN")
        self.assertEqual(result.overall_disposition, DispositionEnum.QUARANTINE)
        nan_findings = [f for f in result.findings if "NANINF" in f.finding_id]
        self.assertEqual(len(nan_findings), 1)

    def test_graceful_handling_missing_model(self):
        fake_path = Path(self.test_dir) / "non_existent_model.onnx"
        result = self.auditor.audit(fake_path, model_name="Missing_Model")

        # Must NOT crash! Must record required phrase.
        self.assertEqual(result.access_level, AccessLevelEnum.UNAVAILABLE)
        self.assertIn("Assessment unavailable", result.findings[0].reason)
        self.assertIn("Assessment unavailable", result.limitations[0])


if __name__ == "__main__":
    unittest.main()
