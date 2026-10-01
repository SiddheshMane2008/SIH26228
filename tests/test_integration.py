"""
Integration and End-to-End Gauntlet Tests for VisionGuard Master Engine
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from PIL import Image
import torch
import torch.nn as nn

from visionguard.core.schemas import DispositionEnum
from visionguard.engine import VisionGuardEngine
from visionguard.modules.governance.passport import verify_trust_passport
from visionguard.modules.governance.json_schema import export_all_schemas
from visionguard.modules.provenance.chain import InferenceChain


class DummyNet(nn.Module):
    def __init__(self):
        super().__init__()
        self.fc = nn.Linear(3 * 224 * 224, 2)
    def forward(self, x):
        return self.fc(torch.flatten(x, 1))


class TestVisionGuardIntegration(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="vg_integ_"))
        self.engine = VisionGuardEngine()
        self.engine.output_dir = self.test_dir

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)

    def test_full_lifecycle_audit_and_passport_verification(self):
        # 1. Synthetic Dataset
        ds_dir = self.test_dir / "dataset"
        class_0 = ds_dir / "class_0"
        class_0.mkdir(parents=True)
        for i in range(5):
            img = Image.new("RGB", (64, 64), color=(100 + i * 20, 50, 50))
            img.save(class_0 / f"img_{i}.png")

        # 2. Synthetic Model
        model = DummyNet()

        # 3. Synthetic Inference Chain
        chain = InferenceChain("INTEG-CHAIN", keypair=self.engine.keypair)
        for i in range(3):
            chain.append_record(f"input_{i}", model_digest="d" * 64, output={"score": 0.9})
        checkpoint = chain.create_head_checkpoint()

        # 4. Baseline & Eval images for shift
        base_imgs = [Image.new("RGB", (64, 64), color=(120, 120, 120)) for _ in range(5)]
        eval_imgs = [Image.new("RGB", (64, 64), color=(122, 118, 121)) for _ in range(5)]

        # 5. Blast Radius Registration
        self.engine.blast_graph.register_lineage(
            contributor_id="Contrib_A",
            batch_id="Batch_01",
            dataset_id="dataset",
            model_id="DummyNet",
            inference_record_ids=["REC-001"]
        )

        # Run full lifecycle audit
        results = self.engine.run_full_audit(
            dataset_path=ds_dir,
            model_or_path=model,
            inference_records=chain.records,
            head_checkpoint=checkpoint,
            baseline_images=base_imgs,
            operational_images=eval_imgs,
            target_contributor_trace="Contrib_A",
            generate_html_report=True
        )

        passport = results["trust_passport"]
        self.assertIsNotNone(passport)

        # Verify cryptographic authenticity of Trust Passport
        valid, msg = verify_trust_passport(passport)
        self.assertTrue(valid, f"Passport verification failed: {msg}")

        # Check HTML report was generated
        report_path = Path(results["html_report_path"])
        self.assertTrue(report_path.is_file())
        with open(report_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("VisionGuard", content)
        self.assertIn(passport.passport_id, content)

    def test_json_schema_export(self):
        schema_dir = self.test_dir / "schemas"
        schemas = export_all_schemas(schema_dir)
        self.assertIn("trust_passport.schema.json", schemas)
        self.assertIn("finding.schema.json", schemas)
        self.assertTrue((schema_dir / "trust_passport.schema.json").is_file())


if __name__ == "__main__":
    unittest.main()
