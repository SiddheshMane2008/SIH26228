"""
Automated Integration Tests for VisionGuard Upload API Endpoints
Verifies:
  - Single image upload (with and without ground truth expected label)
  - Intentionally incorrect expected label (detects LABEL INCONSISTENCY)
  - Corrupt image upload (fails gracefully with FIND-IMG-CORRUPT)
  - Dataset ZIP upload (validates format, computes hashes, audits integrity)
  - Model upload (ONNX model audit, unsupported format rejection)
  - Distribution shift diagnosis upload
"""

import io
import zipfile
import unittest
from pathlib import Path
from PIL import Image
import numpy as np
from fastapi.testclient import TestClient

from visionguard.api.app import app


class TestUploadAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.real_img = Path("real_assets/coco_samples/coco_baseball_bat.jpg")
        if not cls.real_img.is_file():
            # Fallback to create a test image if coco sample not present
            cls.real_img = Path("runs/uploads/test_real_baseball.jpg")
            cls.real_img.parent.mkdir(parents=True, exist_ok=True)
            im = Image.new("RGB", (224, 224), color=(100, 150, 200))
            im.save(cls.real_img)

    def test_image_upload_no_ground_truth(self):
        """Test uploading image without expected label reports GROUND TRUTH UNAVAILABLE honestly."""
        with open(self.real_img, "rb") as f:
            resp = self.client.post(
                "/api/upload/image",
                files={"file": ("test_baseball.jpg", f, "image/jpeg")}
            )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["assurance_status"], "GROUND TRUTH UNAVAILABLE")
        self.assertEqual(data["disposition"], "REVIEW")
        self.assertIn("Ground truth unavailable", data["disclaimer"])
        self.assertIn("sha256", data)
        self.assertIn("phash", data)
        self.assertIn("quality_metrics", data)
        self.assertIn("passport", data)
        self.assertGreater(data["file_size_bytes"], 0)

    def test_image_upload_with_matching_label(self):
        """Test uploading image with matching expected label returns CLEAN."""
        with open(self.real_img, "rb") as f:
            resp = self.client.post(
                "/api/upload/image",
                files={"file": ("test_baseball.jpg", f, "image/jpeg")},
                data={"expected_label": "baseball"}
            )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["assurance_status"], "CLEAN / NO SUSPICIOUS EVIDENCE FOUND")
        self.assertEqual(data["disposition"], "ACCEPT")
        self.assertIn("passport", data)

    def test_image_upload_with_mislabeled_expectation(self):
        """Test uploading baseball image with expected label 'stop sign' flags LABEL INCONSISTENCY."""
        with open(self.real_img, "rb") as f:
            resp = self.client.post(
                "/api/upload/image",
                files={"file": ("test_baseball.jpg", f, "image/jpeg")},
                data={"expected_label": "stop sign"}
            )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["assurance_status"], "LABEL INCONSISTENCY")
        self.assertEqual(data["disposition"], "QUARANTINE")
        findings = data["findings"]
        self.assertTrue(any("MISLABEL" in f["finding_id"] for f in findings))

    def test_corrupt_image_upload_fails_safely(self):
        """Test uploading corrupt image byte content is quarantined without crashing."""
        corrupt_bytes = b"NOT_A_VALID_JPEG_HEADER_CORRUPTED_STREAM_CONTENT_9999"
        resp = self.client.post(
            "/api/upload/image",
            files={"file": ("corrupt.jpg", io.BytesIO(corrupt_bytes), "image/jpeg")}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["assurance_status"], "CORRUPT / UNREADABLE")
        self.assertEqual(data["disposition"], "QUARANTINE")
        self.assertTrue(any("CORRUPT" in f["finding_id"] for f in data["findings"]))

    def test_dataset_zip_upload(self):
        """Test uploading a dataset ZIP archive."""
        # Create in-memory zip dataset
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as zf:
            for i in range(4):
                im = Image.new("RGB", (64, 64), color=(i * 40, i * 40, i * 40))
                ibuf = io.BytesIO()
                im.save(ibuf, format="JPEG")
                zf.writestr(f"class_a/img_{i}.jpg", ibuf.getvalue())
            for i in range(4):
                im = Image.new("RGB", (64, 64), color=(200 - i * 30, 200 - i * 30, 200 - i * 30))
                ibuf = io.BytesIO()
                im.save(ibuf, format="JPEG")
                zf.writestr(f"class_b/img_{i}.jpg", ibuf.getvalue())

        zip_buf.seek(0)
        resp = self.client.post(
            "/api/upload/dataset",
            files={"file": ("test_dataset.zip", zip_buf, "application/zip")}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total_samples"], 8)
        self.assertIn("passport", data)
        self.assertIn("report_url", data)

    def test_model_upload_onnx_and_unsupported(self):
        """Test uploading ONNX model and rejecting unsupported model formats."""
        # 1. Unsupported model extension
        resp = self.client.post(
            "/api/upload/model",
            files={"file": ("invalid_model.txt", io.BytesIO(b"fake_model"), "text/plain")}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "UNSUPPORTED_FORMAT")
        self.assertIn("Assessment unavailable", data["message"])

        # 2. Real ONNX model (if exists)
        onnx_path = Path("mobilenet_v3_small.onnx")
        if onnx_path.is_file():
            with open(onnx_path, "rb") as f:
                resp2 = self.client.post(
                    "/api/upload/model",
                    files={"file": ("mobilenet_v3_small.onnx", f, "application/octet-stream")}
                )
            self.assertEqual(resp2.status_code, 200)
            data2 = resp2.json()
            self.assertIn("weight_sha256", data2)
            self.assertIn("parameter_count", data2)
            self.assertIn("passport", data2)

    def test_shift_diagnose_upload(self):
        """Test uploading baseline vs operational images to shift diagnosis."""
        base_files = []
        op_files = []
        for i in range(3):
            im1 = Image.new("RGB", (64, 64), color=(150, 150, 150))
            b1 = io.BytesIO(); im1.save(b1, format="JPEG"); b1.seek(0)
            base_files.append(("baseline_files", (f"base_{i}.jpg", b1, "image/jpeg")))

            im2 = Image.new("RGB", (64, 64), color=(30, 30, 30))
            b2 = io.BytesIO(); im2.save(b2, format="JPEG"); b2.seek(0)
            op_files.append(("operational_files", (f"op_{i}.jpg", b2, "image/jpeg")))

        resp = self.client.post(
            "/api/shift/diagnose",
            files=base_files + op_files
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["baseline_sample_count"], 3)
        self.assertEqual(data["operational_sample_count"], 3)
        self.assertIn("brightness_psi", data)
        self.assertIn("sharpness_wasserstein", data)
        self.assertIn("passport", data)


if __name__ == "__main__":
    unittest.main()
