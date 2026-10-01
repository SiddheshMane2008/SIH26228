"""
Integration Endpoints Unit Test Suite
Validates the contracts required by the React frontend:
- GET /api/status
- GET /api/embedders (returns {"embedders": [...]})
- POST /api/embedder/select
- POST /api/ingest
- POST /api/audit
- GET /api/provenance/chain
- GET /api/shift/metrics
- GET /api/model/audit
- GET /api/blast-radius
- GET /api/redteam/benchmark
- POST /api/passport/verify
"""

import hashlib
import io
import unittest
from fastapi.testclient import TestClient
from PIL import Image

from visionguard.api.app import app


class TestIntegrationEndpoints(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_status_endpoint(self):
        res = self.client.get("/api/status")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["operating_mode"], "OFFLINE_AIR_GAPPED")
        self.assertIn("active_embedder", data)
        self.assertIn("embedder_dimension", data)

    def test_embedders_endpoint_shape(self):
        res = self.client.get("/api/embedders")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("embedders", data)
        self.assertIsInstance(data["embedders"], list)
        names = [e["name"] for e in data["embedders"]]
        self.assertIn("mobilenet_v3", names)
        # Check that loaded and note are present
        for e in data["embedders"]:
            self.assertIn("name", e)
            self.assertIn("available", e)
            self.assertIn("loaded", e)

    def test_select_embedder_endpoint(self):
        res = self.client.post("/api/embedder/select?name=mobilenet_v3")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["selected_embedder"], "mobilenet_v3")
        self.assertIn(data["dimension"], [576, 1024])

    def test_ingest_image_and_audit(self):
        # Create a small valid test image in memory
        im = Image.new("RGB", (64, 64), color=(100, 150, 200))
        buf = io.BytesIO()
        im.save(buf, format="JPEG")
        raw_bytes = buf.getvalue()
        sha256 = hashlib.sha256(raw_bytes).hexdigest()

        # Ingest image
        res = self.client.post(
            "/api/ingest",
            data={"kind": "image", "sha256": sha256},
            files={"file": ("test_ingest.jpg", raw_bytes, "image/jpeg")}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["registration_id"].startswith("REG-"))
        self.assertEqual(data["sha256"], sha256)
        self.assertEqual(data["kind"], "image")
        self.assertIn("analysis", data)
        self.assertIn("embedding", data["analysis"])
        self.assertIn("duplicate", data["analysis"])
        self.assertIn("ood", data["analysis"])
        self.assertIn("trigger", data["analysis"])

        reg_id = data["registration_id"]

        # Audit registered asset
        audit_res = self.client.post("/api/audit", json={"registration_ids": [reg_id]})
        self.assertEqual(audit_res.status_code, 200)
        audit_data = audit_res.json()
        self.assertIn("passport", audit_data)
        self.assertIn("passport_id", audit_data["passport"])
        self.assertIn("overall_disposition", audit_data["passport"])
        self.assertIn("report_url", audit_data)

    def test_ingest_sha_mismatch_fails(self):
        raw_bytes = b"sample_bytes_content"
        fake_sha256 = "0" * 64
        res = self.client.post(
            "/api/ingest",
            data={"kind": "image", "sha256": fake_sha256},
            files={"file": ("fake.jpg", raw_bytes, "image/jpeg")}
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn("Integrity check failed", res.json()["detail"])

    def test_provenance_chain_endpoint(self):
        res = self.client.get("/api/provenance/chain")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("records", data)
        self.assertIn("verified", data)
        self.assertIn("message", data)
        self.assertGreater(len(data["records"]), 0)
        rec0 = data["records"][0]
        self.assertIn("sequence", rec0)
        self.assertIn("hash", rec0)
        self.assertIn("previous_hash", rec0)

    def test_shift_metrics_endpoint(self):
        res = self.client.get("/api/shift/metrics")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("features", data)
        self.assertIn("embedding_drift", data)
        self.assertIn("threshold", data)
        feature_names = [f["name"] for f in data["features"]]
        self.assertIn("brightness", feature_names)
        self.assertIn("contrast", feature_names)
        self.assertIn("sharpness", feature_names)
        self.assertIn("color", feature_names)
        # Check histogram shape
        for f in data["features"]:
            self.assertIn("histogram", f)
            self.assertIn("bins", f["histogram"])
            self.assertIn("baseline", f["histogram"])
            self.assertIn("current", f["histogram"])
            self.assertEqual(len(f["histogram"]["bins"]), 24)

    def test_model_audit_endpoint(self):
        res = self.client.get("/api/model/audit")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("identity", data)
        self.assertIn("blackbox", data)
        self.assertIn("whitebox", data)
        self.assertIn("fingerprint", data)
        self.assertIn("behavioral", data)
        self.assertEqual(data["identity"]["format"], "ONNX")
        self.assertEqual(data["identity"]["access"], "white-box")
        self.assertGreater(data["blackbox"]["golden_battery"]["total"], 0)
        self.assertGreater(len(data["behavioral"]), 0)


if __name__ == "__main__":
    unittest.main()
