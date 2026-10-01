"""
Unit Tests for Switchable Embedders & Registry (Gate B)
"""

import unittest
from PIL import Image
import numpy as np

from visionguard.embedders.registry import embedder_registry
from visionguard.embedders.mobilenet import MobileNetV3Embedder


class TestEmbedders(unittest.TestCase):
    def setUp(self):
        # Create a synthetic 128x128 image for fast local testing
        self.img = Image.new("RGB", (128, 128), color=(200, 100, 50))

    def test_mobilenet_v3_embedding(self):
        embedder = embedder_registry.get("mobilenet_v3")
        self.assertTrue(embedder.is_available)
        self.assertEqual(embedder.dimension, 576)

        vec = embedder.embed_image(self.img)
        self.assertEqual(vec.shape, (576,))
        norm = np.linalg.norm(vec)
        self.assertAlmostEqual(norm, 1.0, places=4, msg="Embedding vector must be L2 normalized")

    def test_dinov3_graceful_unavailable(self):
        embedder = embedder_registry.get("dinov3", fallback_to_default=False)
        self.assertFalse(embedder.is_available)
        self.assertIn("Assessment unavailable", embedder.unavailable_reason)

    def test_registry_fallback(self):
        # Requesting dinov3 with fallback_to_default=True should return mobilenet_v3
        embedder = embedder_registry.get("dinov3", fallback_to_default=True)
        self.assertEqual(embedder.name, "mobilenet_v3")
        self.assertTrue(embedder.is_available)

    def test_list_embedders(self):
        all_info = embedder_registry.list_all()
        names = [x["name"] for x in all_info]
        self.assertIn("mobilenet_v3", names)
        self.assertIn("dinov3", names)
        self.assertIn("siglip2", names)


if __name__ == "__main__":
    unittest.main()
