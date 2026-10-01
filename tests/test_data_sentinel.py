"""
Unit and Attack Tests for Data Sentinel (Gate C)
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from PIL import Image, ImageDraw
import numpy as np

from visionguard.core.schemas import DispositionEnum
from visionguard.modules.data_sentinel.auditor import DataSentinel


class TestDataSentinel(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="vg_test_ds_")
        self.sentinel = DataSentinel()

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def _create_synthetic_image(self, path: Path, color: tuple, shape: str = "rect", trigger: bool = False, seed_idx: int = 0):
        # Create distinct pattern per seed_idx
        np.random.seed(seed_idx + 100)
        np_bg = np.random.randint(20, 80, size=(64, 64, 3), dtype=np.uint8)
        img = Image.fromarray(np_bg)
        draw = ImageDraw.Draw(img)
        
        if shape == "rect":
            draw.rectangle([10, 10, 50, 50], fill=color)
        elif shape == "circle":
            draw.ellipse([10, 10, 50, 50], fill=color)
        elif shape == "triangle":
            draw.polygon([(32, 8), (8, 54), (56, 54)], fill=color)
        elif shape == "cross":
            draw.line([(32, 8), (32, 56)], fill=color, width=8)
            draw.line([(8, 32), (56, 32)], fill=color, width=8)
        elif shape == "diamond":
            draw.polygon([(32, 8), (56, 32), (32, 56), (8, 32)], fill=color)

        if trigger:
            # Backdoor trigger: textured/checkerboard 8x8 square in bottom-right corner (high variance)
            for ty in range(56, 64):
                for tx in range(56, 64):
                    tcol = (255, 255, 0) if (tx + ty) % 2 == 0 else (0, 0, 0)
                    draw.point((tx, ty), fill=tcol)

        img.save(path)

    def test_clean_dataset_accept(self):
        dataset_path = Path(self.test_dir) / "clean_dataset"
        class_a = dataset_path / "class_a"
        class_b = dataset_path / "class_b"
        class_a.mkdir(parents=True)
        class_b.mkdir(parents=True)

        for i in range(5):
            self._create_synthetic_image(
                class_a / f"img_a_{i}.png",
                color=(180 + i * 15, 30 + i * 5, 40),
                shape="rect",
                seed_idx=i
            )
            self._create_synthetic_image(
                class_b / f"img_b_{i}.png",
                color=(30, 40 + i * 5, 180 + i * 15),
                shape="circle",
                seed_idx=i + 50
            )

        result = self.sentinel.audit(dataset_path, format_type="classification")
        self.assertEqual(result.total_samples, 10)
        self.assertEqual(result.exact_duplicates_count, 0)
        self.assertEqual(result.near_duplicates_count, 0)
        self.assertEqual(result.overall_disposition, DispositionEnum.ACCEPT)
        self.assertTrue(len(result.limitations) > 0)

    def test_exact_duplicate_detection(self):
        dataset_path = Path(self.test_dir) / "dup_dataset"
        dataset_path.mkdir(parents=True)

        img1 = dataset_path / "img_orig.png"
        img2 = dataset_path / "img_copy.png"
        self._create_synthetic_image(img1, color=(100, 200, 100), shape="triangle")
        shutil.copyfile(img1, img2)

        result = self.sentinel.audit(dataset_path, format_type="classification")
        self.assertEqual(result.exact_duplicates_count, 1)
        self.assertEqual(result.overall_disposition, DispositionEnum.QUARANTINE)

    def test_trigger_pattern_detection(self):
        dataset_path = Path(self.test_dir) / "trigger_dataset"
        dataset_path.mkdir(parents=True)

        # Create 4 images with identical corner backdoor trigger
        for i in range(4):
            self._create_synthetic_image(
                dataset_path / f"img_trig_{i}.png",
                color=(50 + i * 20, 100, 150),
                shape="rect",
                trigger=True
            )

        result = self.sentinel.audit(dataset_path, format_type="classification")
        self.assertGreaterEqual(result.trigger_anomalies_count, 3)
        self.assertEqual(result.overall_disposition, DispositionEnum.QUARANTINE)

    def test_label_flip_detection(self):
        dataset_path = Path(self.test_dir) / "flip_dataset"
        class_a = dataset_path / "class_a"
        class_b = dataset_path / "class_b"
        class_a.mkdir(parents=True)
        class_b.mkdir(parents=True)

        # Class A: 5 red rectangles
        for i in range(5):
            self._create_synthetic_image(class_a / f"img_a_{i}.png", color=(220, 20 + i * 5, 20), shape="rect", seed_idx=i)
        # Class B: 5 blue circles
        for i in range(5):
            self._create_synthetic_image(class_b / f"img_b_{i}.png", color=(20, 20 + i * 5, 220), shape="circle", seed_idx=i + 30)

        # Injected label flip: A red rectangle (identical in characteristics to class A) labeled as class B!
        self._create_synthetic_image(class_b / "flipped_sample.png", color=(220, 25, 20), shape="rect", seed_idx=1)

        result = self.sentinel.audit(dataset_path, format_type="classification")
        self.assertGreaterEqual(result.label_anomalies_count, 1)

    def test_ood_detection(self):
        dataset_path = Path(self.test_dir) / "ood_dataset"
        class_main = dataset_path / "class_main"
        class_main.mkdir(parents=True)

        # 8 normal green shapes
        for i in range(8):
            self._create_synthetic_image(class_main / f"norm_{i}.png", color=(30, 180 + i * 8, 30), shape="triangle", seed_idx=i)

        # 1 extreme OOD sample (pure static noise)
        ood_img = Image.fromarray(np.random.randint(0, 255, size=(64, 64, 3), dtype=np.uint8))
        ood_img.save(class_main / "ood_anomaly.png")

        result = self.sentinel.audit(dataset_path, format_type="classification")
        self.assertGreaterEqual(result.ood_samples_count, 1)


if __name__ == "__main__":
    unittest.main()
