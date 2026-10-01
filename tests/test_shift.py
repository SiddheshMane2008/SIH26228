"""
Unit and Attack Tests for Shift Diagnostician (Gate F)
"""

import unittest
from PIL import Image, ImageEnhance, ImageFilter
import numpy as np

from visionguard.core.schemas import DispositionEnum
from visionguard.modules.shift.diagnostician import ShiftDiagnostician


class TestShiftDiagnostician(unittest.TestCase):
    def setUp(self):
        self.diagnostician = ShiftDiagnostician()
        # Generate 10 standard baseline images
        self.baseline = []
        for i in range(10):
            np.random.seed(100 + i)
            arr = np.random.randint(50, 200, size=(128, 128, 3), dtype=np.uint8)
            self.baseline.append(Image.fromarray(arr))

    def test_stable_distribution_accept(self):
        # Evaluation set from the same underlying distribution (different seeds)
        evaluation = []
        for i in range(10):
            np.random.seed(500 + i)
            arr = np.random.randint(50, 200, size=(128, 128, 3), dtype=np.uint8)
            evaluation.append(Image.fromarray(arr))

        result = self.diagnostician.audit(self.baseline, evaluation)
        self.assertLess(result.composite_risk_score, 0.35)
        self.assertIn(result.overall_disposition, (DispositionEnum.ACCEPT, DispositionEnum.REVIEW))
        self.assertTrue(len(result.limitations) > 0)

    def test_moderate_environmental_shift_review(self):
        # Simulate heavy environmental fog / blur
        foggy_eval = []
        for img in self.baseline:
            # Drop contrast & apply blur
            enhancer = ImageEnhance.Contrast(img)
            dimmed = enhancer.enhance(0.4)
            blurred = dimmed.filter(ImageFilter.GaussianBlur(radius=2))
            foggy_eval.append(blurred)

        result = self.diagnostician.audit(self.baseline, foggy_eval)
        self.assertGreater(result.composite_risk_score, 0.20)
        self.assertIn("contrast", result.characterization.lower())
        self.assertIn(result.overall_disposition, (DispositionEnum.REVIEW, DispositionEnum.QUARANTINE))

    def test_severe_night_regime_shift_quarantine(self):
        # Simulate extreme nighttime plunge (90% brightness reduction + heavy color shift)
        night_eval = []
        for img in self.baseline:
            arr = np.asarray(img, dtype=np.float32) * 0.10  # 90% darker
            arr[:, :, 0] *= 0.5  # Heavy blue tint
            night_eval.append(Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8)))

        result = self.diagnostician.audit(self.baseline, night_eval)
        self.assertGreaterEqual(result.composite_risk_score, 0.50)
        self.assertIn(result.overall_disposition, (DispositionEnum.REVIEW, DispositionEnum.QUARANTINE))
        self.assertIn("brightness", result.characterization.lower())


if __name__ == "__main__":
    unittest.main()
