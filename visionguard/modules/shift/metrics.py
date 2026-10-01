"""
Statistical Metrics for Shift Diagnostician

Implements:
- Population Stability Index (PSI)
- 1D Wasserstein Distance (Earth Mover's Distance)
- Visual feature extraction: brightness, contrast, sharpness, color distribution
"""

from typing import Dict, List, Tuple
import cv2
import numpy as np
from PIL import Image
from scipy.stats import wasserstein_distance


def compute_psi(baseline: np.ndarray, evaluation: np.ndarray, num_bins: int = 20, eps: float = 1e-6) -> float:
    """
    Computes Population Stability Index (PSI) between baseline and evaluation distributions.
    PSI = sum((actual% - expected%) * ln(actual% / expected%))
    """
    b_min, b_max = min(np.min(baseline), np.min(evaluation)), max(np.max(baseline), np.max(evaluation))
    if b_min == b_max:
        return 0.0

    bins = np.linspace(b_min, b_max, num_bins + 1)
    base_counts, _ = np.histogram(baseline, bins=bins)
    eval_counts, _ = np.histogram(evaluation, bins=bins)

    base_pct = base_counts / (np.sum(base_counts) + eps)
    eval_pct = eval_counts / (np.sum(eval_counts) + eps)

    # Regularize zero counts
    base_pct = np.clip(base_pct, eps, None)
    eval_pct = np.clip(eval_pct, eps, None)

    psi_val = np.sum((eval_pct - base_pct) * np.log(eval_pct / base_pct))
    return float(max(0.0, psi_val))


def compute_wasserstein_dist(u: np.ndarray, v: np.ndarray) -> float:
    """Computes first Wasserstein distance (Earth Mover's Distance) between two 1D distributions."""
    return float(wasserstein_distance(u, v))


def extract_image_visual_stats(img: Image.Image) -> Dict[str, float]:
    """
    Extracts fundamental photometric and structural metrics from a single image:
    - brightness: mean grayscale intensity (0 - 255)
    - contrast: standard deviation of grayscale intensity
    - sharpness: variance of Laplacian (measure of edge focus/blur)
    - color_balance: mean R, G, B channel ratios
    """
    rgb = np.asarray(img.convert("RGB"), dtype=np.float32)
    gray = 0.299 * rgb[:, :, 0] + 0.587 * rgb[:, :, 1] + 0.114 * rgb[:, :, 2]

    # Brightness & Contrast
    brightness = float(np.mean(gray))
    contrast = float(np.std(gray))

    # Sharpness via Laplacian variance
    # Discrete 3x3 Laplacian kernel
    kernel = np.array([[0, 1, 0], [1, -4, 1], [0, 1, 0]], dtype=np.float32)
    # Fast 2D convolution for air-gapped CPU execution without requiring heavy cv2
    from scipy.signal import convolve2d
    lap = convolve2d(gray, kernel, mode='valid')
    sharpness = float(np.var(lap))

    # Color means normalized to [0, 1]
    mean_r = float(np.mean(rgb[:, :, 0])) / 255.0
    mean_g = float(np.mean(rgb[:, :, 1])) / 255.0
    mean_b = float(np.mean(rgb[:, :, 2])) / 255.0

    return {
        "brightness": brightness,
        "contrast": contrast,
        "sharpness": sharpness,
        "color_r": mean_r,
        "color_g": mean_g,
        "color_b": mean_b
    }
