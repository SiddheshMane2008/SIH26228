"""
Shift Diagnostician Core Engine

Audits distributional changes between baseline training/reference images and live operational images:
- Photometric drift (Brightness, Contrast, Sharpness) via PSI & Wasserstein
- Chromatic drift (Color distribution divergence)
- Semantic embedding drift via L2/Cosine space
- Calibrated composite risk scoring and human-readable characterization
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import numpy as np
from PIL import Image

from visionguard.core.config import ShiftConfig
from visionguard.core.schemas import (
    DispositionEnum,
    Finding,
    ModuleEnum,
    SeverityEnum,
    ShiftDiagnosticianResult
)
from visionguard.embedders.base import BaseEmbedder
from visionguard.embedders.registry import embedder_registry
from visionguard.modules.data_sentinel.detectors import _now_iso
from visionguard.modules.shift.metrics import (
    compute_psi,
    compute_wasserstein_dist,
    extract_image_visual_stats
)


class ShiftDiagnostician:
    """Diagnoses photometric, structural, and semantic distribution shifts."""

    def __init__(
        self,
        config: Optional[ShiftConfig] = None,
        embedder: Optional[BaseEmbedder] = None
    ):
        self.config = config or ShiftConfig()
        self.embedder = embedder or embedder_registry.get("mobilenet_v3")

    def audit(
        self,
        baseline_images: List[Union[Image.Image, Path, str]],
        evaluation_images: List[Union[Image.Image, Path, str]],
        baseline_id: str = "baseline",
        evaluation_id: str = "operational_batch"
    ) -> ShiftDiagnosticianResult:
        if not baseline_images or not evaluation_images:
            return ShiftDiagnosticianResult(
                baseline_id=baseline_id,
                evaluation_id=evaluation_id,
                brightness_psi=0.0,
                contrast_psi=0.0,
                sharpness_wasserstein=0.0,
                color_distribution_divergence=0.0,
                embedding_drift_score=0.0,
                composite_risk_score=0.0,
                characterization="Insufficient sample data for distribution shift analysis.",
                overall_disposition=DispositionEnum.ACCEPT,
                confidence=0.50,
                limitations=["Insufficient sample data to measure statistical divergence."]
            )

        # 1. Load PIL images
        base_pil = [self._to_pil(img) for img in baseline_images]
        eval_pil = [self._to_pil(img) for img in evaluation_images]

        # 2. Extract visual metrics
        base_stats = [extract_image_visual_stats(img) for img in base_pil]
        eval_stats = [extract_image_visual_stats(img) for img in eval_pil]

        # 3. Compute statistical divergences
        # Brightness PSI
        b_base = np.array([s["brightness"] for s in base_stats])
        b_eval = np.array([s["brightness"] for s in eval_stats])
        brightness_psi = compute_psi(b_base, b_eval, num_bins=self.config.bins)

        # Contrast PSI
        c_base = np.array([s["contrast"] for s in base_stats])
        c_eval = np.array([s["contrast"] for s in eval_stats])
        contrast_psi = compute_psi(c_base, c_eval, num_bins=self.config.bins)

        # Sharpness Wasserstein distance (normalized by baseline mean sharpness)
        s_base = np.array([s["sharpness"] for s in base_stats])
        s_eval = np.array([s["sharpness"] for s in eval_stats])
        raw_sharp_wass = compute_wasserstein_dist(s_base, s_eval)
        norm_factor = max(1.0, float(np.mean(s_base)))
        sharpness_wass = raw_sharp_wass / norm_factor

        # Color Divergence (Wasserstein across RGB channels)
        col_div_r = compute_wasserstein_dist(np.array([s["color_r"] for s in base_stats]), np.array([s["color_r"] for s in eval_stats]))
        col_div_g = compute_wasserstein_dist(np.array([s["color_g"] for s in base_stats]), np.array([s["color_g"] for s in eval_stats]))
        col_div_b = compute_wasserstein_dist(np.array([s["color_b"] for s in base_stats]), np.array([s["color_b"] for s in eval_stats]))
        color_divergence = float(np.mean([col_div_r, col_div_g, col_div_b]))

        # 4. Semantic Embedding Drift
        base_emb = self.embedder.embed_batch(base_pil)
        eval_emb = self.embedder.embed_batch(eval_pil)

        base_centroid = np.mean(base_emb, axis=0)
        base_centroid = base_centroid / (np.linalg.norm(base_centroid) + 1e-12)
        eval_centroid = np.mean(eval_emb, axis=0)
        eval_centroid = eval_centroid / (np.linalg.norm(eval_centroid) + 1e-12)

        # Cosine distance between centroids
        centroid_dist = 1.0 - float(np.dot(base_centroid, eval_centroid))
        embedding_drift = float(np.clip(centroid_dist, 0.0, 1.0))

        # 5. Composite Risk Score Calibration (0.0 to 1.0)
        # Weights: Brightness (0.15), Contrast (0.15), Sharpness (0.20), Color (0.20), Embedding (0.30)
        norm_b_psi = min(1.0, brightness_psi / 0.40)
        norm_c_psi = min(1.0, contrast_psi / 0.40)
        norm_s_wass = min(1.0, sharpness_wass / 0.50)
        norm_col = min(1.0, color_divergence / 0.25)
        norm_emb = min(1.0, embedding_drift / self.config.embedding_drift_threshold)

        composite_risk = float(np.clip(
            0.15 * norm_b_psi +
            0.15 * norm_c_psi +
            0.20 * norm_s_wass +
            0.20 * norm_col +
            0.30 * norm_emb,
            0.0,
            1.0
        ))

        # 6. Human-Readable Characterization
        characterization = self._characterize_shift(
            b_base, b_eval, brightness_psi,
            c_base, c_eval, contrast_psi,
            s_base, s_eval, sharpness_wass,
            color_divergence,
            embedding_drift,
            composite_risk
        )

        # 7. Generate Findings
        findings: List[Finding] = []
        if composite_risk >= 0.60:
            overall_disposition = DispositionEnum.QUARANTINE
            findings.append(Finding(
                finding_id=f"FIND-SD-CRITICAL-SHIFT-{evaluation_id}",
                module=ModuleEnum.SHIFT_DIAGNOSTICIAN,
                asset=evaluation_id,
                reason=f"Severe distribution shift detected (Composite Risk: {composite_risk:.2f}). {characterization}",
                evidence={
                    "brightness_psi": round(brightness_psi, 4),
                    "contrast_psi": round(contrast_psi, 4),
                    "sharpness_wasserstein": round(sharpness_wass, 4),
                    "color_divergence": round(color_divergence, 4),
                    "embedding_drift": round(embedding_drift, 4),
                    "composite_risk": round(composite_risk, 4)
                },
                severity=SeverityEnum.CRITICAL,
                confidence=0.91,
                disposition=DispositionEnum.QUARANTINE,
                recommended_action="Quarantine live inference stream. Retrain model or adapt domain before resuming automated decisions.",
                timestamp=_now_iso()
            ))
        elif composite_risk >= 0.25:
            overall_disposition = DispositionEnum.REVIEW
            findings.append(Finding(
                finding_id=f"FIND-SD-MODERATE-SHIFT-{evaluation_id}",
                module=ModuleEnum.SHIFT_DIAGNOSTICIAN,
                asset=evaluation_id,
                reason=f"Moderate distribution shift detected (Composite Risk: {composite_risk:.2f}). {characterization}",
                evidence={
                    "brightness_psi": round(brightness_psi, 4),
                    "contrast_psi": round(contrast_psi, 4),
                    "sharpness_wasserstein": round(sharpness_wass, 4),
                    "color_divergence": round(color_divergence, 4),
                    "embedding_drift": round(embedding_drift, 4),
                    "composite_risk": round(composite_risk, 4)
                },
                severity=SeverityEnum.MEDIUM,
                confidence=0.85,
                disposition=DispositionEnum.REVIEW,
                recommended_action="Review operational environment. Check for environmental drift (lighting, weather, sensor degradation).",
                timestamp=_now_iso()
            ))
        else:
            overall_disposition = DispositionEnum.ACCEPT

        limitations = [
            "'Drift' versus 'suspicious manipulation' is an evidence-based assessment, not an absolute determination.",
            f"Embeddings extracted using local offline embedder '{self.embedder.name}'.",
            "Metrics assume representative baseline sampling of deployment domain."
        ]

        return ShiftDiagnosticianResult(
            baseline_id=baseline_id,
            evaluation_id=evaluation_id,
            brightness_psi=round(brightness_psi, 4),
            contrast_psi=round(contrast_psi, 4),
            sharpness_wasserstein=round(sharpness_wass, 4),
            color_distribution_divergence=round(color_divergence, 4),
            embedding_drift_score=round(embedding_drift, 4),
            composite_risk_score=round(composite_risk, 4),
            characterization=characterization,
            findings=findings,
            overall_disposition=overall_disposition,
            confidence=0.90,
            limitations=limitations
        )

    def _to_pil(self, img_input: Union[Image.Image, Path, str]) -> Image.Image:
        if isinstance(img_input, Image.Image):
            return img_input.convert("RGB")
        return Image.open(img_input).convert("RGB")

    def _characterize_shift(
        self,
        b_base: np.ndarray, b_eval: np.ndarray, b_psi: float,
        c_base: np.ndarray, c_eval: np.ndarray, c_psi: float,
        s_base: np.ndarray, s_eval: np.ndarray, s_wass: float,
        col_div: float,
        emb_drift: float,
        composite_risk: float
    ) -> str:
        descs = []
        # Brightness direction
        b_mean_diff = float(np.mean(b_eval) - np.mean(b_base))
        if b_psi > 0.15:
            direction = "drop (darkening/night regime)" if b_mean_diff < 0 else "surge (glare/overexposure)"
            descs.append(f"significant brightness {direction} (PSI: {b_psi:.2f})")

        # Contrast
        c_mean_diff = float(np.mean(c_eval) - np.mean(c_base))
        if c_psi > 0.15:
            c_dir = "contrast loss (fog/washout)" if c_mean_diff < 0 else "contrast surge"
            descs.append(f"{c_dir} (PSI: {c_psi:.2f})")

        # Sharpness
        s_mean_diff = float(np.mean(s_eval) - np.mean(s_base))
        if s_wass > 0.20:
            s_dir = "blur / defocusing / motion artifact" if s_mean_diff < 0 else "high-frequency noise"
            descs.append(f"sharpness alteration ({s_dir})")

        if col_div > 0.15:
            descs.append(f"color spectrum divergence (Δ: {col_div:.2f})")

        if emb_drift > 0.20:
            descs.append(f"significant semantic embedding drift ({emb_drift:.2f})")

        if not descs:
            return "Distribution stable: photometric, chromatic, and embedding parameters remain within acceptable operational tolerances."

        return "Observed: " + "; ".join(descs) + "."
