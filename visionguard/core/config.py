"""
VisionGuard Configuration System
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional
import yaml
from pydantic import BaseModel, Field


class EmbedderConfig(BaseModel):
    name: str = "mobilenet_v3"
    fallback: str = "mobilenet_v3"
    cache_embeddings: bool = True
    device: str = "cpu"  # enforce cpu/lightweight by default


class DataSentinelConfig(BaseModel):
    phash_hamming_threshold: int = 6  # 0-64 bits, <= 6 indicates near-duplicate
    embedding_similarity_threshold: float = 0.96
    ood_percentile_cutoff: float = 95.0
    label_flip_confidence_min: float = 0.65
    patch_trigger_size: int = 16
    trigger_repetition_threshold: int = 3
    contributor_flag_ratio: float = 0.15


class ModelAuditorConfig(BaseModel):
    golden_battery_size: int = 20
    golden_battery_tolerance: float = 0.05
    trigger_sweep_locations: int = 4
    trigger_sweep_sizes: list[int] = Field(default_factory=lambda: [8, 16, 24])
    weight_outlier_sigma: float = 4.0


class ProvenanceConfig(BaseModel):
    hash_algorithm: str = "sha256"
    signature_algorithm: str = "ed25519"
    spot_check_sample_rate: float = 0.25
    spot_check_tolerance: float = 1e-4
    watermark_policy: str = "VISIBLE"  # NONE, VISIBLE, INVISIBLE, BOTH
    c2pa_sidecar_enabled: bool = True


class ShiftConfig(BaseModel):
    bins: int = 20
    psi_review_threshold: float = 0.15
    psi_quarantine_threshold: float = 0.30
    wasserstein_review_threshold: float = 0.10
    embedding_drift_threshold: float = 0.25


class VisionGuardConfig(BaseModel):
    operating_mode: str = "OFFLINE_AIR_GAPPED"
    embedder: EmbedderConfig = Field(default_factory=EmbedderConfig)
    data_sentinel: DataSentinelConfig = Field(default_factory=DataSentinelConfig)
    model_auditor: ModelAuditorConfig = Field(default_factory=ModelAuditorConfig)
    provenance: ProvenanceConfig = Field(default_factory=ProvenanceConfig)
    shift: ShiftConfig = Field(default_factory=ShiftConfig)
    output_dir: str = "runs"

    @classmethod
    def load(cls, config_path: Optional[str] = None) -> "VisionGuardConfig":
        if config_path and os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            return cls(**data)
        return cls()

    def to_yaml(self, filepath: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            yaml.dump(self.model_dump(), f, default_flow_style=False)
