"""
Model Auditor Core Engine

Audits classification and detection models across supported formats (ONNX, PyTorch, TorchScript).
Operates in White-Box or Black-Box modes based on available access.
Strictly adheres to the Retraining Policy: Baseline assurance NEVER retrains the contributed model.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import torch

from visionguard.core.config import ModelAuditorConfig
from visionguard.core.crypto import sha256_file
from visionguard.core.schemas import (
    AccessLevelEnum,
    DispositionEnum,
    Finding,
    ModelAuditorResult,
    ModuleEnum,
    SeverityEnum
)
from visionguard.modules.data_sentinel.detectors import _now_iso
from visionguard.modules.model_auditor.blackbox import BlackBoxAuditor
from visionguard.modules.model_auditor.loader import BaseModelWrapper, load_model
from visionguard.modules.model_auditor.whitebox import WhiteBoxAuditor


class ModelAuditor:
    """Audits models for tampering, parameter anomalies, substitution, and backdoor sensitivity."""

    def __init__(self, config: Optional[ModelAuditorConfig] = None):
        self.config = config or ModelAuditorConfig()
        self.whitebox_auditor = WhiteBoxAuditor(outlier_sigma=self.config.weight_outlier_sigma)
        self.blackbox_auditor = BlackBoxAuditor(
            battery_size=self.config.golden_battery_size,
            tolerance=self.config.golden_battery_tolerance
        )

    def audit(
        self,
        model_or_path: Union[torch.nn.Module, str, Path],
        model_name: Optional[str] = None,
        registered_fingerprint: Optional[Dict[str, Any]] = None
    ) -> ModelAuditorResult:
        name = model_name or (Path(model_or_path).name if isinstance(model_or_path, (str, Path)) else "model")

        # 1. Load model wrapper
        wrapper = load_model(model_or_path)

        # 2. Check if model loading failed
        if not wrapper.is_loaded:
            finding = Finding(
                finding_id=f"FIND-MA-UNAVAILABLE-{name}",
                module=ModuleEnum.MODEL_AUDITOR,
                asset=name,
                reason="Assessment unavailable — required model format/access not available.",
                evidence={"error": wrapper.load_error},
                severity=SeverityEnum.MEDIUM,
                confidence=1.0,
                disposition=DispositionEnum.REVIEW,
                recommended_action="Ensure model file exists and is in supported ONNX or PyTorch format.",
                timestamp=_now_iso()
            )
            return ModelAuditorResult(
                model_name=name,
                model_format=wrapper.model_format,
                access_level=AccessLevelEnum.UNAVAILABLE,
                findings=[finding],
                overall_disposition=DispositionEnum.REVIEW,
                confidence=0.50,
                limitations=[
                    "Assessment unavailable — required model format/access not available.",
                    "Remaining applicable assessments continue."
                ]
            )

        all_findings: List[Finding] = []
        weight_digest: Optional[str] = None
        graph_hash: Optional[str] = None
        param_stats: Optional[Dict[str, Any]] = None
        activation_stats: Optional[Dict[str, Any]] = None

        # 3. White-Box Audit (if internal torch model available)
        if isinstance(model_or_path, (str, Path)) and Path(model_or_path).is_file():
            # File-level digest
            file_sha = sha256_file(model_or_path)
        else:
            file_sha = "memory_tensor_buffer"

        internal_torch = getattr(wrapper, "internal_model", None)
        if internal_torch is not None:
            wb_summary, wb_findings = self.whitebox_auditor.audit(internal_torch, model_name=name)
            all_findings.extend(wb_findings)
            weight_digest = wb_summary.get("weight_digest", file_sha)
            graph_hash = wb_summary.get("graph_hash")
            param_stats = wb_summary
            activation_stats = wb_summary.get("activation_stats")
        else:
            weight_digest = file_sha

        # 4. Black-Box Audit (behavioral golden battery & trigger sweep)
        bb_summary, bb_findings = self.blackbox_auditor.audit(
            wrapper,
            model_name=name,
            registered_fingerprint=registered_fingerprint
        )
        all_findings.extend(bb_findings)

        # 5. Determine overall disposition
        has_quarantine = any(f.disposition == DispositionEnum.QUARANTINE for f in all_findings)
        has_review = any(f.disposition == DispositionEnum.REVIEW for f in all_findings)

        if has_quarantine:
            overall_disposition = DispositionEnum.QUARANTINE
        elif has_review:
            overall_disposition = DispositionEnum.REVIEW
        else:
            overall_disposition = DispositionEnum.ACCEPT

        evidence_summary = {
            "file_sha256": file_sha,
            "weight_digest": weight_digest,
            "graph_hash": graph_hash,
            "golden_battery_size": bb_summary.get("golden_battery_size", 0),
            "fingerprint_hash": bb_summary.get("fingerprint_hash"),
            "consistency_score": bb_summary.get("consistency_score", 1.0),
            "outputs": bb_summary.get("outputs", [])
        }

        limitations = [
            "A cryptographic model digest provides strong evidence of exact artifact identity.",
            "The golden battery provides evidence of behavioural consistency with the registered fingerprint.",
            "White-box statistics provide additional supporting evidence; none of these alone proves that every possible hidden attack is absent.",
            "Baseline assurance policy: Model was audited without retraining."
        ]

        return ModelAuditorResult(
            model_name=name,
            model_format=wrapper.model_format,
            access_level=wrapper.access_level,
            weight_digest=weight_digest,
            graph_hash=graph_hash,
            parameter_stats=param_stats,
            activation_stats=activation_stats,
            golden_battery_consistency=bb_summary.get("consistency_score"),
            trigger_sweep_sensitivity=bb_summary.get("trigger_sweep", {}).get("dominant_class_collapse_ratio"),
            findings=all_findings,
            overall_disposition=overall_disposition,
            confidence=0.94 if wrapper.access_level == AccessLevelEnum.WHITE_BOX else 0.85,
            evidence_summary=evidence_summary,
            limitations=limitations
        )
