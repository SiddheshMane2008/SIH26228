"""
White-Box Model Auditor for VisionGuard

Inspects model internals when access level is WHITE_BOX:
- Weight SHA-256 digest
- Model / graph structural hash
- Parameter statistics (mean, std, min, max, sparsity, NaN/Inf check)
- Parameter outlier detection (> 4 sigma weights indicative of trojan weight perturbations)
- Activation statistics
"""

import hashlib
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import torch

from visionguard.core.crypto import sha256_text
from visionguard.core.schemas import DispositionEnum, Finding, ModuleEnum, SeverityEnum
from visionguard.modules.data_sentinel.detectors import _now_iso


class WhiteBoxAuditor:
    """Performs deep internal parameter and architecture forensics."""

    def __init__(self, outlier_sigma: float = 4.0):
        self.outlier_sigma = outlier_sigma

    def audit(self, model: torch.nn.Module, model_name: str = "model") -> Tuple[Dict[str, Any], List[Finding]]:
        findings: List[Finding] = []
        
        all_weights: List[np.ndarray] = []
        param_stats: Dict[str, Any] = {}
        graph_structure: List[str] = []
        hasher = hashlib.sha256()

        total_params = 0
        nan_inf_found = False
        outlier_params = 0

        for name, param in sorted(model.named_parameters()):
            p_np = param.detach().cpu().numpy()
            total_params += p_np.size
            graph_structure.append(f"{name}:{list(p_np.shape)}:{str(p_np.dtype)}")
            
            # Canonical weight hashing
            hasher.update(name.encode("utf-8"))
            hasher.update(p_np.tobytes())

            # Check for NaN / Inf
            if np.isnan(p_np).any() or np.isinf(p_np).any():
                nan_inf_found = True
                findings.append(Finding(
                    finding_id=f"FIND-MA-PARAM-NANINF-{name}",
                    module=ModuleEnum.MODEL_AUDITOR,
                    asset=f"{model_name}:{name}",
                    reason=f"Numerical corruption detected: NaN or Inf found in layer weights '{name}'",
                    evidence={"layer": name, "shape": list(p_np.shape)},
                    severity=SeverityEnum.CRITICAL,
                    confidence=1.0,
                    disposition=DispositionEnum.QUARANTINE,
                    recommended_action="Quarantine model. Weights are corrupted or subject to adversarial NaN injection.",
                    timestamp=_now_iso()
                ))

            all_weights.append(p_np.flatten())

        if not all_weights:
            return {"error": "No parameters found"}, findings

        flat_all = np.concatenate(all_weights)
        weight_digest = hasher.hexdigest()
        graph_hash = sha256_text(";".join(graph_structure))

        # Statistical calculations
        mean_val = float(np.mean(flat_all))
        std_val = float(np.std(flat_all))
        min_val = float(np.min(flat_all))
        max_val = float(np.max(flat_all))
        sparsity = float(np.sum(flat_all == 0) / flat_all.size)

        # Detect extreme weight outliers (> outlier_sigma * std from mean)
        outlier_threshold = abs(mean_val) + self.outlier_sigma * std_val
        outlier_mask = np.abs(flat_all) > outlier_threshold
        outlier_count = int(np.sum(outlier_mask))

        if outlier_count > 0:
            outlier_ratio = outlier_count / flat_all.size
            if outlier_ratio > 0.001:  # More than 0.1% extreme outliers
                findings.append(Finding(
                    finding_id=f"FIND-MA-PARAM-OUTLIER-{model_name}",
                    module=ModuleEnum.MODEL_AUDITOR,
                    asset=model_name,
                    reason=f"Extreme parameter outliers detected ({outlier_count} weights exceed {self.outlier_sigma}-sigma). Possible trojan weight perturbation.",
                    evidence={
                        "outlier_count": outlier_count,
                        "outlier_ratio": round(outlier_ratio, 6),
                        "mean": round(mean_val, 6),
                        "std": round(std_val, 6),
                        "threshold": round(float(outlier_threshold), 4),
                        "max_weight": round(max_val, 4)
                    },
                    severity=SeverityEnum.HIGH,
                    confidence=0.85,
                    disposition=DispositionEnum.REVIEW,
                    recommended_action="Inspect flagged weight tensors for targeted backdoor weight modification.",
                    timestamp=_now_iso()
                ))

        # Check activation statistics on clean probe
        activation_stats = self._probe_activations(model)

        summary = {
            "weight_digest": weight_digest,
            "graph_hash": graph_hash,
            "total_parameters": total_params,
            "mean": round(mean_val, 6),
            "std": round(std_val, 6),
            "min": round(min_val, 6),
            "max": round(max_val, 6),
            "sparsity": round(sparsity, 4),
            "outlier_count": outlier_count,
            "nan_inf_found": nan_inf_found,
            "activation_stats": activation_stats
        }

        return summary, findings

    def _probe_activations(self, model: torch.nn.Module) -> Dict[str, Any]:
        """Runs a safe synthetic forward pass to measure activation statistics and dead neuron ratio."""
        probe = torch.zeros((1, 3, 224, 224), dtype=torch.float32)
        activations = []
        hooks = []

        def hook_fn(module, input, output):
            if isinstance(output, torch.Tensor):
                activations.append(output.detach().cpu().numpy())

        for layer in list(model.children())[:5]:
            hooks.append(layer.register_forward_hook(hook_fn))

        try:
            with torch.no_grad():
                model(probe)
        except Exception:
            pass
        finally:
            for h in hooks:
                h.remove()

        if activations:
            cat_acts = np.concatenate([a.flatten() for a in activations])
            return {
                "mean_activation": round(float(np.mean(cat_acts)), 4),
                "std_activation": round(float(np.std(cat_acts)), 4),
                "zero_activation_ratio": round(float(np.sum(cat_acts == 0) / cat_acts.size), 4)
            }
        return {"probed": False}
