"""
Spot-Check Engine for Provenance Assurance

Randomly spot-checks recorded inferences by re-executing inputs through the registered model
and asserting output equivalence within numerical tolerance.
"""

import random
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from visionguard.core.schemas import DispositionEnum, Finding, ModuleEnum, ProvenanceRecord, SeverityEnum
from visionguard.modules.data_sentinel.detectors import _now_iso
from visionguard.modules.model_auditor.loader import BaseModelWrapper


class SpotCheckEngine:
    """Re-runs random sample of inference records against registered model."""

    def __init__(self, sample_rate: float = 0.25, tolerance: float = 1e-4, seed: int = 42):
        self.sample_rate = sample_rate
        self.tolerance = tolerance
        self.seed = seed

    def audit(
        self,
        records: List[ProvenanceRecord],
        model_wrapper: BaseModelWrapper,
        input_data_provider: Dict[str, Any]  # map of record_id -> raw input Image/array
    ) -> Tuple[Dict[str, Any], List[Finding]]:
        findings: List[Finding] = []
        if not records or not input_data_provider:
            return {"spot_checked": 0, "passed": 0, "discrepancies": 0}, findings

        random.seed(self.seed)
        num_samples = max(1, int(len(records) * self.sample_rate))
        sampled_records = random.sample(records, min(num_samples, len(records)))

        passed = 0
        discrepancies = 0

        for rec in sampled_records:
            if rec.record_id not in input_data_provider:
                continue

            raw_input = input_data_provider[rec.record_id]
            re_pred = model_wrapper.predict(raw_input).flatten()
            orig_output = np.array(rec.output).flatten()

            if len(re_pred) != len(orig_output):
                discrepancies += 1
                findings.append(Finding(
                    finding_id=f"FIND-PE-SPOTCHECK-DIM-{rec.record_id}",
                    module=ModuleEnum.PROVENANCE_ENGINE,
                    asset=rec.record_id,
                    reason=f"Spot-check failed: Output dimensionality mismatch between recorded inference ({len(orig_output)}) and re-execution ({len(re_pred)})",
                    evidence={"recorded_dim": len(orig_output), "reproduced_dim": len(re_pred)},
                    severity=SeverityEnum.CRITICAL,
                    confidence=1.0,
                    disposition=DispositionEnum.QUARANTINE,
                    recommended_action="Quarantine inference record. Possible model substitution or fabricated output.",
                    timestamp=_now_iso()
                ))
                continue

            max_diff = float(np.max(np.abs(re_pred - orig_output)))
            if max_diff > self.tolerance:
                discrepancies += 1
                findings.append(Finding(
                    finding_id=f"FIND-PE-SPOTCHECK-DIFF-{rec.record_id}",
                    module=ModuleEnum.PROVENANCE_ENGINE,
                    asset=rec.record_id,
                    reason=f"Spot-check failed: Re-executed model output deviates from recorded output (Max diff: {max_diff:.6f}, tolerance: {self.tolerance})",
                    evidence={
                        "max_difference": round(max_diff, 6),
                        "tolerance": self.tolerance,
                        "record_id": rec.record_id
                    },
                    severity=SeverityEnum.CRITICAL,
                    confidence=0.98,
                    disposition=DispositionEnum.QUARANTINE,
                    recommended_action="Quarantine record. Output recorded in log does not match output produced by registered model.",
                    timestamp=_now_iso()
                ))
            else:
                passed += 1

        summary = {
            "total_sampled": len(sampled_records),
            "passed": passed,
            "discrepancies": discrepancies,
            "tolerance": self.tolerance
        }

        return summary, findings
