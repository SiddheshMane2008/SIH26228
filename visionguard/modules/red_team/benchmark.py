"""
Red-Team Benchmark & Metrics Engine for VisionGuard

Runs empirical evaluations against ground-truth adversarial scenarios.
Computes real Precision, Recall, and F1 scores without fabrication.
"""

import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional
import numpy as np

from visionguard.core.schemas import (
    RedTeamEvaluationSummary,
    RedTeamVariantResult
)
from visionguard.modules.data_sentinel.auditor import DataSentinel
from visionguard.modules.data_sentinel.detectors import _now_iso
from visionguard.modules.model_auditor.auditor import ModelAuditor
from visionguard.modules.provenance.chain import ChainVerifier
from visionguard.modules.red_team.simulator import RedTeamSimulator
from visionguard.modules.shift.diagnostician import ShiftDiagnostician


class RedTeamBenchmark:
    """Executes held-out attack suites and measures genuine forensic accuracy."""

    def __init__(self, seed: int = 42):
        self.seed = seed
        self.simulator = RedTeamSimulator(seed=seed)
        self.sentinel = DataSentinel()
        self.provenance_verifier = ChainVerifier()
        self.shift_diagnostician = ShiftDiagnostician()

    def run_full_benchmark(self) -> RedTeamEvaluationSummary:
        temp_dir = Path(tempfile.mkdtemp(prefix="vg_benchmark_"))
        scenarios: List[RedTeamVariantResult] = []

        try:
            # 1. Label Flipping Evaluation
            scenarios.append(self._eval_data_sentinel_attack(
                attack_type="label_flip",
                family="poisoning",
                dir_path=temp_dir / "ds_label_flip",
                num_clean=10,
                num_poisoned=2
            ))

            # 2. Duplicate Flooding Evaluation
            scenarios.append(self._eval_data_sentinel_attack(
                attack_type="duplicate_flood",
                family="poisoning",
                dir_path=temp_dir / "ds_dup_flood",
                num_clean=10,
                num_poisoned=3
            ))

            # 3. OOD Insertion Evaluation
            scenarios.append(self._eval_data_sentinel_attack(
                attack_type="ood_insertion",
                family="evasion",
                dir_path=temp_dir / "ds_ood",
                num_clean=10,
                num_poisoned=2
            ))

            # 4. Trigger / Backdoor Patch Evaluation
            scenarios.append(self._eval_data_sentinel_attack(
                attack_type="trigger_poisoning",
                family="poisoning",
                dir_path=temp_dir / "ds_trigger",
                num_clean=10,
                num_poisoned=2
            ))

            # 5. Provenance Output Tampering Evaluation
            scenarios.append(self._eval_provenance_tampering("output_modification"))

            # 6. Provenance Model Substitution Evaluation
            scenarios.append(self._eval_provenance_tampering("model_substitution"))

            # 7. Provenance Replay Evaluation
            scenarios.append(self._eval_provenance_tampering("replay"))

        finally:
            if temp_dir.exists():
                shutil.rmtree(temp_dir)

        # Macro averages
        precisions = [s.precision for s in scenarios]
        recalls = [s.recall for s in scenarios]
        f1s = [s.f1_score for s in scenarios]

        macro_p = float(np.mean(precisions)) if precisions else 0.0
        macro_r = float(np.mean(recalls)) if recalls else 0.0
        macro_f1 = float(np.mean(f1s)) if f1s else 0.0

        return RedTeamEvaluationSummary(
            timestamp=_now_iso(),
            random_seed=self.seed,
            scenarios_evaluated=scenarios,
            macro_precision=round(macro_p, 4),
            macro_recall=round(macro_r, 4),
            macro_f1=round(macro_f1, 4)
        )

    def _eval_data_sentinel_attack(
        self,
        attack_type: str,
        family: str,
        dir_path: Path,
        num_clean: int,
        num_poisoned: int
    ) -> RedTeamVariantResult:
        sim_data = self.simulator.generate_poisoned_dataset(
            output_dir=dir_path,
            attack_type=attack_type,
            num_clean=num_clean,
            num_poisoned=num_poisoned
        )
        gt = sim_data["ground_truth"]
        res = self.sentinel.audit(dir_path, format_type="classification")

        flagged_assets = {f.asset for f in res.findings}

        tp = sum(1 for sample_id, is_atk in gt.items() if is_atk and sample_id in flagged_assets)
        fp = sum(1 for sample_id, is_atk in gt.items() if not is_atk and sample_id in flagged_assets)
        fn = sum(1 for sample_id, is_atk in gt.items() if is_atk and sample_id not in flagged_assets)
        total_positives = sum(1 for is_atk in gt.values() if is_atk)

        precision = (tp / (tp + fp)) if (tp + fp) > 0 else (1.0 if total_positives == 0 else 0.0)
        recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        return RedTeamVariantResult(
            attack_name=attack_type.replace("_", " ").title(),
            attack_family=family,
            sample_count=len(gt),
            detected_count=tp,
            precision=round(float(precision), 4),
            recall=round(float(recall), 4),
            f1_score=round(float(f1), 4),
            held_out_evaluated=True,
            evidence_notes=f"Evaluated against {total_positives} injected attacks and {len(gt) - total_positives} clean samples."
        )

    def _eval_provenance_tampering(self, attack_type: str) -> RedTeamVariantResult:
        chain, injected_indices = self.simulator.generate_tampered_chain(attack_type=attack_type)
        checkpoint = chain.create_head_checkpoint()
        # Head checkpoint was computed before tampering in simulator
        res, findings = self.provenance_verifier.verify(
            records=chain.records,
            checkpoint=checkpoint,
            public_key_hex=chain.public_key_hex
        )

        detected_set = set(res.tampered_records + res.broken_links + res.replay_records)
        injected_set = set(injected_indices)

        tp = len(detected_set.intersection(injected_set))
        fp = len(detected_set - injected_set)
        fn = len(injected_set - detected_set)

        precision = (tp / (tp + fp)) if (tp + fp) > 0 else 1.0
        recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        return RedTeamVariantResult(
            attack_name=f"Inference {attack_type.replace('_', ' ').title()}",
            attack_family="tampering",
            sample_count=len(chain.records),
            detected_count=tp,
            precision=round(float(precision), 4),
            recall=round(float(recall), 4),
            f1_score=round(float(f1), 4),
            held_out_evaluated=True,
            evidence_notes=f"Injected into {len(injected_indices)} / {len(chain.records)} records."
        )
