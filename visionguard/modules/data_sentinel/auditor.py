"""
Data Sentinel Core Auditor

Orchestrates training-data integrity checks across COCO, YOLO, and classification datasets.
Aggregates sample findings into contributor and batch risk profiles.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import numpy as np

from visionguard.core.config import DataSentinelConfig
from visionguard.core.schemas import (
    DataSentinelResult,
    DispositionEnum,
    Finding,
    ModuleEnum,
    SeverityEnum
)
from visionguard.embedders.base import BaseEmbedder
from visionguard.embedders.registry import embedder_registry
from visionguard.modules.data_sentinel.parser import DatasetParser, DatasetSample
from visionguard.modules.data_sentinel.detectors import (
    DuplicateDetector,
    LabelAnomalyDetector,
    OODDetector,
    TriggerPatternDetector,
    _now_iso
)


class DataSentinel:
    """Audits contributed training datasets for defined integrity threats."""

    def __init__(
        self,
        config: Optional[DataSentinelConfig] = None,
        embedder: Optional[BaseEmbedder] = None
    ):
        self.config = config or DataSentinelConfig()
        self.embedder = embedder or embedder_registry.get("mobilenet_v3")
        self.duplicate_detector = DuplicateDetector(
            phash_threshold=self.config.phash_hamming_threshold,
            cosine_threshold=self.config.embedding_similarity_threshold
        )
        self.label_detector = LabelAnomalyDetector(
            confidence_threshold=self.config.label_flip_confidence_min
        )
        self.ood_detector = OODDetector(
            percentile_cutoff=self.config.ood_percentile_cutoff
        )
        self.trigger_detector = TriggerPatternDetector(
            patch_size=self.config.patch_trigger_size,
            repetition_threshold=self.config.trigger_repetition_threshold
        )

    def audit(
        self,
        dataset_path: Union[str, Path],
        format_type: str = "auto",
        annotation_file: Optional[Union[str, Path]] = None,
        dataset_name: Optional[str] = None
    ) -> DataSentinelResult:
        path = Path(dataset_path)
        name = dataset_name or path.name

        # 1. Parse dataset according to format
        samples, resolved_format = self._parse_dataset(path, format_type, annotation_file)
        total_samples = len(samples)

        if total_samples == 0:
            return DataSentinelResult(
                dataset_name=name,
                format=resolved_format,
                total_samples=0,
                clean_samples=0,
                overall_disposition=DispositionEnum.ACCEPT,
                confidence=1.0,
                limitations=["Empty dataset provided for audit."]
            )

        # 2. Extract embeddings
        embeddings = self.embedder.embed_batch([s.image_path for s in samples])

        all_findings: List[Finding] = []

        # Separate corrupted samples from valid samples
        corrupt_samples = [s for s in samples if s.metadata.get("is_corrupted")]
        valid_samples = [s for s in samples if not s.metadata.get("is_corrupted")]

        for cs in corrupt_samples:
            all_findings.append(Finding(
                finding_id=f"FIND-DS-CORRUPT-{cs.sample_id}",
                module=ModuleEnum.DATA_SENTINEL,
                asset=cs.sample_id,
                reason=f"Corrupt or unreadable image file detected: {cs.metadata.get('error', 'decode error')}",
                evidence={"path": str(cs.image_path), "error": cs.metadata.get("error")},
                severity=SeverityEnum.HIGH,
                confidence=1.0,
                disposition=DispositionEnum.QUARANTINE,
                recommended_action="Remove or replace corrupted image file.",
                timestamp=_now_iso()
            ))

        exact_dups, near_dups, label_anomalies, ood_count, trigger_count = 0, 0, 0, 0, 0

        if valid_samples:
            # 2. Extract embeddings on valid samples
            embeddings = self.embedder.embed_batch([s.image_path for s in valid_samples])

            # 3. Detect exact & near duplicates
            dup_findings, exact_dups, near_dups = self.duplicate_detector.audit(valid_samples, embeddings)
            all_findings.extend(dup_findings)

            # 4. Detect label anomalies / flipping
            label_findings, label_anomalies = self.label_detector.audit(valid_samples, embeddings)
            all_findings.extend(label_findings)

            # 5. Detect OOD insertions
            ood_findings, ood_count = self.ood_detector.audit(valid_samples, embeddings)
            all_findings.extend(ood_findings)

            # 6. Detect trigger / backdoor patches
            trigger_findings, trigger_count = self.trigger_detector.audit(valid_samples)
            all_findings.extend(trigger_findings)

        # 7. Aggregate Contributor and Batch Risk
        contributor_risk, batch_risk, risk_findings = self._aggregate_risk(samples, all_findings)
        all_findings.extend(risk_findings)

        # Determine overall disposition
        has_quarantine = any(f.disposition == DispositionEnum.QUARANTINE for f in all_findings)
        has_review = any(f.disposition == DispositionEnum.REVIEW for f in all_findings)

        if has_quarantine:
            overall_disposition = DispositionEnum.QUARANTINE
        elif has_review:
            overall_disposition = DispositionEnum.REVIEW
        else:
            overall_disposition = DispositionEnum.ACCEPT

        # Compute confidence (based on sample volume and embedder consistency)
        confidence = 0.95 if total_samples >= 10 else 0.80

        flagged_sample_ids = {f.asset for f in all_findings}
        clean_count = max(0, total_samples - len(flagged_sample_ids))

        limitations = [
            "Detects defined classes of training-data poisoning under specified assumptions (duplicates, label flips, OOD, and repetitive triggers).",
            "Does not claim universal detection of invisible-noise backdoors, clean-label triggers, or fully adaptive poisoning strategies.",
            f"Embeddings extracted using local offline embedder '{self.embedder.name}' (dimension: {self.embedder.dimension})."
        ]

        return DataSentinelResult(
            dataset_name=name,
            format=resolved_format,
            total_samples=total_samples,
            clean_samples=clean_count,
            exact_duplicates_count=exact_dups,
            near_duplicates_count=near_dups,
            label_anomalies_count=label_anomalies,
            ood_samples_count=ood_count,
            trigger_anomalies_count=trigger_count,
            contributor_risk=contributor_risk,
            batch_risk=batch_risk,
            findings=all_findings,
            overall_disposition=overall_disposition,
            confidence=confidence,
            limitations=limitations
        )

    def _parse_dataset(
        self,
        path: Path,
        format_type: str,
        annotation_file: Optional[Union[str, Path]]
    ) -> tuple[List[DatasetSample], str]:
        if path.is_file() and path.suffix.lower() == ".zip":
            return DatasetParser.parse_zip(path), "zip"

        if format_type.lower() == "coco" or (annotation_file and Path(annotation_file).is_file()):
            anno = Path(annotation_file) if annotation_file else (path / "annotations" / "instances.json")
            img_dir = path / "images" if (path / "images").is_dir() else path
            return DatasetParser.parse_coco(anno, img_dir), "coco"

        if format_type.lower() == "yolo" or (path / "labels").is_dir():
            return DatasetParser.parse_yolo(path), "yolo"

        if format_type.lower() == "classification" or (path.is_dir() and any(d.is_dir() for d in path.iterdir())):
            return DatasetParser.parse_classification(path), "classification"

        # Default fallback to classification parser
        return DatasetParser.parse_classification(path), "classification"

    def _aggregate_risk(
        self,
        samples: List[DatasetSample],
        findings: List[Finding]
    ) -> tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]], List[Finding]]:
        contrib_samples: Dict[str, int] = {}
        contrib_flagged: Dict[str, int] = {}
        batch_samples: Dict[str, int] = {}
        batch_flagged: Dict[str, int] = {}

        for s in samples:
            contrib_samples[s.contributor_id] = contrib_samples.get(s.contributor_id, 0) + 1
            batch_samples[s.batch_id] = batch_samples.get(s.batch_id, 0) + 1

        flagged_sample_map = {f.asset: f for f in findings}
        for s in samples:
            if s.sample_id in flagged_sample_map:
                contrib_flagged[s.contributor_id] = contrib_flagged.get(s.contributor_id, 0) + 1
                batch_flagged[s.batch_id] = batch_flagged.get(s.batch_id, 0) + 1

        contrib_summary: Dict[str, Dict[str, Any]] = {}
        risk_findings: List[Finding] = []

        for cid, total in contrib_samples.items():
            flagged = contrib_flagged.get(cid, 0)
            ratio = flagged / total if total > 0 else 0.0
            disposition = DispositionEnum.ACCEPT
            if ratio >= self.config.contributor_flag_ratio:
                disposition = DispositionEnum.QUARANTINE if ratio > 0.3 else DispositionEnum.REVIEW
                risk_findings.append(Finding(
                    finding_id=f"FIND-DS-CONTRIB-{cid}",
                    module=ModuleEnum.DATA_SENTINEL,
                    asset=cid,
                    reason=f"High contributor risk: {flagged}/{total} samples ({ratio:.1%}) flagged for integrity violations",
                    evidence={
                        "contributor_id": cid,
                        "total_contributed": total,
                        "flagged_samples": flagged,
                        "violation_rate": round(ratio, 4)
                    },
                    severity=SeverityEnum.HIGH if ratio < 0.3 else SeverityEnum.CRITICAL,
                    confidence=0.92,
                    disposition=disposition,
                    recommended_action=f"Quarantine all contributions from {cid} and audit contributor credentials.",
                    timestamp=_now_iso()
                ))

            contrib_summary[cid] = {
                "total": total,
                "flagged": flagged,
                "violation_rate": round(ratio, 4),
                "disposition": disposition.value
            }

        batch_summary: Dict[str, Dict[str, Any]] = {}
        for bid, total in batch_samples.items():
            flagged = batch_flagged.get(bid, 0)
            ratio = flagged / total if total > 0 else 0.0
            disposition = DispositionEnum.ACCEPT
            if ratio >= self.config.contributor_flag_ratio:
                disposition = DispositionEnum.QUARANTINE if ratio > 0.3 else DispositionEnum.REVIEW

            batch_summary[bid] = {
                "total": total,
                "flagged": flagged,
                "violation_rate": round(ratio, 4),
                "disposition": disposition.value
            }

        return contrib_summary, batch_summary, risk_findings
