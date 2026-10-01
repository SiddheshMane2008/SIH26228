"""
VisionGuard Master Assurance Engine

Integrates all 6 core lifecycle modules:
1. Data Sentinel (Training-Data Integrity)
2. Model Auditor (Model Architecture & Fingerprinting)
3. Provenance Engine (Inference Chain & Signatures)
4. Shift Diagnostician (Distribution Shift Analysis)
5. Blast Radius (Lineage & Downstream Impact)
6. Trust Passport (Consolidated Cryptographic Assurance)
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import torch
from PIL import Image

from visionguard.core.config import VisionGuardConfig
from visionguard.core.crypto import KeyPair
from visionguard.core.schemas import (
    BlastRadiusTrace,
    DataSentinelResult,
    ModelAuditorResult,
    ProvenanceAuditResult,
    ProvenanceRecord,
    ShiftDiagnosticianResult,
    SignedHeadCheckpoint,
    TrustPassport
)
from visionguard.embedders.base import BaseEmbedder
from visionguard.embedders.registry import embedder_registry
from visionguard.modules.blast_radius.tracer import BlastRadiusGraph
from visionguard.modules.data_sentinel.auditor import DataSentinel
from visionguard.modules.governance.html_report import HTMLReportGenerator
from visionguard.modules.governance.logger import AuditLogger
from visionguard.modules.governance.passport import TrustPassportGenerator
from visionguard.modules.model_auditor.auditor import ModelAuditor
from visionguard.modules.provenance.auditor import ProvenanceAuditor
from visionguard.modules.shift.diagnostician import ShiftDiagnostician


class VisionGuardEngine:
    """Master orchestrator for the complete air-gapped computer vision lifecycle audit."""

    def __init__(
        self,
        config: Optional[VisionGuardConfig] = None,
        keypair: Optional[KeyPair] = None,
        embedder_name: Optional[str] = None
    ):
        self.config = config or VisionGuardConfig()
        self.keypair = keypair or KeyPair.generate()

        # Select embedder (defaulting to MobileNetV3 with fallback)
        sel_embedder = embedder_name or self.config.embedder.name
        self.embedder: BaseEmbedder = embedder_registry.get(sel_embedder, fallback_to_default=True)

        # Initialize core lifecycle modules
        self.data_sentinel = DataSentinel(config=self.config.data_sentinel, embedder=self.embedder)
        self.model_auditor = ModelAuditor(config=self.config.model_auditor)
        self.provenance_auditor = ProvenanceAuditor(config=self.config.provenance)
        self.shift_diagnostician = ShiftDiagnostician(config=self.config.shift, embedder=self.embedder)
        self.blast_graph = BlastRadiusGraph()
        self.passport_generator = TrustPassportGenerator(keypair=self.keypair)

        # Output & Logging
        self.output_dir = Path(self.config.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.audit_logger = AuditLogger(log_path=self.output_dir / "audit_log.jsonl")

    def run_full_audit(
        self,
        dataset_path: Optional[Union[str, Path]] = None,
        model_or_path: Optional[Union[torch.nn.Module, str, Path]] = None,
        inference_records: Optional[List[ProvenanceRecord]] = None,
        head_checkpoint: Optional[SignedHeadCheckpoint] = None,
        baseline_images: Optional[List[Union[Image.Image, Path, str]]] = None,
        operational_images: Optional[List[Union[Image.Image, Path, str]]] = None,
        target_contributor_trace: Optional[str] = None,
        registered_model_fingerprint: Optional[Dict[str, Any]] = None,
        generate_html_report: bool = True
    ) -> Dict[str, Any]:
        """
        Executes an end-to-end assurance audit across all active lifecycle components.
        Produces one signed Trust Passport.
        """
        results: Dict[str, Any] = {}
        audited_assets: Dict[str, Any] = {
            "engine": "VisionGuard v1.0.0",
            "operating_mode": self.config.operating_mode,
            "embedder": self.embedder.name,
            "embedder_dimension": self.embedder.dimension
        }

        # 1. Data Sentinel Audit
        ds_res: Optional[DataSentinelResult] = None
        if dataset_path:
            p_data = Path(dataset_path)
            audited_assets["dataset"] = str(p_data.name)
            ds_res = self.data_sentinel.audit(p_data)
            results["data_sentinel"] = ds_res
            self.audit_logger.log_findings(ds_res.findings)

        # 2. Model Auditor Audit
        ma_res: Optional[ModelAuditorResult] = None
        if model_or_path is not None:
            m_name = Path(model_or_path).name if isinstance(model_or_path, (str, Path)) else "contributed_model"
            audited_assets["model"] = m_name
            ma_res = self.model_auditor.audit(
                model_or_path=model_or_path,
                model_name=m_name,
                registered_fingerprint=registered_model_fingerprint
            )
            results["model_auditor"] = ma_res
            self.audit_logger.log_findings(ma_res.findings)

        # 3. Provenance Engine Audit
        pe_res: Optional[ProvenanceAuditResult] = None
        if inference_records:
            audited_assets["inference_record_count"] = len(inference_records)
            pe_res = self.provenance_auditor.audit(
                records=inference_records,
                checkpoint=head_checkpoint,
                public_key_hex=self.keypair.public_key_hex
            )
            results["provenance_engine"] = pe_res
            self.audit_logger.log_findings(pe_res.findings)

        # 4. Shift Diagnostician Audit
        sd_res: Optional[ShiftDiagnosticianResult] = None
        if baseline_images and operational_images:
            audited_assets["shift_baseline_count"] = len(baseline_images)
            audited_assets["shift_eval_count"] = len(operational_images)
            sd_res = self.shift_diagnostician.audit(
                baseline_images=baseline_images,
                evaluation_images=operational_images
            )
            results["shift_diagnostician"] = sd_res
            self.audit_logger.log_findings(sd_res.findings)

        # 5. Blast Radius Trace
        br_trace: Optional[BlastRadiusTrace] = None
        if target_contributor_trace:
            br_trace = self.blast_graph.trace_impact(target_contributor_trace)
            results["blast_radius"] = br_trace

        # 6. Generate Signed Trust Passport
        passport = self.passport_generator.generate(
            audited_assets=audited_assets,
            data_sentinel_res=ds_res,
            model_auditor_res=ma_res,
            provenance_res=pe_res,
            shift_res=sd_res,
            blast_radius_trace=br_trace
        )
        results["trust_passport"] = passport
        # Save signed passport JSON
        passport_path = self.output_dir / f"trust_passport_{passport.passport_id}.json"
        with open(passport_path, "w", encoding="utf-8") as f:
            f.write(passport.model_dump_json(indent=2))
        results["passport_path"] = str(passport_path)

        # 7. Generate Self-Contained Offline HTML Report
        if generate_html_report:
            report_path = self.output_dir / f"report_{passport.passport_id}.html"
            html_content = HTMLReportGenerator.generate_report(
                passport=passport,
                data_sentinel_res=ds_res,
                model_auditor_res=ma_res,
                provenance_res=pe_res,
                shift_res=sd_res,
                blast_radius=br_trace,
                output_file=report_path
            )
            results["html_report_path"] = str(report_path)

        return results
