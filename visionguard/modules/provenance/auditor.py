"""
Provenance Engine Auditor

Orchestrates full cryptographic audit:
- Hash-chain verification
- Digital signature verification
- Signed Head Checkpoint validation
- Replay, truncation, and modification detection
- Optional random spot-checks
"""

from typing import Any, Dict, List, Optional
from visionguard.core.config import ProvenanceConfig
from visionguard.core.schemas import (
    ProvenanceAuditResult,
    ProvenanceRecord,
    SignedHeadCheckpoint
)
from visionguard.modules.model_auditor.loader import BaseModelWrapper
from visionguard.modules.provenance.chain import ChainVerifier
from visionguard.modules.provenance.spotcheck import SpotCheckEngine


class ProvenanceAuditor:
    """Forensic auditor for the inference lifecycle."""

    def __init__(self, config: Optional[ProvenanceConfig] = None):
        self.config = config or ProvenanceConfig()
        self.spotcheck_engine = SpotCheckEngine(
            sample_rate=self.config.spot_check_sample_rate,
            tolerance=self.config.spot_check_tolerance
        )

    def audit(
        self,
        records: List[ProvenanceRecord],
        checkpoint: Optional[SignedHeadCheckpoint] = None,
        public_key_hex: Optional[str] = None,
        model_wrapper: Optional[BaseModelWrapper] = None,
        input_data_provider: Optional[Dict[str, Any]] = None
    ) -> ProvenanceAuditResult:
        # 1. Forensic Chain Verification
        result, chain_findings = ChainVerifier.verify(
            records=records,
            checkpoint=checkpoint,
            public_key_hex=public_key_hex
        )

        # 2. Optional Spot-Check Verification
        if model_wrapper is not None and input_data_provider:
            sc_summary, sc_findings = self.spotcheck_engine.audit(
                records=records,
                model_wrapper=model_wrapper,
                input_data_provider=input_data_provider
            )
            result.spot_check_passed = (sc_summary.get("discrepancies", 0) == 0)
            result.findings.extend(sc_findings)
            if not result.spot_check_passed:
                result.chain_valid = False
                result.overall_disposition = result.overall_disposition.QUARANTINE

        return result
