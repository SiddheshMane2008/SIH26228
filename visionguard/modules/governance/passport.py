"""
Trust Passport Generator and Cryptographic Verifier for VisionGuard

Consolidates all assurance evidence across the CV lifecycle into ONE signed artifact.
"""

import json
from typing import Any, Dict, List, Optional, Tuple

from visionguard.core.crypto import KeyPair, canonical_json_hash, sha256_text, verify_signature
from visionguard.core.schemas import (
    BlastRadiusTrace,
    DataSentinelResult,
    DispositionEnum,
    Finding,
    ModelAuditorResult,
    ProvenanceAuditResult,
    RedTeamEvaluationSummary,
    ShiftDiagnosticianResult,
    TrustPassport
)
from visionguard.modules.data_sentinel.detectors import _now_iso


class TrustPassportGenerator:
    """Consolidates lifecycle audit results into a signed Trust Passport."""

    def __init__(self, keypair: Optional[KeyPair] = None):
        self.keypair = keypair or KeyPair.generate()

    def generate(
        self,
        audited_assets: Dict[str, Any],
        data_sentinel_res: Optional[DataSentinelResult] = None,
        model_auditor_res: Optional[ModelAuditorResult] = None,
        provenance_res: Optional[ProvenanceAuditResult] = None,
        shift_res: Optional[ShiftDiagnosticianResult] = None,
        blast_radius_trace: Optional[BlastRadiusTrace] = None,
        red_team_summary: Optional[RedTeamEvaluationSummary] = None,
        passport_id: Optional[str] = None
    ) -> TrustPassport:
        pid = passport_id or f"PASSPORT-{_now_iso()[:10]}-{self.keypair.public_key_hex[:8].upper()}"
        ts = _now_iso()

        # 1. Collect module dispositions
        module_dispositions: Dict[str, DispositionEnum] = {}
        all_findings: List[Finding] = []

        if data_sentinel_res:
            module_dispositions["DATA_SENTINEL"] = data_sentinel_res.overall_disposition
            all_findings.extend(data_sentinel_res.findings)
        if model_auditor_res:
            module_dispositions["MODEL_AUDITOR"] = model_auditor_res.overall_disposition
            all_findings.extend(model_auditor_res.findings)
        if provenance_res:
            module_dispositions["PROVENANCE_ENGINE"] = provenance_res.overall_disposition
            all_findings.extend(provenance_res.findings)
        if shift_res:
            module_dispositions["SHIFT_DIAGNOSTICIAN"] = shift_res.overall_disposition
            all_findings.extend(shift_res.findings)

        # 2. Overall Disposition Determination
        has_quarantine = any(d == DispositionEnum.QUARANTINE for d in module_dispositions.values())
        has_review = any(d == DispositionEnum.REVIEW for d in module_dispositions.values())

        if has_quarantine:
            overall_disposition = DispositionEnum.QUARANTINE
        elif has_review:
            overall_disposition = DispositionEnum.REVIEW
        else:
            overall_disposition = DispositionEnum.ACCEPT

        # 3. Confidence Calculation
        confidences = []
        if data_sentinel_res: confidences.append(data_sentinel_res.confidence)
        if model_auditor_res: confidences.append(model_auditor_res.confidence)
        if provenance_res: confidences.append(provenance_res.confidence)
        if shift_res: confidences.append(shift_res.confidence)
        overall_confidence = round(float(sum(confidences) / len(confidences)), 2) if confidences else 0.85

        # 4. Findings Summary
        findings_summary = {
            "total": len(all_findings),
            "critical": sum(1 for f in all_findings if f.severity.value == "CRITICAL"),
            "high": sum(1 for f in all_findings if f.severity.value == "HIGH"),
            "medium": sum(1 for f in all_findings if f.severity.value == "MEDIUM"),
            "low": sum(1 for f in all_findings if f.severity.value == "LOW"),
        }

        # Top 5 most severe findings
        top_findings = sorted(
            all_findings,
            key=lambda x: (
                0 if x.severity.value == "CRITICAL" else
                1 if x.severity.value == "HIGH" else
                2 if x.severity.value == "MEDIUM" else 3
            )
        )[:5]

        # 5. Executive Summary
        exec_summary = (
            f"VisionGuard Air-Gapped Lifecycle Assurance Audit. Overall Disposition: {overall_disposition.value}. "
            f"Confidence: {overall_confidence:.0%}. Audited {findings_summary['total']} total findings "
            f"({findings_summary['critical']} Critical, {findings_summary['high']} High). "
        )
        if overall_disposition == DispositionEnum.ACCEPT:
            exec_summary += "All audited assets satisfy cryptographic integrity, distributional consistency, and provenance verification."
        elif overall_disposition == DispositionEnum.REVIEW:
            exec_summary += "Operational anomalies or non-catastrophic distribution drift detected requiring human supervisor review."
        else:
            exec_summary += "Critical integrity compromises detected (poisoning, tampering, model substitution, or chain breach). Immediate quarantine recommended."

        # 6. Explicit Coverage Statement
        coverage_statement = [
            "Data Sentinel: Exact duplicate hash detection (SHA-256), near-duplicate perceptual flooding (pHash + Cosine), kNN label purity, OOD insertion, and corner trigger pattern detection.",
            "Model Auditor: White-box parameter statistics, weight SHA-256 digest, graph hash, parameter outlier detection (4-sigma), and 20-image golden behavioral battery with trigger sweep.",
            "Provenance Engine: Tamper-evident sequential hash chaining, Ed25519 digital signatures per record, and signed head checkpoint verification.",
            "Shift Diagnostician: Population Stability Index (PSI) on photometric distributions, 1D Wasserstein distance on sharpness/color, and embedding centroid drift.",
            "Blast Radius: Downstream DAG impact tracing connecting Contributor -> Batch -> Dataset -> Model -> Inference -> Output."
        ]

        # 7. Explicit Limitations Statement (Harsh Truths & Honest Claims)
        explicit_limitations = [
            "VisionGuard detects defined classes of training-data poisoning under specified assumptions; it does NOT claim universal detection of every possible attack.",
            "Does NOT claim guaranteed detection of clean-label poisoning, invisible-noise backdoors, or fully adaptive adversaries.",
            "A cryptographic model digest provides strong evidence of exact artifact identity; behavioral battery provides evidence of consistency; none of these alone proves all hidden compromises are absent.",
            "Baseline assurance policy: Audits are conducted strictly without retraining the contributed model.",
            "Blast radius provides attack-path lineage attribution; it does NOT claim identification of real-world physical individuals or IP addresses.",
            "Watermarking is an auxiliary provenance aid; cryptographic signatures remain the actual tamper-proof proof."
        ]

        # 8. Remediation Recommendations
        remediations = []
        for f in top_findings:
            if f.recommended_action and f.recommended_action not in remediations:
                remediations.append(f.recommended_action)
        if not remediations:
            remediations.append("No immediate remediation required. Assets meet baseline assurance criteria.")

        # 9. Cryptographic Signing of Passport
        passport_payload = {
            "passport_id": pid,
            "generated_at": ts,
            "engine_version": "1.0.0",
            "operating_mode": "OFFLINE_AIR_GAPPED",
            "audited_assets": audited_assets,
            "overall_disposition": overall_disposition.value,
            "overall_confidence": overall_confidence,
            "executive_summary": exec_summary,
            "module_dispositions": {k: v.value for k, v in module_dispositions.items()},
            "findings_summary": findings_summary,
            "top_findings": [f.model_dump() for f in top_findings],
            "blast_radius_summary": blast_radius_trace.model_dump() if blast_radius_trace else None,
            "coverage_statement": coverage_statement,
            "explicit_limitations": explicit_limitations,
            "remediation_recommendations": remediations,
            "signer_public_key_hex": self.keypair.public_key_hex
        }

        canonical_str, digest = canonical_json_hash(passport_payload)
        signature = self.keypair.sign(digest)

        return TrustPassport(
            passport_id=pid,
            generated_at=ts,
            engine_version="1.0.0",
            operating_mode="OFFLINE_AIR_GAPPED",
            audited_assets=audited_assets,
            overall_disposition=overall_disposition,
            overall_confidence=overall_confidence,
            executive_summary=exec_summary,
            module_dispositions=module_dispositions,
            findings_summary=findings_summary,
            top_findings=top_findings,
            blast_radius_summary=blast_radius_trace.model_dump() if blast_radius_trace else None,
            coverage_statement=coverage_statement,
            explicit_limitations=explicit_limitations,
            remediation_recommendations=remediations,
            signer_public_key_hex=self.keypair.public_key_hex,
            passport_digest=digest,
            signature_hex=signature
        )


def verify_trust_passport(passport: TrustPassport) -> Tuple[bool, str]:
    """Independently verifies the cryptographic authenticity and integrity of a Trust Passport."""
    payload = {
        "passport_id": passport.passport_id,
        "generated_at": passport.generated_at,
        "engine_version": passport.engine_version,
        "operating_mode": passport.operating_mode,
        "audited_assets": passport.audited_assets,
        "overall_disposition": passport.overall_disposition.value,
        "overall_confidence": passport.overall_confidence,
        "executive_summary": passport.executive_summary,
        "module_dispositions": {k: v.value for k, v in passport.module_dispositions.items()},
        "findings_summary": passport.findings_summary,
        "top_findings": [f.model_dump() for f in passport.top_findings],
        "blast_radius_summary": passport.blast_radius_summary,
        "coverage_statement": passport.coverage_statement,
        "explicit_limitations": passport.explicit_limitations,
        "remediation_recommendations": passport.remediation_recommendations,
        "signer_public_key_hex": passport.signer_public_key_hex
    }

    _, computed_digest = canonical_json_hash(payload)

    if computed_digest != passport.passport_digest:
        return False, f"Passport digest mismatch: Payload was modified post-signing (Computed: {computed_digest[:16]}..., Stored: {passport.passport_digest[:16]}...)"

    valid_sig = verify_signature(
        public_key_hex=passport.signer_public_key_hex,
        message=passport.passport_digest,
        signature_hex=passport.signature_hex
    )

    if not valid_sig:
        return False, "Digital signature verification failed. Private key mismatch or corrupted signature."

    return True, "Trust Passport signature and cryptographic digest verified successfully."
