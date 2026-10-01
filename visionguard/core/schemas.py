"""
Unified Data Schemas for VisionGuard

All modules in VisionGuard adhere to these strict Pydantic schemas.
Standardizing findings, disposition, cryptographic proofs, and the Trust Passport.
"""

from enum import Enum
from typing import Dict, List, Optional, Any, Union
from pydantic import BaseModel, Field


class ModuleEnum(str, Enum):
    DATA_SENTINEL = "DATA_SENTINEL"
    MODEL_AUDITOR = "MODEL_AUDITOR"
    PROVENANCE_ENGINE = "PROVENANCE_ENGINE"
    SHIFT_DIAGNOSTICIAN = "SHIFT_DIAGNOSTICIAN"
    BLAST_RADIUS = "BLAST_RADIUS"
    RED_TEAM = "RED_TEAM"
    GOVERNANCE = "GOVERNANCE"


class SeverityEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DispositionEnum(str, Enum):
    ACCEPT = "ACCEPT"
    REVIEW = "REVIEW"
    QUARANTINE = "QUARANTINE"


class AccessLevelEnum(str, Enum):
    WHITE_BOX = "WHITE_BOX"
    BLACK_BOX = "BLACK_BOX"
    UNAVAILABLE = "UNAVAILABLE"


class Finding(BaseModel):
    """Standardized finding schema across all VisionGuard modules."""
    finding_id: str = Field(..., description="Unique deterministic identifier, e.g. FIND-DS-001")
    module: ModuleEnum = Field(..., description="Reporting engine module")
    asset: str = Field(..., description="Target file, batch, model, or record ID")
    reason: str = Field(..., description="Human-readable description of detected condition")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Concrete forensic evidence metrics/hashes")
    severity: SeverityEnum = Field(..., description="Assessed impact severity")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score 0.0 to 1.0")
    disposition: DispositionEnum = Field(..., description="Recommended handling disposition")
    recommended_action: str = Field(..., description="Actionable remediation guidance")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp")


class DataSentinelResult(BaseModel):
    """Audit result for training-data integrity."""
    dataset_name: str
    format: str  # "coco", "yolo", "classification"
    total_samples: int
    clean_samples: int
    exact_duplicates_count: int = 0
    near_duplicates_count: int = 0
    label_anomalies_count: int = 0
    ood_samples_count: int = 0
    trigger_anomalies_count: int = 0
    contributor_risk: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    batch_risk: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    findings: List[Finding] = Field(default_factory=list)
    overall_disposition: DispositionEnum
    confidence: float
    limitations: List[str] = Field(default_factory=list)


class ModelAuditorResult(BaseModel):
    """Audit result for model integrity and fingerprinting."""
    model_name: str
    model_format: str  # "onnx", "pytorch", "torchscript", "unknown"
    access_level: AccessLevelEnum
    weight_digest: Optional[str] = None
    graph_hash: Optional[str] = None
    parameter_stats: Optional[Dict[str, Any]] = None
    activation_stats: Optional[Dict[str, Any]] = None
    golden_battery_consistency: Optional[float] = None
    trigger_sweep_sensitivity: Optional[float] = None
    findings: List[Finding] = Field(default_factory=list)
    overall_disposition: DispositionEnum
    confidence: float
    evidence_summary: Dict[str, Any] = Field(default_factory=dict)
    limitations: List[str] = Field(default_factory=list)


class ProvenanceRecord(BaseModel):
    """A single cryptographically linked inference record."""
    sequence_number: int
    record_id: str
    timestamp: str
    input_sha256: str
    model_digest: str
    preprocessing_config: Dict[str, Any]
    inference_config: Dict[str, Any]
    output: Any
    nonce: str
    previous_record_hash: str
    record_hash: str
    signature: str


class SignedHeadCheckpoint(BaseModel):
    """Signed head checkpoint anchoring the protected chain."""
    chain_id: str
    sequence_length: int
    head_record_hash: str
    merkle_root: str
    timestamp: str
    public_key_hex: str
    signature: str


class ProvenanceAuditResult(BaseModel):
    """Forensic verification result of the inference chain."""
    chain_id: str
    total_records: int
    chain_valid: bool
    tampered_records: List[int] = Field(default_factory=list)
    replay_records: List[int] = Field(default_factory=list)
    broken_links: List[int] = Field(default_factory=list)
    spot_check_passed: Optional[bool] = None
    spot_check_discrepancies: List[Dict[str, Any]] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    overall_disposition: DispositionEnum
    confidence: float
    limitations: List[str] = Field(default_factory=list)


class ShiftDiagnosticianResult(BaseModel):
    """Audit result for visual and embedding distribution shift."""
    baseline_id: str
    evaluation_id: str
    brightness_psi: float
    contrast_psi: float
    sharpness_wasserstein: float
    color_distribution_divergence: float
    embedding_drift_score: float
    composite_risk_score: float  # 0.0 (no shift) to 1.0 (extreme shift)
    characterization: str
    findings: List[Finding] = Field(default_factory=list)
    overall_disposition: DispositionEnum
    confidence: float
    limitations: List[str] = Field(default_factory=list)


class BlastRadiusTrace(BaseModel):
    """Traced impact graph across contributor, dataset, model, and inferences."""
    root_contributor: Optional[str] = None
    root_batch: Optional[str] = None
    affected_datasets: List[str] = Field(default_factory=list)
    affected_models: List[str] = Field(default_factory=list)
    affected_inference_records: List[str] = Field(default_factory=list)
    total_downstream_impact_count: int = 0
    severity: SeverityEnum = SeverityEnum.LOW
    description: str = ""


class RedTeamVariantResult(BaseModel):
    """Evaluation result of a red-team adversarial scenario."""
    attack_name: str
    attack_family: str  # "poisoning", "evasion", "tampering", "shift"
    sample_count: int
    detected_count: int
    precision: float
    recall: float
    f1_score: float
    held_out_evaluated: bool
    evidence_notes: str


class RedTeamEvaluationSummary(BaseModel):
    """Consolidated Red-Team in a Box evaluation."""
    timestamp: str
    random_seed: int
    scenarios_evaluated: List[RedTeamVariantResult] = Field(default_factory=list)
    macro_precision: float
    macro_recall: float
    macro_f1: float


class TrustPassport(BaseModel):
    """
    The Single Signed Assurance Artifact of VisionGuard.
    Consolidates data, model, provenance, shift, blast-radius, and red-team findings.
    """
    passport_id: str
    generated_at: str
    engine_version: str = "1.0.0"
    operating_mode: str = "OFFLINE_AIR_GAPPED"
    audited_assets: Dict[str, Any]
    overall_disposition: DispositionEnum
    overall_confidence: float
    executive_summary: str
    module_dispositions: Dict[str, DispositionEnum]
    findings_summary: Dict[str, int]
    top_findings: List[Finding]
    blast_radius_summary: Optional[Dict[str, Any]] = None
    coverage_statement: List[str]
    explicit_limitations: List[str]
    remediation_recommendations: List[str]
    signer_public_key_hex: str
    passport_digest: str
    signature_hex: str
