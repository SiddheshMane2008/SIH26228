"""
JSON Schema Exporter for VisionGuard Findings & Trust Passport
"""

import json
from pathlib import Path
from typing import Dict, Any
from visionguard.core.schemas import Finding, TrustPassport, DataSentinelResult, ModelAuditorResult, ProvenanceAuditResult, ShiftDiagnosticianResult


def export_all_schemas(output_dir: Path) -> Dict[str, Any]:
    """Exports standardized JSON schemas for programmatic consumption."""
    output_dir.mkdir(parents=True, exist_ok=True)
    
    schemas = {
        "finding.schema.json": Finding.model_json_schema(),
        "trust_passport.schema.json": TrustPassport.model_json_schema(),
        "data_sentinel_result.schema.json": DataSentinelResult.model_json_schema(),
        "model_auditor_result.schema.json": ModelAuditorResult.model_json_schema(),
        "provenance_result.schema.json": ProvenanceAuditResult.model_json_schema(),
        "shift_result.schema.json": ShiftDiagnosticianResult.model_json_schema()
    }

    for filename, schema in schemas.items():
        with open(output_dir / filename, "w", encoding="utf-8") as f:
            json.dump(schema, f, indent=2)

    return schemas
