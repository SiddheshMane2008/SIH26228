"""
C2PA-Inspired Signed Provenance Sidecar Generator

IMPORTANT CLAIM:
This generates a C2PA-inspired signed JSON provenance sidecar.
It is explicitly NOT claimed to be official C2PA compliance or interoperability.
"""

from typing import Any, Dict, Optional
from visionguard.core.crypto import KeyPair, canonical_json_hash
from visionguard.core.schemas import ProvenanceRecord
from visionguard.modules.data_sentinel.detectors import _now_iso


class ProvenanceSidecarGenerator:
    """Generates signed provenance sidecar metadata for output artifacts."""

    @staticmethod
    def generate(
        record: ProvenanceRecord,
        keypair: KeyPair,
        output_image_sha256: Optional[str] = None
    ) -> Dict[str, Any]:
        claim = {
            "format": "VisionGuard-C2PA-Inspired-Sidecar",
            "spec_version": "0.9.1-prototype",
            "generator": "VisionGuard Provenance Engine v1.0.0",
            "produced_at": _now_iso(),
            "assertions": {
                "record_id": record.record_id,
                "sequence_number": record.sequence_number,
                "input_sha256": record.input_sha256,
                "model_digest": record.model_digest,
                "output_image_sha256": output_image_sha256 or record.record_hash,
                "preprocessing": record.preprocessing_config,
                "inference_config": record.inference_config
            },
            "signer": {
                "public_key_hex": keypair.public_key_hex,
                "algorithm": "Ed25519"
            },
            "disclaimer": "C2PA-inspired demonstration sidecar. Does not claim official C2PA standard compliance."
        }

        canonical_str, digest = canonical_json_hash(claim)
        claim["sidecar_digest"] = digest
        claim["signature_hex"] = keypair.sign(digest)
        return claim
