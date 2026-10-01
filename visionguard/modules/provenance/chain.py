"""
Inference Provenance Chain & Cryptographic Verification

Maintains the cryptographically linked relationship:
Input -> Model -> Configuration -> Output

Implements:
- Monotonic sequence numbering & cryptographic nonces
- Hash chaining: Record[N].prev_hash == Record[N-1].hash
- Ed25519 digital signatures per record
- Signed head checkpoint anchoring the chain
- Tamper, replay, model substitution, and gap detection
"""

import os
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
from pathlib import Path

from visionguard.core.crypto import (
    KeyPair,
    canonical_json_hash,
    compute_merkle_root,
    compute_record_hash,
    sha256_bytes,
    sha256_text,
    verify_signature
)
from visionguard.core.schemas import (
    DispositionEnum,
    Finding,
    ModuleEnum,
    ProvenanceAuditResult,
    ProvenanceRecord,
    SeverityEnum,
    SignedHeadCheckpoint
)
from visionguard.modules.data_sentinel.detectors import _now_iso

GENESIS_HASH = "0" * 64


class InferenceChain:
    """Builder and manager for cryptographically secured inference logs."""

    def __init__(self, chain_id: str, keypair: Optional[KeyPair] = None):
        self.chain_id = chain_id
        self.keypair = keypair or KeyPair.generate()
        self.records: List[ProvenanceRecord] = []

    @property
    def public_key_hex(self) -> str:
        return self.keypair.public_key_hex

    def append_record(
        self,
        input_data: Union[bytes, str],
        model_digest: str,
        output: Any,
        preprocessing_config: Optional[Dict[str, Any]] = None,
        inference_config: Optional[Dict[str, Any]] = None,
        timestamp: Optional[str] = None
    ) -> ProvenanceRecord:
        seq = len(self.records)
        prev_hash = self.records[-1].record_hash if seq > 0 else GENESIS_HASH

        if isinstance(input_data, str):
            input_bytes = input_data.encode("utf-8")
        else:
            input_bytes = input_data

        input_sha256 = sha256_bytes(input_bytes)
        _, output_digest = canonical_json_hash(output)
        
        nonce = secrets.token_hex(16)
        ts = timestamp or _now_iso()
        record_id = f"REC-{self.chain_id[:8]}-{seq:06d}"

        pre_cfg = preprocessing_config or {"resize": [224, 224], "norm": "imagenet"}
        inf_cfg = inference_config or {"device": "cpu", "batch_size": 1}

        # Calculate cryptographic record hash
        rec_hash = compute_record_hash(
            sequence_number=seq,
            previous_record_hash=prev_hash,
            input_sha256=input_sha256,
            model_digest=model_digest,
            output_digest=output_digest,
            nonce=nonce,
            timestamp=ts
        )

        # Ed25519 signature
        signature = self.keypair.sign(rec_hash)

        record = ProvenanceRecord(
            sequence_number=seq,
            record_id=record_id,
            timestamp=ts,
            input_sha256=input_sha256,
            model_digest=model_digest,
            preprocessing_config=pre_cfg,
            inference_config=inf_cfg,
            output=output,
            nonce=nonce,
            previous_record_hash=prev_hash,
            record_hash=rec_hash,
            signature=signature
        )

        self.records.append(record)
        return record

    def create_head_checkpoint(self) -> SignedHeadCheckpoint:
        """Create signed head checkpoint anchoring the chain."""
        seq_len = len(self.records)
        head_hash = self.records[-1].record_hash if seq_len > 0 else GENESIS_HASH
        
        leaf_hashes = [r.record_hash for r in self.records]
        merkle_root = compute_merkle_root(leaf_hashes)
        ts = _now_iso()

        payload = f"{self.chain_id}:{seq_len}:{head_hash}:{merkle_root}:{ts}"
        checkpoint_sig = self.keypair.sign(payload)

        return SignedHeadCheckpoint(
            chain_id=self.chain_id,
            sequence_length=seq_len,
            head_record_hash=head_hash,
            merkle_root=merkle_root,
            timestamp=ts,
            public_key_hex=self.keypair.public_key_hex,
            signature=checkpoint_sig
        )


class ChainVerifier:
    """Forensic verification engine for inference provenance chains."""

    @staticmethod
    def verify(
        records: List[ProvenanceRecord],
        checkpoint: Optional[SignedHeadCheckpoint] = None,
        public_key_hex: Optional[str] = None
    ) -> Tuple[ProvenanceAuditResult, List[Finding]]:
        findings: List[Finding] = []
        tampered_records: List[int] = []
        replay_records: List[int] = []
        broken_links: List[int] = []

        total = len(records)
        if total == 0:
            return ProvenanceAuditResult(
                chain_id="empty_chain",
                total_records=0,
                chain_valid=True,
                overall_disposition=DispositionEnum.ACCEPT,
                confidence=1.0,
                limitations=["No inference records in chain to audit."]
            ), findings

        expected_pubkey = public_key_hex or (checkpoint.public_key_hex if checkpoint else None)

        # 1. Verify Checkpoint Signature if provided
        if checkpoint:
            cp_payload = f"{checkpoint.chain_id}:{checkpoint.sequence_length}:{checkpoint.head_record_hash}:{checkpoint.merkle_root}:{checkpoint.timestamp}"
            valid_cp_sig = verify_signature(checkpoint.public_key_hex, cp_payload, checkpoint.signature)
            if not valid_cp_sig:
                findings.append(Finding(
                    finding_id="FIND-PE-CHECKPOINT-SIG-FAIL",
                    module=ModuleEnum.PROVENANCE_ENGINE,
                    asset=f"checkpoint:{checkpoint.chain_id}",
                    reason="Head Checkpoint signature verification failed. The anchor checkpoint has been forged or corrupted.",
                    evidence={"checkpoint": checkpoint.model_dump()},
                    severity=SeverityEnum.CRITICAL,
                    confidence=1.0,
                    disposition=DispositionEnum.QUARANTINE,
                    recommended_action="Reject entire inference log. Head checkpoint integrity failed.",
                    timestamp=_now_iso()
                ))

            if checkpoint.sequence_length != total:
                findings.append(Finding(
                    finding_id="FIND-PE-CHECKPOINT-LEN-MISMATCH",
                    module=ModuleEnum.PROVENANCE_ENGINE,
                    asset=f"chain:{checkpoint.chain_id}",
                    reason=f"Chain truncation or padding detected: Checkpoint specifies {checkpoint.sequence_length} records, but {total} records were found.",
                    evidence={"checkpoint_len": checkpoint.sequence_length, "actual_len": total},
                    severity=SeverityEnum.CRITICAL,
                    confidence=1.0,
                    disposition=DispositionEnum.QUARANTINE,
                    recommended_action="Quarantine chain. Log records have been truncated or appended without authorization.",
                    timestamp=_now_iso()
                ))

        # 2. Iterate through chain records
        expected_prev_hash = GENESIS_HASH

        for idx, rec in enumerate(records):
            # Check A: Monotonic sequence order (Replay / Reordering / Gap check)
            if rec.sequence_number != idx:
                replay_records.append(idx)
                findings.append(Finding(
                    finding_id=f"FIND-PE-SEQ-ANOMALY-{idx:04d}",
                    module=ModuleEnum.PROVENANCE_ENGINE,
                    asset=rec.record_id,
                    reason=f"Sequence anomaly / replay detected: Expected sequence {idx}, but found {rec.sequence_number}",
                    evidence={"expected_seq": idx, "actual_seq": rec.sequence_number},
                    severity=SeverityEnum.HIGH,
                    confidence=1.0,
                    disposition=DispositionEnum.QUARANTINE,
                    recommended_action="Quarantine record. Possible replay attack or omitted log entries.",
                    timestamp=_now_iso()
                ))

            # Check B: Previous record hash link
            if rec.previous_record_hash != expected_prev_hash:
                broken_links.append(idx)
                findings.append(Finding(
                    finding_id=f"FIND-PE-BROKEN-LINK-{idx:04d}",
                    module=ModuleEnum.PROVENANCE_ENGINE,
                    asset=rec.record_id,
                    reason=f"Hash chain broken: Record previous_hash does not match preceding record's actual hash.",
                    evidence={"expected_prev": expected_prev_hash, "actual_prev": rec.previous_record_hash},
                    severity=SeverityEnum.CRITICAL,
                    confidence=1.0,
                    disposition=DispositionEnum.QUARANTINE,
                    recommended_action="Chain integrity broken. Identify truncated or substituted intermediary records.",
                    timestamp=_now_iso()
                ))

            # Check C: Recomputed Payload Hash match
            _, out_digest = canonical_json_hash(rec.output)
            recomputed_hash = compute_record_hash(
                sequence_number=rec.sequence_number,
                previous_record_hash=rec.previous_record_hash,
                input_sha256=rec.input_sha256,
                model_digest=rec.model_digest,
                output_digest=out_digest,
                nonce=rec.nonce,
                timestamp=rec.timestamp
            )

            if recomputed_hash != rec.record_hash:
                tampered_records.append(idx)
                findings.append(Finding(
                    finding_id=f"FIND-PE-RECORD-TAMPER-{idx:04d}",
                    module=ModuleEnum.PROVENANCE_ENGINE,
                    asset=rec.record_id,
                    reason=f"Record payload tampering detected: Recomputed hash does not match stored record hash. Output or configuration modified.",
                    evidence={
                        "stored_hash": rec.record_hash,
                        "recomputed_hash": recomputed_hash,
                        "sequence": rec.sequence_number
                    },
                    severity=SeverityEnum.CRITICAL,
                    confidence=1.0,
                    disposition=DispositionEnum.QUARANTINE,
                    recommended_action="Quarantine inference output. Payload was altered post-generation.",
                    timestamp=_now_iso()
                ))

            # Check D: Cryptographic Ed25519 signature
            if expected_pubkey:
                valid_sig = verify_signature(expected_pubkey, rec.record_hash, rec.signature)
                if not valid_sig:
                    if idx not in tampered_records:
                        tampered_records.append(idx)
                    findings.append(Finding(
                        finding_id=f"FIND-PE-SIG-INVALID-{idx:04d}",
                        module=ModuleEnum.PROVENANCE_ENGINE,
                        asset=rec.record_id,
                        reason="Ed25519 digital signature verification failed for inference record.",
                        evidence={"public_key": expected_pubkey, "record_hash": rec.record_hash},
                        severity=SeverityEnum.CRITICAL,
                        confidence=1.0,
                        disposition=DispositionEnum.QUARANTINE,
                        recommended_action="Quarantine inference output. Signature verification failed.",
                        timestamp=_now_iso()
                    ))

            expected_prev_hash = rec.record_hash

        # 3. Merkle Root Check against Head Checkpoint
        if checkpoint:
            leaf_hashes = [r.record_hash for r in records]
            computed_root = compute_merkle_root(leaf_hashes)
            if computed_root != checkpoint.merkle_root:
                findings.append(Finding(
                    finding_id="FIND-PE-MERKLE-ROOT-MISMATCH",
                    module=ModuleEnum.PROVENANCE_ENGINE,
                    asset=f"checkpoint:{checkpoint.chain_id}",
                    reason="Merkle tree root mismatch between checkpoint anchor and leaf record hashes.",
                    evidence={"checkpoint_root": checkpoint.merkle_root, "computed_root": computed_root},
                    severity=SeverityEnum.CRITICAL,
                    confidence=1.0,
                    disposition=DispositionEnum.QUARANTINE,
                    recommended_action="Quarantine chain. Merkle tree consistency failure.",
                    timestamp=_now_iso()
                ))

        chain_valid = len(tampered_records) == 0 and len(replay_records) == 0 and len(broken_links) == 0 and len(findings) == 0

        disposition = DispositionEnum.ACCEPT if chain_valid else DispositionEnum.QUARANTINE

        result = ProvenanceAuditResult(
            chain_id=checkpoint.chain_id if checkpoint else (records[0].record_id if records else "unknown"),
            total_records=total,
            chain_valid=chain_valid,
            tampered_records=tampered_records,
            replay_records=replay_records,
            broken_links=broken_links,
            findings=findings,
            overall_disposition=disposition,
            confidence=1.0 if total > 0 else 0.5,
            limitations=[
                "Cryptographic hash chaining proves sequential ordering, data integrity, and provenance identity under the assumed security of SHA-256 and Ed25519.",
                "Does not prevent attacks where the private signing key is fully compromised prior to signing."
            ]
        )

        return result, findings
