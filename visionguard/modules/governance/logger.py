"""
Tamper-Evident Hash-Chained Audit Logger for VisionGuard
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from visionguard.core.crypto import sha256_text
from visionguard.core.schemas import Finding
from visionguard.modules.data_sentinel.detectors import _now_iso

GENESIS_AUDIT_HASH = "0" * 64


class AuditLogger:
    """Writes findings and audit events to an immutable hash-chained JSONL log file."""

    def __init__(self, log_path: Path):
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.previous_hash = GENESIS_AUDIT_HASH
        self.entry_count = 0
        self._initialize_from_existing()

    def _initialize_from_existing(self):
        if self.log_path.is_file():
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entry = json.loads(line)
                        self.previous_hash = entry.get("entry_hash", self.previous_hash)
                        self.entry_count += 1

    def log_finding(self, finding: Finding) -> str:
        """Appends a finding to the hash-chained audit log."""
        payload = finding.model_dump()
        ts = _now_iso()
        seq = self.entry_count

        entry_data = {
            "seq": seq,
            "previous_hash": self.previous_hash,
            "timestamp": ts,
            "finding": payload
        }

        canonical_str = json.dumps(entry_data, sort_keys=True)
        entry_hash = sha256_text(canonical_str)
        entry_data["entry_hash"] = entry_hash

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry_data) + "\n")

        self.previous_hash = entry_hash
        self.entry_count += 1
        return entry_hash

    def log_findings(self, findings: List[Finding]) -> List[str]:
        return [self.log_finding(f) for f in findings]
