"""
Cryptographic Utilities for VisionGuard

Provides:
- Ed25519 key management, digital signing, and signature verification
- SHA-256 for files, memory buffers, tensors, and canonical JSON
- Discrete Cosine Transform (DCT) based perceptual hashing (pHash)
- Merkle root computation and hash-chain verification
"""

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
from PIL import Image
from scipy.fftpack import dct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


# ==========================================
# 1. Ed25519 Asymmetric Cryptography
# ==========================================

class KeyPair:
    """Manages an Ed25519 private/public keypair."""
    def __init__(self, private_key: Optional[ed25519.Ed25519PrivateKey] = None):
        if private_key is None:
            self._private_key = ed25519.Ed25519PrivateKey.generate()
        else:
            self._private_key = private_key
        self._public_key = self._private_key.public_key()

    @classmethod
    def generate(cls) -> "KeyPair":
        return cls(ed25519.Ed25519PrivateKey.generate())

    @classmethod
    def from_private_bytes(cls, raw_bytes: bytes) -> "KeyPair":
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(raw_bytes)
        return cls(priv)

    @property
    def public_key_hex(self) -> str:
        raw = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return raw.hex()

    @property
    def private_key_hex(self) -> str:
        raw = self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        return raw.hex()

    def sign(self, message: Union[bytes, str]) -> str:
        """Sign message bytes or UTF-8 string, returning hex signature."""
        if isinstance(message, str):
            data = message.encode("utf-8")
        else:
            data = message
        sig_bytes = self._private_key.sign(data)
        return sig_bytes.hex()


def verify_signature(public_key_hex: str, message: Union[bytes, str], signature_hex: str) -> bool:
    """Verify an Ed25519 signature given the public key hex and message."""
    try:
        pub_bytes = bytes.fromhex(public_key_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        if isinstance(message, str):
            data = message.encode("utf-8")
        else:
            data = message

        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub_key.verify(sig_bytes, data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# ==========================================
# 2. SHA-256 Hashing Utilities
# ==========================================

def sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    """Compute SHA-256 of UTF-8 text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(filepath: Union[str, Path], chunk_size: int = 65536) -> str:
    """Stream a file and compute its SHA-256 hash without loading entire file into RAM."""
    h = hashlib.sha256()
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"Cannot hash non-existent file: {filepath}")
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def canonical_json_hash(data: Any) -> Tuple[str, str]:
    """
    Produce canonical, deterministic JSON string and its SHA-256 hash.
    Ensures identical dictionaries always result in identical hashes.
    """
    canonical_str = json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    digest = sha256_text(canonical_str)
    return canonical_str, digest


# ==========================================
# 3. Perceptual Hashing (pHash)
# ==========================================

def compute_phash(image: Union[Image.Image, str, Path], hash_size: int = 8, highfreq_factor: int = 4) -> str:
    """
    Compute a 64-bit DCT-based perceptual hash (pHash) for an image.
    1. Convert to grayscale
    2. Resize to 32x32 (hash_size * highfreq_factor)
    3. Compute 2D DCT
    4. Keep the top-left 8x8 low-frequency components
    5. Compare to median value -> 64-bit binary vector -> 16 hex chars
    """
    if isinstance(image, (str, Path)):
        img = Image.open(image).convert("L")
    else:
        img = image.convert("L")

    img_size = hash_size * highfreq_factor
    img = img.resize((img_size, img_size), Image.Resampling.LANCZOS)
    pixels = np.asarray(img, dtype=np.float32)

    # 2D Discrete Cosine Transform
    dct_2d = dct(dct(pixels, axis=0, norm='ortho'), axis=1, norm='ortho')

    # Extract top-left low frequencies (excluding DC component at [0,0] for brightness invariance)
    sub_dct = dct_2d[:hash_size, :hash_size]
    med = np.median(sub_dct)

    # Boolean bitmask
    diff = sub_dct > med
    # Flatten to integer
    bit_str = "".join("1" if b else "0" for b in diff.flatten())
    # Format to 16-character hex
    int_val = int(bit_str, 2)
    return f"{int_val:016x}"


def phash_hamming_distance(hash1_hex: str, hash2_hex: str) -> int:
    """Compute Hamming distance (differing bits) between two 16-hex-char pHashes (0-64)."""
    val1 = int(hash1_hex, 16)
    val2 = int(hash2_hex, 16)
    xor_val = val1 ^ val2
    return bin(xor_val).count('1')


# ==========================================
# 4. Merkle Root & Hash-Chaining
# ==========================================

def compute_merkle_root(leaf_hashes: List[str]) -> str:
    """Compute standard cryptographic Merkle root from leaf hashes."""
    if not leaf_hashes:
        return sha256_text("EMPTY_MERKLE_TREE")
    if len(leaf_hashes) == 1:
        return leaf_hashes[0]

    current_level = list(leaf_hashes)
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            combined = sha256_text(left + right)
            next_level.append(combined)
        current_level = next_level
    return current_level[0]


def compute_record_hash(
    sequence_number: int,
    previous_record_hash: str,
    input_sha256: str,
    model_digest: str,
    output_digest: str,
    nonce: str,
    timestamp: str
) -> str:
    """Calculate the cryptographic hash linking an inference record into the chain."""
    payload = f"{sequence_number}:{previous_record_hash}:{input_sha256}:{model_digest}:{output_digest}:{nonce}:{timestamp}"
    return sha256_text(payload)
