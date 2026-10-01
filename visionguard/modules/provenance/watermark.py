"""
Optional Watermarking Engine for VisionGuard Outputs

Policies:
- NONE
- VISIBLE (Overlays authorized text / badge + record ID)
- INVISIBLE (Embeds machine-detectable record ID via blue-channel LSB)
- BOTH

DISCLAIMER:
Watermarking is a visual and forensic marking aid, NOT the primary cryptographic proof.
The Ed25519 digital signature and hash chain remain the actual tamper-proof integrity mechanisms.
"""

from enum import Enum
from pathlib import Path
from typing import Optional, Tuple, Union
import numpy as np
from PIL import Image, ImageDraw, ImageFont


class WatermarkPolicy(str, Enum):
    NONE = "NONE"
    VISIBLE = "VISIBLE"
    INVISIBLE = "INVISIBLE"
    BOTH = "BOTH"


class Watermarker:
    """Applies visible and/or invisible watermarks to output images."""

    def __init__(self, policy: Union[WatermarkPolicy, str] = WatermarkPolicy.VISIBLE):
        if isinstance(policy, str):
            self.policy = WatermarkPolicy(policy.upper())
        else:
            self.policy = policy

    def apply(self, image: Image.Image, record_id: str, label_text: str = "VisionGuard Verified") -> Image.Image:
        """Apply watermarks based on active policy."""
        if self.policy == WatermarkPolicy.NONE:
            return image.copy()

        out_img = image.convert("RGB")

        if self.policy in (WatermarkPolicy.INVISIBLE, WatermarkPolicy.BOTH):
            out_img = self._embed_invisible_lsb(out_img, record_id)

        if self.policy in (WatermarkPolicy.VISIBLE, WatermarkPolicy.BOTH):
            out_img = self._apply_visible_badge(out_img, record_id, label_text)

        return out_img

    def _apply_visible_badge(self, img: Image.Image, record_id: str, label_text: str) -> Image.Image:
        """Draws a semi-transparent provenance badge in the lower-right corner."""
        badge_img = img.copy()
        draw = ImageDraw.Draw(badge_img)
        w, h = badge_img.size

        badge_w, badge_h = min(220, w - 10), 36
        x1, y1 = w - badge_w - 8, h - badge_h - 8
        x2, y2 = w - 8, h - 8

        # Draw semi-dark background pill
        draw.rectangle([x1, y1, x2, y2], fill=(15, 23, 42))
        draw.rectangle([x1, y1, x2, y2], outline=(59, 130, 246), width=1)

        # Draw text
        draw.text((x1 + 8, y1 + 4), f"🛡️ {label_text}", fill=(240, 240, 240))
        draw.text((x1 + 8, y1 + 18), f"ID: {record_id}", fill=(148, 163, 184))

        return badge_img

    def _embed_invisible_lsb(self, img: Image.Image, payload: str) -> Image.Image:
        """Embeds UTF-8 payload into the Least Significant Bit (LSB) of the blue channel."""
        arr = np.asarray(img, dtype=np.uint8).copy()
        # Convert payload to binary bitstream with 16-bit length header
        raw_bytes = payload.encode("utf-8")
        length = len(raw_bytes)
        header = length.to_bytes(2, byteorder="big")
        full_stream = header + raw_bytes
        
        bits = []
        for b in full_stream:
            for shift in range(7, -1, -1):
                bits.append((b >> shift) & 1)

        h, w, c = arr.shape
        total_pixels = h * w
        if len(bits) > total_pixels:
            return img  # Image too small to embed payload safely

        flat_blue = arr[:, :, 2].flatten()
        for idx, bit in enumerate(bits):
            flat_blue[idx] = (flat_blue[idx] & 0xFE) | bit

        arr[:, :, 2] = flat_blue.reshape((h, w))
        return Image.fromarray(arr)

    @staticmethod
    def extract_invisible_lsb(img: Image.Image) -> Optional[str]:
        """Extracts the LSB payload from the blue channel if present."""
        try:
            arr = np.asarray(img.convert("RGB"), dtype=np.uint8)
            flat_blue = arr[:, :, 2].flatten()
            if len(flat_blue) < 16:
                return None

            # Read 16-bit length header
            header_bits = [flat_blue[i] & 1 for i in range(16)]
            length = 0
            for b in header_bits:
                length = (length << 1) | b

            if length <= 0 or length > 512 or len(flat_blue) < 16 + length * 8:
                return None

            payload_bits = [flat_blue[16 + i] & 1 for i in range(length * 8)]
            byte_vals = []
            for i in range(0, len(payload_bits), 8):
                byte_val = 0
                for b in payload_bits[i:i + 8]:
                    byte_val = (byte_val << 1) | b
                byte_vals.append(byte_val)

            return bytes(byte_vals).decode("utf-8")
        except Exception:
            return None
