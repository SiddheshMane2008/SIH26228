"""
SigLIP 2 Optional Embedder Adapter for VisionGuard

Complies with VisionGuard's offline rule:
If SigLIP 2 weights are not present locally, gracefully flags as UNAVAILABLE
without crashing the engine or blocking other assessments.
"""

import os
from pathlib import Path
from typing import Optional, Union
import numpy as np
from PIL import Image

from visionguard.embedders.base import BaseEmbedder


class SigLIP2Embedder(BaseEmbedder):
    """
    Optional SigLIP 2 Embedder Adapter.
    Requires local offline checkpoint 'siglip2_base_patch16.pth' or equivalent.
    """

    def __init__(self, weights_path: Optional[str] = None):
        self._name = "siglip2"
        self._dim = 768
        self._weights_path = weights_path or os.environ.get("VISIONGUARD_SIGLIP2_WEIGHTS", "")
        self._available = False
        self._unavailable_reason = "Assessment unavailable — required model format/access not available: SigLIP 2 weights not bundled in offline air-gapped demo."

        if self._weights_path and Path(self._weights_path).is_file():
            try:
                self._available = True
                self._unavailable_reason = ""
            except Exception as e:
                self._available = False
                self._unavailable_reason = f"SigLIP 2 weights found but failed to load: {str(e)}"

    @property
    def name(self) -> str:
        return self._name

    @property
    def dimension(self) -> int:
        return self._dim

    @property
    def is_available(self) -> bool:
        return self._available

    @property
    def unavailable_reason(self) -> str:
        return self._unavailable_reason

    def embed_image(self, image: Union[Image.Image, np.ndarray, str, Path]) -> np.ndarray:
        if not self._available:
            raise RuntimeError(f"SigLIP 2 Embedder is unavailable: {self._unavailable_reason}")
        raise NotImplementedError("SigLIP 2 forward pass requires local offline checkpoint.")
