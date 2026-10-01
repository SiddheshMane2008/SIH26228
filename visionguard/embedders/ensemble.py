"""
Ensemble Embedder for VisionGuard

Combines available embedders (e.g. MobileNetV3 + available foundation models).
If optional models are unavailable, gracefully uses the available subset without crashing.
"""

from pathlib import Path
from typing import List, Optional, Union
import numpy as np
from PIL import Image

from visionguard.embedders.base import BaseEmbedder


class EnsembleEmbedder(BaseEmbedder):
    """Combines representations from multiple embedders."""

    def __init__(self, embedders: List[BaseEmbedder]):
        self._all_embedders = embedders
        self._active_embedders = [e for e in embedders if e.is_available]
        self._name = "ensemble"
        
        if self._active_embedders:
            self._dim = sum(e.dimension for e in self._active_embedders)
            self._available = True
            self._unavailable_reason = ""
        else:
            self._dim = 0
            self._available = False
            self._unavailable_reason = "No active sub-embedders available for ensemble."

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

    @property
    def active_embedder_names(self) -> List[str]:
        return [e.name for e in self._active_embedders]

    def embed_image(self, image: Union[Image.Image, np.ndarray, str, Path]) -> np.ndarray:
        if not self._available:
            raise RuntimeError(f"Ensemble is unavailable: {self._unavailable_reason}")

        vectors = [e.embed_image(image) for e in self._active_embedders]
        concatenated = np.concatenate(vectors)
        norm = np.linalg.norm(concatenated)
        if norm > 1e-12:
            return (concatenated / norm).astype(np.float32)
        return concatenated.astype(np.float32)
