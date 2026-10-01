"""
Base Embedder Abstract Interface for VisionGuard
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Union
import numpy as np
from PIL import Image


class BaseEmbedder(ABC):
    """Abstract base class for all vision embedders."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the embedder."""
        pass

    @property
    @abstractmethod
    def dimension(self) -> int:
        """Dimensionality of the feature vector."""
        pass

    @property
    @abstractmethod
    def is_available(self) -> bool:
        """Whether model weights and runtime are available locally offline."""
        pass

    @property
    @abstractmethod
    def unavailable_reason(self) -> str:
        """Reason if unavailable."""
        pass

    @abstractmethod
    def embed_image(self, image: Union[Image.Image, np.ndarray, str, Path]) -> np.ndarray:
        """
        Embed a single image into an L2-normalized 1D vector (dim,).
        """
        pass

    def embed_batch(self, images: List[Union[Image.Image, np.ndarray, str, Path]]) -> np.ndarray:
        """
        Embed a list of images into an L2-normalized 2D matrix (N, dim).
        """
        vectors = [self.embed_image(img) for img in images]
        if not vectors:
            return np.empty((0, self.dimension), dtype=np.float32)
        return np.vstack(vectors)
