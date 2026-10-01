"""
Vision Embedders Package for VisionGuard
"""

from visionguard.embedders.base import BaseEmbedder
from visionguard.embedders.mobilenet import MobileNetV3Embedder
from visionguard.embedders.dinov3 import DINOv3Embedder
from visionguard.embedders.siglip import SigLIP2Embedder
from visionguard.embedders.ensemble import EnsembleEmbedder
from visionguard.embedders.registry import embedder_registry

__all__ = [
    "BaseEmbedder",
    "MobileNetV3Embedder",
    "DINOv3Embedder",
    "SigLIP2Embedder",
    "EnsembleEmbedder",
    "embedder_registry",
]
