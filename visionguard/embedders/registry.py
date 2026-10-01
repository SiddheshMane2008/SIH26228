"""
Embedder Registry & Factory for VisionGuard

Provides plugin-style extensible registration.
Enforces fallback to MobileNetV3 if a requested heavy embedder is unavailable.
"""

from typing import Callable, Dict, List, Optional
import logging

from visionguard.embedders.base import BaseEmbedder
from visionguard.embedders.mobilenet import MobileNetV3Embedder
from visionguard.embedders.dinov3 import DINOv3Embedder
from visionguard.embedders.siglip import SigLIP2Embedder
from visionguard.embedders.ensemble import EnsembleEmbedder

logger = logging.getLogger("visionguard.embedders")


class EmbedderRegistry:
    """Singleton/Factory for vision embedders."""

    def __init__(self):
        self._factories: Dict[str, Callable[[], BaseEmbedder]] = {}
        self._instances: Dict[str, BaseEmbedder] = {}
        self._register_defaults()

    def _register_defaults(self):
        self.register("mobilenet_v3", lambda: MobileNetV3Embedder(device="cpu", cache_embeddings=True))
        self.register("dinov3", lambda: DINOv3Embedder())
        self.register("siglip2", lambda: SigLIP2Embedder())
        self.register("ensemble", lambda: EnsembleEmbedder([
            self.get("mobilenet_v3"),
            self.get("dinov3"),
            self.get("siglip2")
        ]))

    def register(self, name: str, factory: Callable[[], BaseEmbedder]):
        """Register a new embedder plugin."""
        self._factories[name.lower()] = factory
        # Invalidate cached instance if re-registered
        self._instances.pop(name.lower(), None)

    def get(self, name: str, fallback_to_default: bool = True) -> BaseEmbedder:
        """
        Get or instantiate an embedder by name.
        If the embedder is unavailable and fallback_to_default is True,
        returns the robust MobileNetV3 fallback with a logged notice.
        """
        key = name.lower()
        if key not in self._instances:
            if key not in self._factories:
                if fallback_to_default:
                    logger.warning(f"Unknown embedder '{name}'. Falling back to mobilenet_v3.")
                    return self.get("mobilenet_v3", fallback_to_default=False)
                raise KeyError(f"Embedder '{name}' is not registered.")
            
            instance = self._factories[key]()
            self._instances[key] = instance

        inst = self._instances[key]
        if not inst.is_available and fallback_to_default and key != "mobilenet_v3":
            logger.warning(
                f"Requested embedder '{name}' is unavailable ({inst.unavailable_reason}). "
                f"Falling back to mobilenet_v3."
            )
            return self.get("mobilenet_v3", fallback_to_default=False)

        return inst

    def list_all(self) -> List[Dict[str, any]]:
        """List all registered embedders and their current availability."""
        results = []
        for name in list(self._factories.keys()):
            inst = self.get(name, fallback_to_default=False)
            results.append({
                "name": inst.name,
                "dimension": inst.dimension,
                "available": inst.is_available,
                "unavailable_reason": inst.unavailable_reason if not inst.is_available else None
            })
        return results


# Global singleton registry
embedder_registry = EmbedderRegistry()
