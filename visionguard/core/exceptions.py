"""
VisionGuard Exception Hierarchy
"""

class VisionGuardError(Exception):
    """Base exception for all VisionGuard errors."""
    pass


class DatasetIntegrityError(VisionGuardError):
    """Raised when dataset cannot be parsed or has catastrophic corruption."""
    pass


class ModelFormatError(VisionGuardError):
    """Raised when model format cannot be loaded or is invalid."""
    pass


class ProvenanceTamperError(VisionGuardError):
    """Raised when cryptographic chain or signature verification fails."""
    pass


class DistributionShiftError(VisionGuardError):
    """Raised when distribution shift analysis cannot be completed."""
    pass


class ConfigurationError(VisionGuardError):
    """Raised when configuration values or plugins are invalid."""
    pass
