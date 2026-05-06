class KmsError(Exception):
    """Base class for KMS domain errors."""


class KeyNotFoundError(KmsError):
    """Raised when a key does not exist."""


class InvalidKeyStateError(KmsError):
    """Raised when a key state is invalid for the requested operation."""


class InvalidAllowedOpsError(KmsError):
    """Raised when allowed_ops contains unsupported values."""

