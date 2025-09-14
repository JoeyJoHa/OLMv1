"""
Custom Exceptions

Defines custom exception classes for the RBAC Manager tool.
"""


class RBACManagerError(Exception):
    """Base exception class for RBAC Manager errors"""
    pass


class AuthenticationError(RBACManagerError):
    """Raised when authentication fails"""
    pass


class ConfigurationError(RBACManagerError):
    """Raised when configuration is invalid or missing"""
    pass


class CatalogdError(RBACManagerError):
    """Raised when catalogd operations fail"""
    pass


class OPMError(RBACManagerError):
    """Raised when OPM operations fail"""
    pass


class BundleProcessingError(OPMError):
    """Raised when bundle processing fails"""
    pass


class NetworkError(RBACManagerError):
    """Raised when network operations fail"""
    pass


class ParsingError(RBACManagerError):
    """Raised when data parsing fails"""
    pass
