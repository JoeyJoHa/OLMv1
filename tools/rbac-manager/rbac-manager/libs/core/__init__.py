"""
Core Libraries

Shared functionality and utilities for the RBAC Manager tool.
"""

from .auth import OpenShiftAuth
from .config import ConfigManager
from .constants import (
    KubernetesConstants, OPMConstants, NetworkConstants, 
    FileConstants, ErrorMessages
)
from .exceptions import (
    RBACManagerError, AuthenticationError, ConfigurationError,
    CatalogdError, OPMError, BundleProcessingError, ParsingError, NetworkError
)
from .protocols import AuthProvider, ConfigProvider, BundleProvider, CatalogdProvider, HelpProvider
from .utils import (
    setup_logging, validate_image_url,
    validate_namespace, validate_openshift_url, format_bytes,
    handle_api_error, mask_sensitive_info
)

__all__ = [
    # Main classes
    'OpenShiftAuth',
    'ConfigManager',
    # Constants
    'KubernetesConstants',
    'OPMConstants', 
    'NetworkConstants',
    'FileConstants',
    'ErrorMessages',
    # Exceptions
    'RBACManagerError',
    'AuthenticationError',
    'ConfigurationError',
    'CatalogdError',
    'OPMError',
    'BundleProcessingError',
    'ParsingError',
    'NetworkError',
    # Protocols
    'AuthProvider',
    'ConfigProvider',
    'BundleProvider',
    'CatalogdProvider',
    'HelpProvider',
    # Utilities
    'setup_logging',
    'validate_image_url',
    'validate_namespace',
    'validate_openshift_url',
    'format_bytes',
    'handle_api_error',
    'mask_sensitive_info'
]
