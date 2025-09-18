"""
RBAC Manager Library

A comprehensive tool for managing operator bundle metadata and RBAC resources.
"""

__version__ = "1.0.0"
__author__ = "OLMv1 Project"

# Core libraries
from .core import OpenShiftAuth, ConfigManager
from .core.exceptions import RBACManagerError, AuthenticationError, ConfigurationError

# Catalogd libraries
from .catalogd import CatalogdService, CatalogdClient, NDJSONParser, CatalogdCache, CatalogdSession

# OPM libraries
from .opm import BundleProcessor, YAMLManifestGenerator, HelmValuesGenerator, OPMClient

# Main application and help
from .help_manager import HelpManager
from .main_app import RBACManager, main

__all__ = [
    # Core
    'OpenShiftAuth',
    'ConfigManager',
    'RBACManagerError',
    'AuthenticationError', 
    'ConfigurationError',
    # Catalogd
    'CatalogdService',
    'CatalogdClient',
    'NDJSONParser',
    'CatalogdCache',
    'CatalogdSession',
    # OPM
    'BundleProcessor', 
    'YAMLManifestGenerator',
    'HelmValuesGenerator',
    'OPMClient',
    # Main
    'HelpManager',
    'RBACManager',
    'main'
]
