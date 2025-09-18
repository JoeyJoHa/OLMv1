"""
RBAC Manager

A comprehensive tool to fetch operator bundle metadata using opm binary
and interact with OpenShift catalogs. Generates RBAC resources and 
Helm values for OLMv1 operators.
"""

__version__ = "1.0.0"
__author__ = "OLMv1 Project"

from .libs import (
    # Core
    OpenShiftAuth, ConfigManager, RBACManagerError, AuthenticationError, ConfigurationError,
    # Catalogd
    CatalogdService, CatalogdClient, NDJSONParser, CatalogdCache, CatalogdSession,
    # OPM
    BundleProcessor, YAMLManifestGenerator, HelmValuesGenerator, OPMClient,
    # Main
    HelpManager, RBACManager, main
)

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
