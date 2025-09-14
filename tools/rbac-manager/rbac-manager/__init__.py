"""
RBAC Manager

A comprehensive tool to fetch operator bundle metadata using opm binary
and interact with OpenShift catalogs. Generates RBAC resources and 
Helm values for OLMv1 operators.
"""

__version__ = "1.0.0"
__author__ = "OLMv1 Project"

from .libs import CatalogManager, BundleProcessor, YAMLGenerator, HelmGenerator, HelpManager, RBACManager, main

__all__ = [
    'CatalogManager',
    'BundleProcessor', 
    'YAMLGenerator',
    'HelmGenerator',
    'HelpManager',
    'RBACManager',
    'main'
]
