"""
RBAC Manager Library

A comprehensive tool for managing operator bundle metadata and RBAC resources.
"""

__version__ = "1.0.0"
__author__ = "OLMv1 Project"

from .catalog_manager import CatalogManager
from .bundle_processor import BundleProcessor
from .yaml_generator import YAMLGenerator
from .helm_generator import HelmGenerator
from .help_manager import HelpManager
from .main_app import RBACManager, main

__all__ = [
    'CatalogManager',
    'BundleProcessor', 
    'YAMLGenerator',
    'HelmGenerator',
    'HelpManager',
    'RBACManager',
    'main'
]
