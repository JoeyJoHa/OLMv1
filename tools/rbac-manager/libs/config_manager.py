"""
Configuration Manager Module.

This module handles configuration file loading, parsing, and management
for the RBAC Manager application. It provides YAML-based configuration
with environment variable support and default value handling.

Separated from config_utils.py to follow the Single Responsibility Principle.
"""

"""
Configuration and CLI Management Module.

This module provides configuration file loading, parsing, CLI interface setup,
and argument parsing for the RBAC Manager application.
Consolidates configuration and CLI concerns in one cohesive module.
"""

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

import yaml

# Set up logger
logger = logging.getLogger(__name__)


# ============================================================================
# LOGGING UTILITIES (Moved from core_utils.py)
# ============================================================================

def setup_logging(verbose: bool = False) -> None:
    """
    Configure logging for the application.
    
    Args:
        verbose: Enable debug-level logging if True
    """
    level = logging.DEBUG if verbose else logging.INFO
    
    # Configure root logger
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Configure urllib3 logging based on verbose mode
    urllib3_logger = logging.getLogger('urllib3')
    urllib3_connectionpool_logger = logging.getLogger('urllib3.connectionpool')
    
    if verbose:
        # In verbose mode, show urllib3 warnings (like SSL certificate issues)
        urllib3_logger.setLevel(logging.WARNING)
        urllib3_connectionpool_logger.setLevel(logging.WARNING)
    else:
        # In normal mode, suppress urllib3 warnings to reduce noise
        urllib3_logger.setLevel(logging.ERROR)
        urllib3_connectionpool_logger.setLevel(logging.ERROR)


class ConfigManager:
    """Manages configuration file loading and merging with CLI arguments."""
    
    # Default configuration file locations (in order of precedence)
    DEFAULT_CONFIG_LOCATIONS = [
        "rbac-manager.yaml",  # Current directory
        "~/.rbac-manager.yaml",  # Home directory  
        "~/.config/rbac-manager.yaml",  # XDG config directory
    ]
    
    def __init__(self, custom_config_path: Optional[str] = None):
        """
        Initialize configuration manager.
        
        Args:
            custom_config_path: Optional custom path to configuration file
        """
        self.custom_config_path = custom_config_path
        self.config_data: Dict[str, Any] = {}
        self.config_file_used: Optional[str] = None
    
    def load_config(self) -> Dict[str, Any]:
        """
        Load configuration from file.
        
        Returns:
            Configuration dictionary
        """
        config_path = self._find_config_file()
        
        if not config_path:
            logger.debug("No configuration file found")
            return {}
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config_content = f.read()
            
            # Expand environment variables in config content
            config_content = os.path.expandvars(config_content)
            
            # Parse YAML
            self.config_data = yaml.safe_load(config_content) or {}
            self.config_file_used = config_path
            
            logger.info(f"Loaded configuration from: {config_path}")
            return self.config_data
            
        except yaml.YAMLError as e:
            logger.warning(f"Invalid YAML in config file {config_path}: {e}")
            return {}
        except Exception as e:
            logger.warning(f"Could not load config file {config_path}: {e}")
            return {}
    
    def _find_config_file(self) -> Optional[str]:
        """
        Find the configuration file to use.
        
        Returns:
            Path to config file or None if not found
        """
        # If custom path provided, use it exclusively
        if self.custom_config_path:
            custom_path = os.path.expanduser(self.custom_config_path)
            if os.path.exists(custom_path):
                return custom_path
            else:
                logger.warning(f"Custom config file not found: {custom_path}")
                return None
        
        # Check default locations
        for location in self.DEFAULT_CONFIG_LOCATIONS:
            expanded_path = os.path.expanduser(location)
            if os.path.exists(expanded_path):
                return expanded_path
        
        return None
    
    def get_defaults_for_argparse(self) -> Dict[str, Any]:
        """
        Get configuration values formatted for argparse defaults.
        
        Returns:
            Dictionary suitable for argparse.set_defaults()
        """
        if not self.config_data:
            return {}
        
        defaults = {}
        
        # Catalog settings
        catalog = self.config_data.get('catalog', {})
        if catalog.get('name'):
            defaults['catalog_name'] = catalog['name']
        if catalog.get('image'):
            defaults['image'] = catalog['image']
        
        # OpenShift settings  
        openshift = self.config_data.get('openshift', {})
        if openshift.get('url'):
            defaults['openshift_url'] = openshift['url']
        if openshift.get('token'):
            defaults['openshift_token'] = openshift['token']
        if 'insecure' in openshift:
            defaults['insecure'] = openshift['insecure']
        
        # Catalogd settings
        catalogd = self.config_data.get('catalogd', {})
        if catalogd.get('namespace'):
            defaults['catalogd_namespace'] = catalogd['namespace']
        if catalogd.get('service'):
            defaults['catalogd_service'] = catalogd['service']
        if catalogd.get('local_port'):
            defaults['local_port'] = catalogd['local_port']
        
        # Output settings
        output = self.config_data.get('output', {})
        if output.get('directory'):
            defaults['output'] = output['directory']
        if 'deploy' in output:
            defaults['deploy'] = output['deploy']
        
        # Logging settings
        logging_config = self.config_data.get('logging', {})
        if 'verbose' in logging_config:
            defaults['verbose'] = logging_config['verbose']
        
        # Common package (if specified)
        if self.config_data.get('package'):
            defaults['package'] = self.config_data['package']
        
        return defaults
    
    def get_config_info(self) -> Dict[str, Any]:
        """
        Get information about the loaded configuration.
        
        Returns:
            Dictionary with config file path and loaded settings
        """
        return {
            'config_file': self.config_file_used,
            'config_data': self.config_data,
            'has_config': bool(self.config_file_used)
        }


def create_sample_config(mode: str = "global") -> str:
    """
    Create a sample configuration file content based on the specified mode.
    
    Args:
        mode: Configuration mode ("global", "opm", "catalogd")
    
    Returns:
        Sample YAML configuration as string
    """
    if mode == "opm":
        return create_opm_config()
    elif mode == "catalogd":
        return create_catalogd_config()
    else:
        return create_global_config()

def create_global_config() -> str:
    """Create a global configuration template."""
    return """# RBAC Manager Global Configuration File
# Place this file at ~/.rbac-manager.yaml or ~/.config/rbac-manager.yaml
# This config provides defaults for both OPM and Catalogd operations

# OpenShift cluster settings (applies to both modes)
openshift:
  # url: https://api.my-cluster.com:6443  # Uncomment to set default cluster URL
  # token: ${OPENSHIFT_TOKEN}              # Environment variable expansion supported
  insecure: false                          # Set to true to skip TLS verification

# Catalogd-specific settings
catalogd:
  namespace: openshift-catalogd            # Catalogd service namespace
  service: catalogd-service                # Catalogd service name
  local_port: 8080                         # Local port for port-forwarding
  
# Default catalog for Catalogd operations
catalog:
  name: operatorhubio                      # Default catalog name
  # image: quay.io/operatorhubio/catalog:latest  # Uncomment for OPM catalog operations

# OPM-specific settings  
opm:
  # registry_token: ${REGISTRY_TOKEN}      # Registry auth token for private images
  insecure: false                          # Skip TLS for image pulls
  
# Common package settings
# package: prometheus-operator             # Uncomment to set default package
# channel: stable                          # Uncomment to set default channel
# version: latest                          # Uncomment to set default version
"""

def create_opm_config() -> str:
    """Create an OPM-specific configuration template."""
    return """# RBAC Manager OPM Configuration File
# This configuration is optimized for OPM bundle image operations
# Usage: python3 rbac_manager.py --config ~/.rbac-manager-opm.yaml --opm --image bundle:latest

# OPM-specific settings
opm:
  insecure: false                          # Skip TLS verification for image pulls
  # registry_token: ${REGISTRY_TOKEN}      # Registry authentication token (env var)

# OpenShift cluster settings (optional for deployment)
openshift:
  # url: https://api.my-cluster.com:6443   # OpenShift cluster URL
  # token: ${OPENSHIFT_TOKEN}              # Service account token (env var)
  insecure: false                          # Skip TLS verification for cluster API

# Common bundle processing settings
bundle:
  # Default output options
  output:
    # format: helm                         # Default to Helm values.yaml output
    # directory: ./rbac-output             # Default output directory
    
# Registry authentication examples:
# Option 1: Use discovered credentials (automatic)
#   - Checks ~/.docker/config.json (Docker)
#   - Checks ~/.config/containers/auth.json (Podman)
#   - Checks $XDG_RUNTIME_DIR/containers/auth.json (Runtime)
#
# Option 2: Environment variables
#   export REGISTRY_TOKEN="your-registry-token"
#   export OPENSHIFT_TOKEN="your-cluster-token"

# Example bundle images for testing:
# examples:
#   - quay.io/operatorhubio/argocd-operator:v0.7.0
#   - quay.io/jaegertracing/jaeger-operator-bundle:1.29.0
#   - registry.redhat.io/ubi8/cert-manager-bundle@sha256:abc123
"""

def create_catalogd_config() -> str:
    """Create a Catalogd-specific configuration template.""" 
    return """# RBAC Manager Catalogd Configuration File  
# This configuration is optimized for Catalogd operations via OpenShift API
# Usage: python3 rbac_manager.py --config ~/.rbac-manager-catalogd.yaml --catalogd --package prometheus

# OpenShift cluster connection (REQUIRED)
openshift:
  url: https://api.my-cluster.com:6443     # Replace with your cluster URL
  # token: ${OPENSHIFT_TOKEN}              # Service account token (env var recommended)
  insecure: false                          # Set to true for self-signed certificates

# Catalogd service connection settings
catalogd:
  namespace: openshift-catalogd            # Namespace where catalogd runs
  service: catalogd-service                # Catalogd service name
  local_port: 8080                         # Local port for port-forwarding

# Default catalog settings
catalog:
  name: operatorhubio                      # Default catalog name
  # Alternative catalog options:
  # name: openshift-certified-operators
  # name: openshift-community-operators  
  # name: redhat-operators

# Common query settings  
query:
  # package: prometheus                    # Default package name
  # channel: stable                        # Default channel
  # version: latest                        # Default version
  
# Authentication setup:
# 1. Get cluster token: oc whoami -t
# 2. Set environment variable: export OPENSHIFT_TOKEN="your-token"
# 3. Or uncomment and set the token directly above (less secure)

# Common packages for testing:
# examples:
#   packages: [prometheus, grafana, jaeger, cert-manager]
#   catalogs: [operatorhubio, openshift-certified-operators]
"""


def generate_sample_config_file(output_path: Optional[str] = None, mode: str = "global") -> str:
    """
    Generate a sample configuration file for the specified mode.
    
    Args:
        output_path: Path where to write the config file. If None, uses default location.
        mode: Configuration mode ("global", "opm", "catalogd")
        
    Returns:
        Path to the created configuration file
        
    Raises:
        PermissionError: If unable to write to the specified path
        OSError: If unable to create directory or write file
    """
    if not output_path:
        # Use default location with mode suffix
        config_dir = os.path.expanduser("~/.config")
        try:
            os.makedirs(config_dir, exist_ok=True)
        except OSError as e:
            logger.error(f"Failed to create config directory {config_dir}: {e}")
            raise OSError(f"Unable to create config directory {config_dir}: {e}") from e
            
        if mode == "global":
            filename = "rbac-manager.yaml"
        else:
            filename = f"rbac-manager-{mode}.yaml"
        output_path = os.path.join(config_dir, filename)
    
    sample_content = create_sample_config(mode)
    
    try:
        # Ensure the directory exists
        output_dir = os.path.dirname(os.path.abspath(output_path))
        os.makedirs(output_dir, exist_ok=True)
        
        # Write the configuration file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(sample_content)
            
    except PermissionError as e:
        logger.error(f"Permission denied writing config file to {output_path}: {e}")
        raise PermissionError(f"Permission denied: Unable to write config file to {output_path}. "
                            f"Check directory permissions and try a different path.") from e
    except OSError as e:
        logger.error(f"Failed to write config file to {output_path}: {e}")
        raise OSError(f"Failed to write config file to {output_path}: {e}") from e
    
    logger.info(f"Sample {mode} configuration file created: {output_path}")
    return output_path


# ============================================================================
# CLI INTERFACE AND ARGUMENT PARSING
# ============================================================================