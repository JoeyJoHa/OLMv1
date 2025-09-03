"""
Configuration File Utilities.

This module provides configuration file support for the RBAC Manager,
allowing users to set default values for frequently used arguments.
"""

import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

import yaml

# Set up logger
logger = logging.getLogger(__name__)


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
            
            logger.info(f"📁 Loaded configuration from: {config_path}")
            return self.config_data
            
        except yaml.YAMLError as e:
            logger.warning(f"⚠️  Invalid YAML in config file {config_path}: {e}")
            return {}
        except Exception as e:
            logger.warning(f"⚠️  Could not load config file {config_path}: {e}")
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
                logger.warning(f"⚠️  Custom config file not found: {custom_path}")
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


def create_sample_config() -> str:
    """
    Create a sample configuration file content.
    
    Returns:
        Sample YAML configuration as string
    """
    sample_config = """# RBAC Manager Configuration File
# Place this file at ~/.rbac-manager.yaml or ~/.config/rbac-manager.yaml

# Default catalog settings
catalog:
  name: operatorhubio
  image: quay.io/operatorhubio/catalog:latest

# Default OpenShift settings
openshift:
  # url: https://api.my-cluster.com:6443  # Uncomment to set default cluster
  # token: ${OPENSHIFT_TOKEN}              # Environment variable expansion supported
  insecure: false

# Default catalogd settings  
catalogd:
  namespace: openshift-catalogd
  service: catalogd-service
  local_port: 8080

# Default output settings
output:
  # directory: ./rbac-output  # Uncomment to set default output directory
  deploy: false

# Default logging settings
logging:
  verbose: false

# Default package (uncomment if you frequently work with specific operator)
# package: prometheus-operator
"""
    return sample_config


def generate_sample_config_file(output_path: Optional[str] = None) -> str:
    """
    Generate a sample configuration file.
    
    Args:
        output_path: Path where to write the config file. If None, uses default location.
        
    Returns:
        Path to the created configuration file
    """
    if not output_path:
        # Use default location
        config_dir = os.path.expanduser("~/.config")
        os.makedirs(config_dir, exist_ok=True)
        output_path = os.path.join(config_dir, "rbac-manager.yaml")
    
    sample_content = create_sample_config()
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(sample_content)
    
    logger.info(f"📄 Sample configuration file created: {output_path}")
    return output_path
