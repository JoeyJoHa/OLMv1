"""
Configuration Management

Handles loading and managing configuration files for the RBAC Manager tool.
"""

import logging
import yaml
from pathlib import Path
from typing import Dict, Any, Optional

from .exceptions import ConfigurationError
from .constants import KubernetesConstants, FileConstants

logger = logging.getLogger(__name__)


class ConfigManager:
    """Manages configuration loading and validation"""
    
    def __init__(self):
        """Initialize configuration manager"""
        self.config_data = {}
        self.config_file_path = None
    
    def load_config(self, config_path: str) -> Dict[str, Any]:
        """
        Load configuration from YAML file
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            Dict containing configuration data
            
        Raises:
            ConfigurationError: If configuration file cannot be loaded or is invalid
        """
        try:
            config_file = Path(config_path)
            
            if not config_file.exists():
                raise ConfigurationError(f"Configuration file not found: {config_path}")
            
            if not config_file.is_file():
                raise ConfigurationError(f"Configuration path is not a file: {config_path}")
            
            with open(config_file, 'r') as f:
                self.config_data = yaml.safe_load(f) or {}
            
            self.config_file_path = config_path
            logger.info(f"Successfully loaded configuration from {config_path}")
            
            # Validate configuration structure
            self._validate_config()
            
            return self.config_data
            
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML in configuration file {config_path}: {e}")
        except Exception as e:
            raise ConfigurationError(f"Failed to load configuration from {config_path}: {e}")
    
    def _validate_config(self) -> None:
        """
        Validate configuration structure and values
        
        Raises:
            ConfigurationError: If configuration is invalid
        """
        if not isinstance(self.config_data, dict):
            raise ConfigurationError("Configuration must be a dictionary")
        
        # Validate global settings
        if 'skip_tls' in self.config_data and not isinstance(self.config_data['skip_tls'], bool):
            raise ConfigurationError("skip_tls must be a boolean value")
        
        if 'debug' in self.config_data and not isinstance(self.config_data['debug'], bool):
            raise ConfigurationError("debug must be a boolean value")
        
        # Validate catalogd section
        if 'catalogd' in self.config_data:
            self._validate_catalogd_config(self.config_data['catalogd'])
        
        # Validate opm section
        if 'opm' in self.config_data:
            self._validate_opm_config(self.config_data['opm'])
    
    def _validate_catalogd_config(self, catalogd_config: Dict[str, Any]) -> None:
        """
        Validate catalogd configuration section
        
        Args:
            catalogd_config: Catalogd configuration dictionary
            
        Raises:
            ConfigurationError: If catalogd configuration is invalid
        """
        if not isinstance(catalogd_config, dict):
            raise ConfigurationError("catalogd configuration must be a dictionary")
        
        # Optional string fields
        string_fields = ['catalog_name', 'openshift_url', 'openshift_token', 'package', 'channel', 'version']
        for field in string_fields:
            if field in catalogd_config and catalogd_config[field] is not None:
                if not isinstance(catalogd_config[field], str):
                    raise ConfigurationError(f"catalogd.{field} must be a string")
    
    def _validate_opm_config(self, opm_config: Dict[str, Any]) -> None:
        """
        Validate opm configuration section
        
        Args:
            opm_config: OPM configuration dictionary
            
        Raises:
            ConfigurationError: If opm configuration is invalid
        """
        if not isinstance(opm_config, dict):
            raise ConfigurationError("opm configuration must be a dictionary")
        
        # Optional string fields
        string_fields = ['image', 'namespace', 'registry_token', 'output']
        for field in string_fields:
            if field in opm_config and opm_config[field] is not None:
                if not isinstance(opm_config[field], str):
                    raise ConfigurationError(f"opm.{field} must be a string")
        
        # Optional boolean fields
        boolean_fields = ['helm']
        for field in boolean_fields:
            if field in opm_config and opm_config[field] is not None:
                if not isinstance(opm_config[field], bool):
                    raise ConfigurationError(f"opm.{field} must be a boolean")
    
    def get_config(self) -> Dict[str, Any]:
        """
        Get current configuration data
        
        Returns:
            Dict containing configuration data
        """
        return self.config_data.copy()
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """
        Get specific configuration section
        
        Args:
            section: Section name (e.g., 'catalogd', 'opm')
            
        Returns:
            Dict containing section data, empty dict if section doesn't exist
        """
        return self.config_data.get(section, {})
    
    def get_value(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value by key
        
        Args:
            key: Configuration key (supports dot notation like 'catalogd.catalog_name')
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        keys = key.split('.')
        value = self.config_data
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def generate_config_template(self, output_dir: str = None) -> str:
        """
        Generate configuration template file
        
        Args:
            output_dir: Directory to save template (optional)
            
        Returns:
            str: Path to generated template file
            
        Raises:
            ConfigurationError: If template generation fails
        """
        try:
            template = {
                "# RBAC Manager Configuration": None,
                "# This file contains default values for RBAC Manager commands": None,
                "": None,
                "# Global settings": None,
                "skip_tls": False,
                "debug": False,
                "": None,
                "# Catalogd settings": None,
                "catalogd": {
                    "catalog_name": "",
                    "openshift_url": "",
                    "openshift_token": "",
                    "package": "",
                    "channel": "",
                    "version": ""
                },
                "": None,
                "# OPM settings": None,
                "opm": {
                    "image": "",
                    "namespace": KubernetesConstants.DEFAULT_NAMESPACE,
                    "registry_token": "",
                    "helm": False,
                    "output": "./output",
                }
            }
            
            # Determine output path
            if output_dir:
                output_path = Path(output_dir)
                output_path.mkdir(parents=True, exist_ok=True)
                config_file = output_path / FileConstants.DEFAULT_CONFIG_FILE
            else:
                config_file = Path(FileConstants.DEFAULT_CONFIG_FILE)
            
            # Generate YAML content manually to preserve comments
            yaml_content = self._dict_to_yaml_with_comments(template)
            
            with open(config_file, 'w') as f:
                f.write(yaml_content)
            
            logger.info(f"Configuration template generated: {config_file}")
            return str(config_file)
            
        except Exception as e:
            raise ConfigurationError(f"Failed to generate configuration template: {e}")
    
    def _dict_to_yaml_with_comments(self, data: Dict[str, Any], indent: int = 0) -> str:
        """
        Convert dictionary to YAML string preserving comments
        
        Args:
            data: Dictionary to convert
            indent: Current indentation level
            
        Returns:
            str: YAML string with comments
        """
        yaml_lines = []
        indent_str = "  " * indent
        
        for key, value in data.items():
            if key.startswith("#") or key == "":
                # Handle comments and empty lines
                if key.startswith("#"):
                    yaml_lines.append(f"{indent_str}{key}")
                else:
                    yaml_lines.append("")
            elif isinstance(value, dict):
                yaml_lines.append(f"{indent_str}{key}:")
                yaml_lines.append(self._dict_to_yaml_with_comments(value, indent + 1))
            elif isinstance(value, str):
                if value:
                    yaml_lines.append(f'{indent_str}{key}: "{value}"')
                else:
                    yaml_lines.append(f'{indent_str}{key}: ""')
            else:
                yaml_lines.append(f"{indent_str}{key}: {value}")
        
        return "\n".join(yaml_lines)
