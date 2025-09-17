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
        
        # Validate new config structure
        if 'operator' in self.config_data:
            self._validate_operator_config(self.config_data['operator'])
        
        if 'output' in self.config_data:
            self._validate_output_config(self.config_data['output'])
            
        if 'global' in self.config_data:
            self._validate_global_config(self.config_data['global'])
        
        # Validate legacy catalogd section (for backward compatibility)
        if 'catalogd' in self.config_data:
            self._validate_catalogd_config(self.config_data['catalogd'])
        
        # Validate legacy opm section (for backward compatibility)
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
    
    def _validate_operator_config(self, operator_config: Dict[str, Any]) -> None:
        """
        Validate operator configuration section
        
        Args:
            operator_config: Operator configuration dictionary
            
        Raises:
            ConfigurationError: If operator configuration is invalid
        """
        if not isinstance(operator_config, dict):
            raise ConfigurationError("operator configuration must be a dictionary")
        
        # Optional string fields
        string_fields = ['image', 'namespace', 'channel', 'packageName', 'version']
        for field in string_fields:
            if field in operator_config and operator_config[field] is not None:
                if not isinstance(operator_config[field], str):
                    raise ConfigurationError(f"operator.{field} must be a string")
    
    def _validate_output_config(self, output_config: Dict[str, Any]) -> None:
        """
        Validate output configuration section
        
        Args:
            output_config: Output configuration dictionary
            
        Raises:
            ConfigurationError: If output configuration is invalid
        """
        if not isinstance(output_config, dict):
            raise ConfigurationError("output configuration must be a dictionary")
        
        # Validate mode
        if 'mode' in output_config:
            if output_config['mode'] not in ['stdout', 'file']:
                raise ConfigurationError("output.mode must be 'stdout' or 'file'")
        
        # Validate type
        if 'type' in output_config:
            if output_config['type'] not in ['yaml', 'helm']:
                raise ConfigurationError("output.type must be 'yaml' or 'helm'")
        
        # Validate path (string)
        if 'path' in output_config and output_config['path'] is not None:
            if not isinstance(output_config['path'], str):
                raise ConfigurationError("output.path must be a string")
    
    def _validate_global_config(self, global_config: Dict[str, Any]) -> None:
        """
        Validate global configuration section
        
        Args:
            global_config: Global configuration dictionary
            
        Raises:
            ConfigurationError: If global configuration is invalid
        """
        if not isinstance(global_config, dict):
            raise ConfigurationError("global configuration must be a dictionary")
        
        # Boolean fields
        boolean_fields = ['skip_tls', 'debug']
        for field in boolean_fields:
            if field in global_config and global_config[field] is not None:
                if not isinstance(global_config[field], bool):
                    raise ConfigurationError(f"global.{field} must be a boolean")
        
        # String fields
        if 'registry_token' in global_config and global_config['registry_token'] is not None:
            if not isinstance(global_config['registry_token'], str):
                raise ConfigurationError("global.registry_token must be a string")
    
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
                "# RBAC Manager Configuration File": None,
                "# Generated from template": None,
                "": None,
                "operator": {
                    "image": "image-url",
                    "namespace": KubernetesConstants.DEFAULT_NAMESPACE,
                    "channel": "channel-name",
                    "packageName": "package-name",
                    "version": "version"
                },
                "": None,
                "output": {
                    "mode": "stdout",
                    "type": "yaml",
                    "path": "./output"
                },
                "": None,
                "global": {
                    "skip_tls": False,
                    "debug": False,
                    "registry_token": ""
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
    
    def generate_config_with_values(self, extracted_data: Dict[str, Any], output_dir: str = None, 
                                  output_mode: str = "stdout", output_type: str = "yaml", 
                                  namespace: str = None) -> str:
        """
        Generate configuration file with extracted values
        
        Args:
            extracted_data: Dictionary with extracted values (bundle_image, channel, package, version)
            output_dir: Directory to save config (optional)
            output_mode: Output mode (stdout or file)
            output_type: Output type (yaml or helm)
            namespace: Target namespace
            
        Returns:
            str: Path to generated config file
            
        Raises:
            ConfigurationError: If config generation fails
        """
        try:
            template = {
                "# RBAC Manager Configuration File": None,
                "# Generated from extracted values": None,
                "": None,
                "operator": {
                    "image": extracted_data.get('bundle_image', 'image-url'),
                    "namespace": namespace or KubernetesConstants.DEFAULT_NAMESPACE,
                    "channel": extracted_data.get('channel', 'channel-name'),
                    "packageName": extracted_data.get('package', 'package-name'),
                    "version": extracted_data.get('version', 'version')
                },
                "": None,
                "output": {
                    "mode": output_mode,
                    "type": output_type,
                    "path": output_dir or "./output"
                },
                "": None,
                "global": {
                    "skip_tls": False,
                    "debug": False,
                    "registry_token": ""
                }
            }
            
            # Determine output path
            if output_dir:
                output_path = Path(output_dir)
                output_path.mkdir(parents=True, exist_ok=True)
                config_file = output_path / FileConstants.DEFAULT_CONFIG_FILE
            else:
                config_file = Path('./config') / FileConstants.DEFAULT_CONFIG_FILE
                config_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Generate YAML content manually to preserve comments
            yaml_content = self._dict_to_yaml_with_comments(template)
            
            with open(config_file, 'w') as f:
                f.write(yaml_content)
            
            logger.info(f"Configuration file generated: {config_file}")
            return str(config_file)
            
        except Exception as e:
            raise ConfigurationError(f"Failed to generate configuration file: {e}")
