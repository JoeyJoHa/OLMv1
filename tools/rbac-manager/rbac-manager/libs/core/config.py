"""
Configuration Management

Handles loading and managing configuration files for the RBAC Manager tool.
"""

import logging
import yaml
from pathlib import Path
from typing import Dict, Any

from .exceptions import ConfigurationError
from .constants import KubernetesConstants, FileConstants

logger = logging.getLogger(__name__)


class ConfigManager:
    """Manages configuration loading and validation"""
    
    # Configuration schema - defines expected structure and types
    CONFIG_SCHEMA = {
        'operator': {
            'type': dict,
            'required': False,
            'fields': {
                'image': {'type': str, 'required': False},
                'namespace': {'type': str, 'required': False},
                'channel': {'type': str, 'required': False},
                'packageName': {'type': str, 'required': False},
                'version': {'type': str, 'required': False}
            }
        },
        'output': {
            'type': dict,
            'required': False,
            'fields': {
                'mode': {'type': str, 'required': False, 'choices': ['stdout', 'file']},
                'type': {'type': str, 'required': False, 'choices': ['yaml', 'helm']},
                'path': {'type': str, 'required': False}
            }
        },
        'global': {
            'type': dict,
            'required': False,
            'fields': {
                'skip_tls': {'type': bool, 'required': False},
                'debug': {'type': bool, 'required': False},
                'registry_token': {'type': str, 'required': False}
            }
        },
    }
    
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
        
        
        # Validate using schema-based approach
        self._validate_against_schema(self.config_data, self.CONFIG_SCHEMA, "config")
    
    def _validate_against_schema(self, data: Dict[str, Any], schema: Dict[str, Any], path: str = "") -> None:
        """
        Validate data against schema definition
        
        Args:
            data: Data to validate
            schema: Schema definition
            path: Current path for error reporting
            
        Raises:
            ConfigurationError: If data doesn't match schema
        """
        for key, field_schema in schema.items():
            current_path = f"{path}.{key}" if path else key
            
            # Check if field exists in data
            if key in data:
                value = data[key]
                
                # Skip None values for optional fields
                if value is None and not field_schema.get('required', False):
                    continue
                
                # Validate type
                expected_type = field_schema['type']
                if not isinstance(value, expected_type):
                    type_name = expected_type.__name__
                    raise ConfigurationError(f"{current_path} must be a {type_name}")
                
                # Validate choices if specified
                if 'choices' in field_schema:
                    if value not in field_schema['choices']:
                        choices_str = ', '.join(f"'{c}'" for c in field_schema['choices'])
                        raise ConfigurationError(f"{current_path} must be one of: {choices_str}")
                
                # Recursively validate nested dictionaries
                if expected_type == dict and 'fields' in field_schema:
                    self._validate_against_schema(value, field_schema['fields'], current_path)
            
            # Check required fields
            elif field_schema.get('required', False):
                raise ConfigurationError(f"Required field {current_path} is missing")
    
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
            # Use the existing method to generate content (DRY principle)
            yaml_content = self.get_config_template_content()
            
            # Determine output path
            if output_dir:
                output_path = Path(output_dir)
                output_path.mkdir(parents=True, exist_ok=True)
                config_file = output_path / FileConstants.DEFAULT_CONFIG_FILE
            else:
                config_file = Path(FileConstants.DEFAULT_CONFIG_FILE)
            
            # Write content to file
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
    
    def get_config_template_content(self) -> str:
        """
        Generate configuration template content as string without file I/O
        
        Returns:
            str: YAML configuration template content
        """
        template = {
            "# RBAC Manager Configuration File": None,
            "# Template for configuring RBAC extraction from operator bundles": None,
            "": None,
            "operator": {
                "image": "quay.io/example/operator-bundle:latest",
                "namespace": KubernetesConstants.DEFAULT_NAMESPACE,
                "channel": "#<VERIFY_WITH_CATALOGD_AND_SET_CHANNEL>",
                "packageName": "example-operator",
                "version": "1.0.0"
            },
            "": None,
            "output": {
                "mode": "yaml",
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
        
        return self._dict_to_yaml_with_comments(template)
    
    def get_config_with_values_content(self, extracted_data: Dict[str, Any], 
                                     output_mode: str = "stdout", output_type: str = "yaml", 
                                     namespace: str = None) -> str:
        """
        Generate configuration content with extracted values as string without file I/O
        
        Args:
            extracted_data: Dictionary with extracted values (bundle_image, channel, package, version)
            output_mode: Output mode (stdout or file)
            output_type: Output type (yaml or helm)
            namespace: Target namespace
            
        Returns:
            str: YAML configuration content with extracted values
        """
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
                "path": "./output"
            },
            "": None,
            "global": {
                "skip_tls": False,
                "debug": False,
                "registry_token": ""
            }
        }
        
        return self._dict_to_yaml_with_comments(template)
    
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
            # Use the existing method to generate content (DRY principle)
            yaml_content = self.get_config_with_values_content(
                extracted_data=extracted_data,
                output_mode=output_mode,
                output_type=output_type,
                namespace=namespace
            )
            
            # Determine output path
            if output_dir:
                output_path = Path(output_dir)
                output_path.mkdir(parents=True, exist_ok=True)
                config_file = output_path / FileConstants.DEFAULT_CONFIG_FILE
            else:
                config_file = Path('./config') / FileConstants.DEFAULT_CONFIG_FILE
                config_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Write content to file
            with open(config_file, 'w') as f:
                f.write(yaml_content)
            
            logger.info(f"Configuration file generated: {config_file}")
            return str(config_file)
            
        except Exception as e:
            raise ConfigurationError(f"Failed to generate configuration file: {e}")
