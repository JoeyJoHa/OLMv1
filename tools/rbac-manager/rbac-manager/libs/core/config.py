"""
Configuration Management

Handles loading and managing configuration files for the RBAC Manager tool.
"""

import logging
from pathlib import Path
from typing import Dict, Any

try:
    import yaml
except ImportError:
    raise ImportError("PyYAML is required. Install with: pip install PyYAML")

try:
    from ruamel.yaml import YAML
    from ruamel.yaml.comments import CommentedMap
    HAS_RUAMEL_YAML = True
except ImportError:
    HAS_RUAMEL_YAML = False

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
                'debug': {'type': bool, 'required': False}
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
    
    def _write_config_file(self, content: str, output_dir: str = None, default_path: str = None) -> str:
        """
        Helper method to write configuration content to file
        
        Args:
            content: YAML content to write
            output_dir: Directory to save file (optional)
            default_path: Default path when output_dir is not provided
            
        Returns:
            str: Path to written file
            
        Raises:
            ConfigurationError: If file writing fails
        """
        try:
            # Determine output path
            if output_dir:
                output_path = Path(output_dir)
                output_path.mkdir(parents=True, exist_ok=True)
                # Extract filename from default_path or use fallback
                if default_path:
                    filename = Path(default_path).name
                else:
                    filename = FileConstants.DEFAULT_CONFIG_FILE
                config_file = output_path / filename
            else:
                config_file = Path(default_path or FileConstants.DEFAULT_CONFIG_FILE)
                config_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Write content to file
            with open(config_file, 'w') as f:
                f.write(content)
            
            logger.info(f"Configuration file written: {config_file}")
            return str(config_file)
            
        except Exception as e:
            raise ConfigurationError(f"Failed to write configuration file: {e}")
    
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
        # Generate content and delegate file writing to helper method
        yaml_content = self.get_config_template_content()
        return self._write_config_file(yaml_content, output_dir)
    
    def _dict_to_yaml_with_comments(self, data: Dict[str, Any], indent: int = 0) -> str:
        """
        Convert dictionary to YAML string preserving comments using ruamel.yaml
        
        Args:
            data: Dictionary to convert
            indent: Current indentation level (unused with ruamel.yaml)
            
        Returns:
            str: YAML string with comments preserved
        """
        if HAS_RUAMEL_YAML:
            return self._ruamel_yaml_with_comments(data)
        else:
            # Simple fallback using standard yaml library if ruamel.yaml is not available
            # Filter out comment keys for basic YAML generation
            clean_data = {k: v for k, v in data.items() if not k.startswith("#") and k != ""}
            return yaml.dump(clean_data, default_flow_style=False, sort_keys=False)
    
    def _ruamel_yaml_with_comments(self, data: Dict[str, Any]) -> str:
        """
        Use ruamel.yaml to generate YAML with comments preserved
        
        Args:
            data: Dictionary to convert
            
        Returns:
            str: YAML string with comments
        """
        yaml_processor = YAML()
        yaml_processor.preserve_quotes = True
        yaml_processor.width = 4096  # Prevent line wrapping
        yaml_processor.indent(mapping=2, sequence=4, offset=2)
        
        # Convert the data to CommentedMap for comment support
        commented_data = CommentedMap()
        
        for key, value in data.items():
            if key.startswith("#"):
                # Handle comment keys by adding them as comments to the previous item
                continue
            elif key == "":
                # Handle empty lines - skip for now as ruamel.yaml handles spacing
                continue
            elif isinstance(value, dict):
                commented_data[key] = CommentedMap(value)
            else:
                commented_data[key] = value
        
        # Add comments for special keys
        self._add_yaml_comments(commented_data, data)
        
        # Generate YAML string
        from io import StringIO
        stream = StringIO()
        yaml_processor.dump(commented_data, stream)
        return stream.getvalue()
    
    def _add_yaml_comments(self, commented_data: CommentedMap, original_data: Dict[str, Any]) -> None:
        """
        Add comments to CommentedMap based on comment keys in original data
        
        Args:
            commented_data: CommentedMap to add comments to
            original_data: Original data with comment keys
        """
        comment_keys = [k for k in original_data.keys() if k.startswith("#")]
        
        # Add header comments
        if comment_keys:
            # Combine all comment lines into a single start comment
            comment_lines = []
            for comment_key in comment_keys[:2]:  # First two comments as header
                comment_text = comment_key[1:].strip()  # Remove # and whitespace
                comment_lines.append(comment_text)
            
            if comment_lines:
                # Set the combined comment as start comment
                combined_comment = '\n'.join(comment_lines)
                commented_data.yaml_set_start_comment(combined_comment)
    
    
    def _create_config_template_structure(self, header_comment: str = None, 
                                        operator_image: str = None, operator_namespace: str = None,
                                        operator_channel: str = None, operator_package: str = None, 
                                        operator_version: str = None, output_mode: str = None, 
                                        output_type: str = None) -> Dict[str, Any]:
        """
        Create the standard configuration template structure
        
        Args:
            header_comment: Second header comment line
            operator_image: Operator image URL
            operator_namespace: Target namespace
            operator_channel: Operator channel
            operator_package: Package name
            operator_version: Operator version
            output_mode: Output mode (stdout/file)
            output_type: Output type (yaml/helm)
            
        Returns:
            Dict: Configuration template structure
        """
        return {
            "# RBAC Manager Configuration File": None,
            f"# {header_comment or 'Configuration template'}": None,
            "": None,
            "operator": {
                "image": operator_image or "quay.io/example/operator-bundle:latest",
                "namespace": operator_namespace or KubernetesConstants.DEFAULT_NAMESPACE,
                "channel": operator_channel or "#<VERIFY_WITH_CATALOGD_AND_SET_CHANNEL>",
                "packageName": operator_package or "example-operator",
                "version": operator_version or "1.0.0"
            },
            "": None,
            "output": {
                "mode": output_mode or "yaml",
                "type": output_type or "yaml",
                "path": "./output"
            },
            "": None,
            "global": {
                "skip_tls": False,
                "debug": False
            }
        }
    
    def get_config_template_content(self) -> str:
        """
        Generate configuration template content as string without file I/O
        
        Returns:
            str: YAML configuration template content
        """
        template = self._create_config_template_structure(
            header_comment="Template for configuring RBAC extraction from operator bundles"
        )
        
        return self._dict_to_yaml_with_comments(template)
    
    def get_config_with_values_content(
        self,
        extracted_data: Dict[str, Any],
        output_mode: str = "stdout",
        output_type: str = "yaml",
        namespace: str = None
    ) -> str:
        """
        Generate configuration content with extracted values as string without file I/O.
        
        Args:
            extracted_data: Dictionary with extracted values (bundle_image, channel, package, version)
            output_mode: Output mode (stdout or file)
            output_type: Output type (yaml or helm)
            namespace: Target namespace
            
        Returns:
            str: YAML configuration content with extracted values
        """
        template = self._create_config_template_structure(
            header_comment="Generated from extracted values",
            operator_image=extracted_data.get('bundle_image', 'image-url'),
            operator_namespace=namespace,
            operator_channel=extracted_data.get('channel', 'channel-name'),
            operator_package=extracted_data.get('packageName') or extracted_data.get('package', 'package-name'),
            operator_version=extracted_data.get('version', 'version'),
            output_mode=output_mode,
            output_type=output_type
        )
        
        return self._dict_to_yaml_with_comments(template)
    
    def _generate_config_filename(self, package_name: str = None) -> str:
        """
        Generate configuration filename based on operator name.
        
        Args:
            package_name: Name of the operator package
            
        Returns:
            str: Generated configuration filename
        """
        if package_name:
            # Import locally to avoid circular imports (PEP 8 compliant)
            from .utils import sanitize_filename
            sanitized_name = sanitize_filename(package_name)
            return f"{sanitized_name}-rbac-config.yaml"
        return FileConstants.DEFAULT_CONFIG_FILE
    
    def generate_config_with_values(
        self,
        extracted_data: Dict[str, Any],
        output_dir: str = None,
        output_mode: str = "stdout",
        output_type: str = "yaml",
        namespace: str = None
    ) -> str:
        """
        Generate configuration file with extracted values.
        
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
        # Generate content and delegate file writing to helper method
        yaml_content = self.get_config_with_values_content(
            extracted_data=extracted_data,
            output_mode=output_mode,
            output_type=output_type,
            namespace=namespace
        )
        
        # Generate filename based on package name
        # Try both 'packageName' (from config file) and 'package' (from command args)
        package_name = extracted_data.get('packageName') or extracted_data.get('package')
        config_filename = self._generate_config_filename(package_name)
        default_path = f'./config/{config_filename}'
        
        # Use helper method with dynamically generated default path
        return self._write_config_file(yaml_content, output_dir, default_path)
