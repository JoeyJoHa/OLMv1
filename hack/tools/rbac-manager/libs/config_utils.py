"""
Configuration and CLI Management Module.

This module provides configuration file loading, parsing, CLI interface setup,
and argument parsing for the RBAC Manager application.
Consolidates configuration and CLI concerns in one cohesive module.
"""

import argparse
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
    
    logger.info(f"Sample configuration file created: {output_path}")
    return output_path


# ============================================================================
# CLI INTERFACE AND ARGUMENT PARSING
# ============================================================================

class CLIInterface:
    """Handles command-line interface setup and argument parsing."""
    
    def __init__(self):
        """Initialize CLI interface."""
        self.config_manager: Optional[ConfigManager] = None
        self.parser: Optional[argparse.ArgumentParser] = None
    
    def setup_config_manager(self, custom_config_path: Optional[str] = None) -> ConfigManager:
        """
        Setup and return configuration manager.
        
        Args:
            custom_config_path: Optional custom configuration file path
            
        Returns:
            Configured ConfigManager instance
        """
        self.config_manager = ConfigManager(custom_config_path=custom_config_path)
        return self.config_manager
    
    def create_argument_parser(self, config_defaults: Optional[Dict[str, Any]] = None) -> argparse.ArgumentParser:
        """
        Create and configure the main argument parser.
        
        Args:
            config_defaults: Default values from configuration file
            
        Returns:
            Configured ArgumentParser instance
        """
        parser = argparse.ArgumentParser(
            description='Unified RBAC Manager for OLM Operators (Port-Forward Version)',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=self._get_help_epilog()
        )
        
        self._add_query_method_arguments(parser)
        self._add_opm_arguments(parser)
        self._add_catalogd_arguments(parser)
        self._add_common_arguments(parser)
        self._add_output_arguments(parser)
        self._add_action_arguments(parser)
        self._add_configuration_arguments(parser)
        
        # Apply configuration defaults (CLI args will override these)
        if config_defaults:
            parser.set_defaults(**config_defaults)
        
        self.parser = parser
        return parser
    
    def _add_query_method_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add query method selection arguments."""
        query_group = parser.add_mutually_exclusive_group(required=True)
        query_group.add_argument('--opm', action='store_true',
                                help='Use OPM image queries')
        query_group.add_argument('--catalogd', action='store_true',
                                help='Use ClusterCatalog API queries via port-forward')
    
    def _add_opm_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add OPM-specific arguments."""
        parser.add_argument('--image', 
                           help='Catalog image reference (required for --opm)')
    
    def _add_catalogd_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add ClusterCatalog API arguments."""
        parser.add_argument('--openshift-url', 
                           help='OpenShift API URL (optional, will auto-discover from kubeconfig if not provided)')
        parser.add_argument('--openshift-token',
                           help='OpenShift authentication token (or set OPENSHIFT_TOKEN env var)')
        parser.add_argument('--catalog-name',
                           help='Name of catalog to query. If not specified, you will be prompted to choose from available catalogs. Use --list-catalogs to see available options.')
        
        # Port-forward configuration
        parser.add_argument('--local-port', type=int, default=8080,
                           help='Local port for port-forward (default: 8080)')
        parser.add_argument('--catalogd-namespace', default='openshift-catalogd',
                           help='Namespace containing catalogd service (default: openshift-catalogd)')
        parser.add_argument('--catalogd-service', default='catalogd-service',
                           help='Name of catalogd service (default: catalogd-service)')
    
    def _add_common_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add common arguments used by both query methods."""
        parser.add_argument('--package',
                           help='Specific package name to query')
        parser.add_argument('--channel',
                           help='Specific channel name (optional, uses default channel if not specified)')
        parser.add_argument('--version',
                           help='Specific version (optional, uses latest version if not specified)')
        parser.add_argument('--insecure', action='store_true',
                           help='Skip TLS certificate verification')
    
    def _add_output_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add output mode arguments."""
        output_group = parser.add_mutually_exclusive_group()
        output_group.add_argument('--output', metavar='DIR',
                                 help='Save YAML files to specified directory')
        output_group.add_argument('--deploy', action='store_true',
                                 help='Deploy RBAC resources directly to cluster using oc apply')
    
    def _add_action_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add action/operation arguments."""
        parser.add_argument('--list-catalogs', action='store_true',
                           help='List available ClusterCatalogs in the cluster with their status')
        parser.add_argument('--list-packages', action='store_true',
                           help='List all available packages and exit')
        parser.add_argument('--all-namespaces-packages', action='store_true',
                           help='List packages supporting AllNamespaces install mode')
        parser.add_argument('--verbose', '-v', action='store_true',
                           help='Enable verbose logging')
    
    def _add_configuration_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add configuration-related arguments."""
        parser.add_argument('--config',
                           help='Path to configuration file (default: search standard locations)')
        parser.add_argument('--generate-config',
                           help='Generate sample configuration file at specified path and exit')
    
    def _get_help_epilog(self) -> str:
        """Return the help epilog text."""
        return """
Examples:
  # Print RBAC YAML to stdout (default)
  %(prog)s --catalogd --package prometheus --insecure
  
  # Deploy RBAC directly to cluster
  %(prog)s --catalogd --package cert-manager --deploy --insecure
  
  # Save RBAC files to directory
  %(prog)s --catalogd --package jaeger --output ./my-rbac-files --insecure
  
  # Use explicit cluster URL
  %(prog)s --catalogd --openshift-url https://api.cluster.com:6443 --package prometheus --insecure
  
  # Extract via OPM image
  %(prog)s --opm --image quay.io/operatorhubio/catalog:latest --package prometheus
  
  # List available ClusterCatalogs
  %(prog)s --catalogd --list-catalogs --insecure
  
  # List all packages (interactive catalog selection)
  %(prog)s --catalogd --list-packages --insecure
  
  # List packages from specific catalog
  %(prog)s --catalogd --catalog-name openshift-certified-operators --list-packages --insecure
  
  # Using service account token
  %(prog)s --catalogd --openshift-token sha256~abc123... --package grafana --deploy

Configuration File:
  The tool supports configuration files to set default values for frequently used options.
  Default locations (in order): ./rbac-manager.yaml, ~/.rbac-manager.yaml, ~/.config/rbac-manager.yaml
  
  Generate a sample config: %(prog)s --generate-config ~/.rbac-manager.yaml
  Use custom config file: %(prog)s --config /path/to/config.yaml --catalogd --package prometheus
        """
    
    def validate_arguments(self, args: argparse.Namespace) -> None:
        """
        Validate parsed arguments for consistency and requirements.
        
        Args:
            args: Parsed command line arguments
            
        Raises:
            argparse.ArgumentError: If validation fails
        """
        if args.opm and not args.image:
            if self.parser:
                self.parser.error("--image is required when using --opm")
            else:
                raise ValueError("--image is required when using --opm")
