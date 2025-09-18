"""
Main Application

Orchestrates the microservice-like architecture with core, catalogd, and opm libraries.
"""

import argparse
import json
import logging
import os
import sys
import tempfile
import time
from typing import Dict, Any, Optional

# Core libraries
from .core import OpenShiftAuth, ConfigManager, setup_logging, disable_ssl_warnings
from .core.exceptions import AuthenticationError, ConfigurationError
from .core.protocols import AuthProvider, ConfigProvider, BundleProvider, CatalogdProvider, HelpProvider
from .core.constants import ErrorMessages, KubernetesConstants

# Catalogd libraries  
from .catalogd import CatalogdService

# OPM libraries
from .opm import BundleProcessor

# Help manager (keeping existing)
from .help_manager import HelpManager

logger = logging.getLogger(__name__)


class RBACManager:
    """Main application orchestrator for RBAC Manager tool"""
    
    def __init__(
        self,
        auth_provider: Optional[AuthProvider] = None,
        config_provider: Optional[ConfigProvider] = None, 
        bundle_provider: Optional[BundleProvider] = None,
        help_provider: Optional[HelpProvider] = None,
        skip_tls: bool = False,
        debug: bool = False
    ):
        """
        Initialize RBAC Manager with dependency injection
        
        Args:
            auth_provider: Authentication provider (defaults to OpenShiftAuth)
            config_provider: Configuration provider (defaults to ConfigManager)
            bundle_provider: Bundle processor (defaults to BundleProcessor)
            help_provider: Help manager (defaults to HelpManager)
            skip_tls: Whether to skip TLS verification
            debug: Enable debug logging
        """
        self.skip_tls = skip_tls
        self.debug = debug
        
        # Set up logging
        setup_logging(debug)
        
        if skip_tls:
            disable_ssl_warnings()
        
        # Inject dependencies with defaults
        self.auth = auth_provider or OpenShiftAuth(skip_tls=skip_tls)
        self.config_manager = config_provider or ConfigManager()
        self.help_manager = help_provider or HelpManager()
        self.bundle_processor = bundle_provider or BundleProcessor(skip_tls=skip_tls, debug=debug)
        
        # Initialize catalogd service (will be configured with auth when needed)
        self.catalogd_service: Optional[CatalogdProvider] = None
    
    def configure_authentication(self, openshift_url: str = None, openshift_token: str = None) -> bool:
        """
        Configure authentication and initialize services
        
        Args:
            openshift_url: OpenShift cluster URL (optional)
            openshift_token: OpenShift authentication token (optional)
            
        Returns:
            bool: True if authentication configured successfully
        """
        try:
            if self.auth.configure_auth(openshift_url, openshift_token):
                # Get Kubernetes clients
                k8s_client, custom_api, core_api = self.auth.get_kubernetes_clients()
                
                # Initialize catalogd service with authenticated clients
                self.catalogd_service = CatalogdService(
                    core_api=core_api,
                    custom_api=custom_api,
                    skip_tls=self.skip_tls,
                    debug=self.debug
                )
                
                logger.debug("Successfully configured authentication and services")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to configure authentication: {e}")
            return False
    
    def load_config(self, config_path: str) -> Dict[str, Any]:
        """
        Load configuration from file
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            Dict containing configuration data
        """
        return self.config_manager.load_config(config_path)
    
    def generate_config(self, output_dir: str = None) -> str:
        """
        Generate configuration template
        
        Args:
            output_dir: Directory to save template (optional)
            
        Returns:
            str: Path to generated template file
        """
        return self.config_manager.generate_config_template(output_dir)
    
    def list_catalogs(self) -> int:
        """
        List ClusterCatalogs
        
        Returns:
            int: Exit code (0 for success, 1 for error)
        """
        try:
            if not self.catalogd_service:
                raise ConfigurationError(ErrorMessages.CATALOGD_SERVICE_NOT_INITIALIZED)
            
            return self.catalogd_service.display_catalogs_enhanced()
            
        except (ConfigurationError, AuthenticationError) as e:
            logger.error(f"Configuration error while listing catalogs: {e}")
            print(f"Error: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            logger.error(f"Unexpected error while listing catalogs: {e}")
            print(f"Error: {e}", file=sys.stderr)
            return 1
    
    def query_catalogd(self, catalog_name: str = None, package: str = None, 
                      channel: str = None, version: str = None) -> None:
        """
        Query catalogd service for package information
        
        Args:
            catalog_name: Name of the catalog (optional, will prompt if not provided)
            package: Package name (optional)
            channel: Channel name (optional)
            version: Version (optional)
        """
        try:
            if not self.catalogd_service:
                raise ConfigurationError(ErrorMessages.CATALOGD_SERVICE_NOT_INITIALIZED)
            
            # Get authentication headers
            auth_headers = self.auth.get_auth_headers()
            
            # Interactive catalog selection if not provided
            if not catalog_name:
                catalog_name = self._select_catalog_interactively()
                if not catalog_name:
                    return
            
            # Hierarchical query based on provided parameters
            if not package:
                # List packages
                packages = self.catalogd_service.get_catalog_packages(catalog_name, auth_headers)
                result = {
                    "catalog": catalog_name,
                    "type": "packages", 
                    "data": packages,
                    "total": len(packages)
                }
                self._print_json_output(result)
                return
            
            if not channel:
                # List channels for package
                channels = self.catalogd_service.get_package_channels(catalog_name, package, auth_headers)
                result = {
                    "catalog": catalog_name,
                    "package": package,
                    "type": "channels",
                    "data": channels,
                    "total": len(channels)
                }
                self._print_json_output(result)
                return
            
            if not version:
                # List versions for channel
                versions = self.catalogd_service.get_channel_versions(catalog_name, package, channel, auth_headers)
                result = {
                    "catalog": catalog_name,
                    "package": package,
                    "channel": channel,
                    "type": "versions",
                    "data": versions,
                    "total": len(versions)
                }
                self._print_json_output(result)
                return
            
            # Get version metadata
            metadata = self.catalogd_service.get_version_metadata(catalog_name, package, channel, version, auth_headers)
            result = {
                "catalog": catalog_name,
                "package": package,
                "channel": channel,
                "version": version,
                "type": "metadata",
                "data": metadata
            }
            self._print_json_output(result)
            
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
        except Exception as e:
            logger.error(f"Error querying catalogd: {e}")
            print(f"Error: {e}", file=sys.stderr)
    
    def extract_bundle(self, image: str, namespace: str = KubernetesConstants.DEFAULT_NAMESPACE, registry_token: str = None,
                      helm: bool = False, output_dir: str = None, stdout: bool = False, 
                      channel: str = None) -> None:
        """
        Extract RBAC from operator bundle
        
        Args:
            image: Container image URL
            namespace: Target namespace
            registry_token: Registry authentication token (optional)
            helm: Generate Helm values
            output_dir: Output directory (optional)
            stdout: Output to stdout instead of files
            channel: Operator channel (optional, used in Helm values)
        """
        try:
            # Extract bundle metadata
            print(f"Extracting metadata from bundle image: {image}")
            metadata = self.bundle_processor.extract_bundle_metadata(image, registry_token)
            
            if not metadata:
                print("Failed to extract bundle metadata")
                return
            
            print("Bundle metadata extracted successfully")
            
            # Generate outputs based on flags
            if helm:
                self._generate_helm_output(metadata, output_dir, stdout, channel)
            else:
                self._generate_yaml_output(metadata, namespace, output_dir, stdout)
                
        except Exception as e:
            logger.error(f"Error extracting bundle: {e}")
            print(f"Error: {e}", file=sys.stderr)
    
    def _select_catalog_interactively(self) -> Optional[str]:
        """
        Interactively select a catalog from available catalogs
        
        Returns:
            str: Selected catalog name, None if cancelled
        """
        try:
            catalogs_data = self.catalogd_service.list_cluster_catalogs()
            if not catalogs_data:
                print("No ClusterCatalogs found in this cluster.")
                return None
            
            # Convert to simple list format
            catalogs = []
            for catalog in catalogs_data:
                name = catalog.get('metadata', {}).get('name', 'Unknown')
                status = catalog.get('status', {})
                conditions = status.get('conditions', [])
                serving = any(c.get('type') == 'Serving' and c.get('status') == 'True' for c in conditions)
                
                catalogs.append({
                    'name': name,
                    'serving': serving
                })
            
            print("\nAvailable ClusterCatalogs:")
            for i, catalog in enumerate(catalogs, 1):
                serving_status = "✓ Serving" if catalog['serving'] else "✗ Not Serving"
                print(f"{i}. {catalog['name']} ({serving_status})")
            
            while True:
                try:
                    choice = input(f"\nSelect a catalog (1-{len(catalogs)}): ").strip()
                    if choice.isdigit() and 1 <= int(choice) <= len(catalogs):
                        return catalogs[int(choice) - 1]['name']
                    else:
                        print(f"Please enter a number between 1 and {len(catalogs)}")
                except (KeyboardInterrupt, EOFError):
                    print("\nOperation cancelled.")
                    return None
                    
        except Exception as e:
            logger.error(f"Failed to select catalog interactively: {e}")
            return None
    
    def _generate_yaml_output(self, metadata: Dict[str, Any], namespace: str, output_dir: str, stdout: bool) -> None:
        """Generate YAML manifest output"""
        package_name = metadata.get('package_name', 'my-operator')
        
        try:
            # Generate manifests using the bundle processor
            manifests = self.bundle_processor.generate_yaml_manifests(metadata, namespace, package_name)
            
            # Use unified output method
            self._save_output_files(manifests, package_name, output_dir, stdout, "YAML manifests")
                
        except Exception as e:
            logger.error(f"Failed to generate YAML manifests: {e}")
            raise
    
    def _save_output_files(self, content_dict: Dict[str, str], package_name: str, 
                          output_dir: str, stdout: bool, content_type: str) -> None:
        """
        Unified method for saving output files (YAML manifests or Helm values)
        
        Args:
            content_dict: Dictionary of filename -> content for multiple files, 
                         or single key-value pair for single file
            package_name: Name of the package for timestamped filename
            output_dir: Output directory path
            stdout: Whether to print to stdout instead of saving files
            content_type: Description for logging (e.g., "YAML manifests", "Helm values")
        """
        if stdout or not output_dir:
            # Print to stdout
            if len(content_dict) == 1:
                # Single content (Helm values)
                content = next(iter(content_dict.values()))
                print(f"\n{'='*50}")
                print(f"{content_type.upper()}")
                print("="*50)
                print(content)
            else:
                # Multiple content (YAML manifests)
                for name, content in content_dict.items():
                    print(f"\n{'='*50}")
                    print(f"{name.upper()}")
                    print("="*50)
                    print(content)
        else:
            # Save to files with operator name and timestamp
            os.makedirs(output_dir, exist_ok=True)
            
            # Generate timestamp string
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            
            if len(content_dict) == 1:
                # Single file (Helm values)
                content = next(iter(content_dict.values()))
                filename = f"{package_name}-{timestamp}.yaml"
                filepath = os.path.join(output_dir, filename)
                with open(filepath, 'w') as f:
                    f.write(content)
                logger.info(f"{content_type} saved to: {filepath}")
            else:
                # Multiple files (YAML manifests)
                for filename, content in content_dict.items():
                    manifest_filename = f"{filename}-{timestamp}.yaml"
                    manifest_file = os.path.join(output_dir, manifest_filename)
                    with open(manifest_file, 'w') as f:
                        f.write(content)
                    logger.info(f"Manifest saved to: {manifest_file}")
            
            print(f"{content_type} generated successfully")

    def _generate_helm_output(self, metadata: Dict[str, Any], output_dir: str, stdout: bool, channel: str = None) -> None:
        """Generate Helm values output"""
        package_name = metadata.get('package_name', 'my-operator')
        
        # Generate Helm values with channel information
        helm_values = self.bundle_processor.generate_helm_values(metadata, package_name, channel=channel)
        
        # Use unified output method (single file, so use package name as key)
        content_dict = {package_name: helm_values}
        self._save_output_files(content_dict, package_name, output_dir, stdout, "Helm values")
    
    def _print_json_output(self, data: Dict[str, Any]) -> None:
        """
        Print JSON output with proper handling for large data
        
        Args:
            data: Dictionary to output as JSON
        """
        try:
            # Use separators to make output more compact for large data
            json_str = json.dumps(data, indent=2, separators=(',', ': '), ensure_ascii=False)
            
            # For very large output, we might want to use sys.stdout.write
            # to avoid potential buffering issues with print()
            if len(json_str) > 1000000:  # 1MB threshold
                sys.stdout.write(json_str)
                sys.stdout.write('\n')
                sys.stdout.flush()
            else:
                print(json_str)
                
        except Exception as e:
            logger.error(f"Failed to output JSON: {e}")
            # Fallback to basic print
            print(json.dumps(data, indent=2))


# Factory function for easy creation
def create_rbac_manager(skip_tls: bool = False, debug: bool = False) -> RBACManager:
    """
    Factory function to create RBACManager with default dependencies
    
    Args:
        skip_tls: Whether to skip TLS verification
        debug: Enable debug logging
        
    Returns:
        RBACManager: Configured RBACManager instance
    """
    return RBACManager(skip_tls=skip_tls, debug=debug)


# Command-line interface functions (keeping existing structure)
def create_argument_parser():
    """Create and configure argument parser with subcommands using parent parsers to eliminate redundancy"""
    
    # Create parent parsers for common argument groups
    
    # Common parser: arguments shared by ALL commands
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    common_parser.add_argument('--examples', action='store_true', help='Show usage examples for this command')
    
    # Auth parser: arguments shared by commands that need authentication
    auth_parser = argparse.ArgumentParser(add_help=False)
    auth_parser.add_argument('--skip-tls', action='store_true', help='Skip TLS verification for insecure requests')
    auth_parser.add_argument('--openshift-url', help='OpenShift cluster URL')
    auth_parser.add_argument('--openshift-token', help='OpenShift authentication token')
    
    # Output parser: arguments shared by commands that generate output
    output_parser = argparse.ArgumentParser(add_help=False)
    output_parser.add_argument('--output', help='Output directory for generated files')
    
    # Main parser
    parser = argparse.ArgumentParser(
        description='RBAC Manager - Extract RBAC permissions from operator bundles and query catalogs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  rbac-manager list-catalogs --skip-tls
  rbac-manager catalogd --generate-config --package argocd-operator --channel alpha
  rbac-manager opm --config config.yaml
  
Use --help with specific commands for detailed help.
        """
    )
    
    # Create subparsers for commands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # list-catalogs subcommand: inherits from common_parser and auth_parser
    list_parser = subparsers.add_parser(
        'list-catalogs',
        parents=[common_parser, auth_parser],
        help='List all ClusterCatalogs',
        description='List all available ClusterCatalogs in the cluster'
    )
    # No additional arguments needed - all inherited from parents
    
    # catalogd subcommand: inherits from common_parser, auth_parser, and output_parser
    catalogd_parser = subparsers.add_parser(
        'catalogd',
        parents=[common_parser, auth_parser, output_parser],
        help='Query catalogd service',
        description='Query catalogd service for package information'
    )
    # Add catalogd-specific arguments
    catalogd_parser.add_argument('--catalog-name', help='Catalog name')
    catalogd_parser.add_argument('--package', help='Package name')
    catalogd_parser.add_argument('--channel', help='Channel name')
    catalogd_parser.add_argument('--version', help='Version')
    catalogd_parser.add_argument('--generate-config', action='store_true', help='Generate configuration file (stdout by default, use --output to save to file)')
    
    # opm subcommand: inherits from common_parser and output_parser (no auth needed for local operations)
    opm_parser = subparsers.add_parser(
        'opm',
        parents=[common_parser, output_parser],
        help='Extract RBAC from bundle using OPM',
        description='Extract RBAC permissions from operator bundle images using OPM'
    )
    # Add opm-specific arguments
    opm_parser.add_argument('--config', help='Configuration file path')
    opm_parser.add_argument('--skip-tls', action='store_true', help='Skip TLS verification for insecure requests')
    opm_parser.add_argument('--image', help='Container image URL')
    opm_parser.add_argument('--namespace', default=KubernetesConstants.DEFAULT_NAMESPACE, help='Target namespace')
    opm_parser.add_argument('--openshift-namespace', help='Alias for --namespace')
    opm_parser.add_argument('--registry-token', help='Registry authentication token')
    opm_parser.add_argument('--helm', action='store_true', help='Generate Helm values')
    
    return parser


def handle_examples(command_name: str) -> bool:
    """Handle examples flag for any command. Returns True if examples were shown."""
    help_manager = HelpManager()
    help_manager.show_help(f"{command_name.replace('-', '_')}_examples")
    return True


def configure_authentication_from_args(rbac_manager, args):
    """
    Configure authentication using centralized auth logic from OpenShiftAuth.
    
    Args:
        rbac_manager: RBACManager instance
        args: Parsed command-line arguments
    """
    if hasattr(args, 'openshift_url') and hasattr(args, 'openshift_token') and args.openshift_url and args.openshift_token:
        if not rbac_manager.configure_authentication(args.openshift_url, args.openshift_token):
            print("Failed to configure OpenShift authentication")
            sys.exit(1)
    else:
        # Try to configure with default context
        if not rbac_manager.configure_authentication():
            print("Failed to configure authentication from context")
            sys.exit(1)




def generate_config_file(args, extracted_data=None, output_path=None, stdout=False):
    """
    Generate configuration file using ConfigManager (DRY principle).
    
    Args:
        args: Parsed command-line arguments
        extracted_data: Dictionary with extracted values from catalogd/opm (optional)
        output_path: Custom output path (optional)
        stdout: Output to stdout instead of file (optional)
    
    Returns:
        str: Path to generated config file, or None if output to stdout
    """
    config_manager = ConfigManager()
    
    # Calculate configuration values once to eliminate duplication (DRY principle)
    output_mode = 'file' if (hasattr(args, 'output') and args.output) else 'stdout'
    output_type = 'helm' if (hasattr(args, 'helm') and args.helm) else 'yaml'
    namespace = getattr(args, 'namespace', 'default')
    
    # Determine if we should output to stdout or file
    output_to_stdout = stdout or (not output_path and not (hasattr(args, 'output') and args.output))
    
    if output_to_stdout:
        # Generate config content and output to stdout
        if extracted_data:
            # Get YAML content directly as string
            yaml_content = config_manager.get_config_with_values_content(
                extracted_data=extracted_data,
                output_mode=output_mode,
                output_type=output_type,
                namespace=namespace
            )
            print(yaml_content)
        else:
            # Get template YAML content directly as string
            yaml_content = config_manager.get_config_template_content()
            print(yaml_content)
        
        return None
    else:
        # Save to file
        output_dir = output_path or (args.output if hasattr(args, 'output') and args.output else './config')
        
        if extracted_data:
            # Generate config with extracted values
            return config_manager.generate_config_with_values(
                extracted_data=extracted_data,
                output_dir=output_dir,
                output_mode=output_mode,
                output_type=output_type,
                namespace=namespace
            )
        else:
            # Generate template config
            return config_manager.generate_config_template(output_dir=output_dir)


def merge_config_with_args(args, config, command_name: str):
    """
    Merge configuration file values with command-line arguments.
    
    This function directly updates the args object with values from the configuration
    file, but only for attributes that are None or False (not provided via command line).
    
    Args:
        args: Parsed command-line arguments object
        config: Loaded configuration dictionary  
        command_name: Name of the command (used as config section key)
    """
    if not config:
        return
    
    # Handle new config structure with operator, output, and global sections
    if 'operator' in config:
        # Map operator config to args
        operator_config = config['operator']
        if hasattr(args, 'image') and (not args.image or args.image == '') and 'image' in operator_config:
            if operator_config['image'] and operator_config['image'] != 'image-url':
                args.image = operator_config['image']
        if hasattr(args, 'namespace') and (not args.namespace or args.namespace == 'default') and 'namespace' in operator_config:
            args.namespace = operator_config['namespace']
        if hasattr(args, 'channel') and (not args.channel or args.channel == '') and 'channel' in operator_config:
            args.channel = operator_config['channel']
        if hasattr(args, 'package') and (not args.package or args.package == '') and 'packageName' in operator_config:
            args.package = operator_config['packageName']
        if hasattr(args, 'version') and (not args.version or args.version == '') and 'version' in operator_config:
            args.version = operator_config['version']
    
    if 'output' in config:
        # Map output config to args - config takes precedence
        output_config = config['output']
        if hasattr(args, 'output') and output_config.get('mode') == 'file' and 'path' in output_config:
            args.output = output_config['path']
        if hasattr(args, 'helm'):
            # Set helm flag based on config type, regardless of command line
            args.helm = (output_config.get('type') == 'helm')
    
    if 'global' in config:
        # Map global config to args
        global_config = config['global']
        if hasattr(args, 'skip_tls') and not args.skip_tls and global_config.get('skip_tls'):
            args.skip_tls = global_config['skip_tls']
        if hasattr(args, 'debug') and not args.debug and global_config.get('debug'):
            args.debug = global_config['debug']
    
    # Handle legacy config structure for backward compatibility
    if command_name in config:
        command_config = config[command_name]
        
        # Iterate through all config values for this command
        for config_key, config_value in command_config.items():
            if config_value is not None and hasattr(args, config_key):
                current_value = getattr(args, config_key)
                
                # Only override if the current value is None, empty string, or False
                # This ensures command-line arguments take precedence
                if current_value is None or current_value == '' or current_value is False:
                    setattr(args, config_key, config_value)


def handle_list_catalogs_command(args, rbac_manager, config):
    """Handle list-catalogs command execution."""
    if hasattr(args, 'examples') and args.examples:
        return handle_examples('list-catalogs')
    
    # Merge configuration file values with command-line arguments
    merge_config_with_args(args, config, 'list-catalogs')
    
    configure_authentication_from_args(rbac_manager, args)
    
    exit_code = rbac_manager.list_catalogs()
    sys.exit(exit_code)


def handle_catalogd_command(args, rbac_manager, config):
    """Handle catalogd command execution."""
    if hasattr(args, 'examples') and args.examples:
        return handle_examples('catalogd')
    
    # Handle generate-config flag
    if hasattr(args, 'generate_config') and args.generate_config:
        # Determine output mode: stdout by default, file if --output is specified
        output_to_stdout = not (hasattr(args, 'output') and args.output)
        
        # If no other flags provided, generate template
        if not any([args.catalog_name, args.package, args.channel, args.version]):
            config_file = generate_config_file(args, stdout=output_to_stdout)
            if not output_to_stdout:
                print(f"Configuration template generated: {config_file}")
            return
        
        # Otherwise, extract data first, then generate config
        # Merge configuration file values with command-line arguments
        merge_config_with_args(args, config, 'catalogd')
        
        # Try to get real data from catalogd if authentication is provided
        extracted_data = {
            'bundle_image': 'bundle-image-from-catalogd',  # Default placeholder
            'channel': args.channel or 'channel-name',
            'package': args.package or 'package-name',
            'version': args.version or 'version'
        }
        
        # Attempt to query catalogd if authentication is available
        if hasattr(args, 'openshift_url') and args.openshift_url and hasattr(args, 'openshift_token') and args.openshift_token:
            try:
                # Configure authentication using centralized auth logic (optional for generate-config)
                if not rbac_manager.configure_authentication(args.openshift_url, args.openshift_token):
                    raise Exception("Failed to configure OpenShift authentication")
                
                # Try to get real bundle metadata from catalogd
                if args.catalog_name and args.package and args.channel and args.version:
                    bundle_data = rbac_manager.catalogd_service.get_version_metadata(
                        args.catalog_name, args.package, args.channel, args.version,
                        rbac_manager.auth.get_auth_headers()
                    )
                    if bundle_data and 'bundle_image' in bundle_data and bundle_data['bundle_image']:
                        extracted_data['bundle_image'] = bundle_data['bundle_image']
                        if not output_to_stdout:
                            print("Successfully extracted bundle image from catalogd")
                    else:
                        if not output_to_stdout:
                            print("Note: Could not extract bundle image from catalogd, using placeholder")
                else:
                    if not output_to_stdout:
                        print("Note: --catalog-name required with authentication for real bundle data")
            except Exception as e:
                if not output_to_stdout:
                    print(f"Note: Could not query catalogd ({e}), using placeholder values")
        else:
            if not output_to_stdout:
                print("Note: Use --openshift-url and --openshift-token with --catalog-name for real bundle data")
        
        config_file = generate_config_file(args, extracted_data, stdout=output_to_stdout)
        if not output_to_stdout:
            if extracted_data['bundle_image'] == 'bundle-image-from-catalogd':
                print(f"Configuration template generated with provided values: {config_file}")
                print("Note: Bundle image URL should be updated with actual value from catalogd query.")
            else:
                print(f"Configuration generated with extracted bundle data: {config_file}")
        return
    
    # Check if any operational flags are provided
    if not any([args.catalog_name, args.package, args.channel, args.version]):
        print("No catalogd operation specified. Use 'rbac-manager catalogd --help' to see available options.\n")
        return
    
    # Merge configuration file values with command-line arguments
    merge_config_with_args(args, config, 'catalogd')
    
    configure_authentication_from_args(rbac_manager, args)
    
    rbac_manager.query_catalogd(
        catalog_name=args.catalog_name,
        package=args.package,
        channel=args.channel,
        version=args.version
    )


def handle_opm_command(args, rbac_manager, config):
    """Handle opm command execution."""
    if hasattr(args, 'examples') and args.examples:
        return handle_examples('opm')
    
    # Merge configuration file values with command-line arguments first
    merge_config_with_args(args, config, 'opm')
    
    # Check if image is provided (required for non-examples operations)
    if not args.image:
        print("Error: --image is required for OPM operations. Use 'rbac-manager opm --examples' to see usage examples.")
        sys.exit(1)
    
    # Set defaults for opm-specific fields
    args.namespace = args.namespace or KubernetesConstants.DEFAULT_NAMESPACE
    args.helm = args.helm or False
    
    # Extract channel from config if available
    channel = None
    if config and 'operator' in config and 'channel' in config['operator']:
        channel = config['operator']['channel']
    
    rbac_manager.extract_bundle(
        image=args.image,
        namespace=args.namespace,
        registry_token=args.registry_token,
        helm=args.helm,
        output_dir=args.output,
        stdout=not args.output,
        channel=channel
    )


# Command dispatcher mapping
COMMAND_HANDLERS = {
    'list-catalogs': handle_list_catalogs_command,
    'catalogd': handle_catalogd_command,
    'opm': handle_opm_command,
}


def main():
    """Main entry point"""
    try:
        # Handle special case where no arguments are provided
        if len(sys.argv) == 1:
            help_manager = HelpManager()
            help_manager.show_help()
            return
        
        parser = create_argument_parser()
        args = parser.parse_args()
        
        # Handle openshift-namespace (alias for namespace) if available
        if hasattr(args, 'openshift_namespace') and args.openshift_namespace:
            args.namespace = args.openshift_namespace
        
        # Load configuration if provided (only opm command has --config)
        config = None
        if hasattr(args, 'config') and args.config:
            rbac_manager_temp = create_rbac_manager()
            config = rbac_manager_temp.load_config(args.config)
        
        # Check if a command was specified
        if not args.command:
            print("Error: No command specified. Use --help for usage information.")
            sys.exit(1)
        
        # Apply configuration overrides (some commands may not have all flags)
        skip_tls = getattr(args, 'skip_tls', False)
        debug = getattr(args, 'debug', False)
        
        if config:
            config_defaults = config
            skip_tls = skip_tls or config_defaults.get('skip_tls', False)
            debug = debug or config_defaults.get('debug', False)
        
        rbac_manager = create_rbac_manager(skip_tls=skip_tls, debug=debug)
        
        try:
            # Use dispatcher pattern to execute commands
            handler = COMMAND_HANDLERS.get(args.command)
            if handler:
                handler(args, rbac_manager, config)
            else:
                print(f"Unknown command: {args.command}")
                sys.exit(1)
            
        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
