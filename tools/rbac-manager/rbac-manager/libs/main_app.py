"""
Main Application

Orchestrates the microservice-like architecture with core, catalogd, and opm libraries.
"""

import json
import logging
import sys
import time
from pathlib import Path
from typing import Dict, Any, Optional

# Core libraries
from .core import OpenShiftAuth, ConfigManager, setup_logging, disable_ssl_warnings
from .core.exceptions import RBACManagerError, AuthenticationError, ConfigurationError
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
    
    def extract_bundle(self, image: str, namespace: str = "default", registry_token: str = None,
                      helm: bool = False, output_dir: str = None, stdout: bool = False) -> None:
        """
        Extract RBAC from operator bundle
        
        Args:
            image: Container image URL
            namespace: Target namespace
            registry_token: Registry authentication token (optional)
            helm: Generate Helm values
            output_dir: Output directory (optional)
            stdout: Output to stdout instead of files
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
                self._generate_helm_output(metadata, output_dir, stdout)
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
            import os
            import time
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

    def _generate_helm_output(self, metadata: Dict[str, Any], output_dir: str, stdout: bool) -> None:
        """Generate Helm values output"""
        package_name = metadata.get('package_name', 'my-operator')
        
        # Generate Helm values
        helm_values = self.bundle_processor.generate_helm_values(metadata, package_name)
        
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
                import sys
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
    """Create and configure argument parser"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='RBAC Manager - Extract RBAC permissions from operator bundles and query catalogs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  rbac-manager --list-catalogs
  rbac-manager --catalogd --catalog-name operatorhubio-catalog
  rbac-manager --opm --image quay.io/redhat/quay-operator-bundle:v3.10.0
  
Use --help with specific commands for detailed help.
        """
    )
    
    # Global flags
    parser.add_argument('--skip-tls', action='store_true', help='Skip TLS verification for insecure requests')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--examples', action='store_true', help='Show usage examples')
    
    # Commands
    parser.add_argument('--list-catalogs', action='store_true', help='List all ClusterCatalogs')
    parser.add_argument('--catalogd', action='store_true', help='Query catalogd service')
    parser.add_argument('--opm', action='store_true', help='Extract RBAC from bundle using OPM')
    parser.add_argument('--generate-config', action='store_true', help='Generate configuration template')
    
    # Authentication flags
    parser.add_argument('--openshift-url', help='OpenShift cluster URL')
    parser.add_argument('--openshift-token', help='OpenShift authentication token')
    
    # Catalogd flags
    parser.add_argument('--catalog-name', help='Catalog name')
    parser.add_argument('--package', help='Package name')
    parser.add_argument('--channel', help='Channel name')
    parser.add_argument('--version', help='Version')
    
    # OPM flags
    parser.add_argument('--image', help='Container image URL')
    parser.add_argument('--namespace', default=KubernetesConstants.DEFAULT_NAMESPACE, help='Target namespace')
    parser.add_argument('--openshift-namespace', help='Alias for --namespace')
    parser.add_argument('--registry-token', help='Registry authentication token')
    parser.add_argument('--helm', action='store_true', help='Generate Helm values')
    parser.add_argument('--output', help='Output directory')
    
    # Configuration
    parser.add_argument('--config', help='Configuration file path')
    
    return parser


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
        
        # Handle openshift-namespace (alias for namespace)
        if args.openshift_namespace:
            args.namespace = args.openshift_namespace
        
        # Load configuration if provided
        config = None
        if args.config:
            rbac_manager_temp = create_rbac_manager()
            config = rbac_manager_temp.load_config(args.config)
        
        # Determine which command was requested
        command_count = sum([args.list_catalogs, args.catalogd, args.opm, args.generate_config])
        
        # Handle help and examples
        if command_count == 0 and not args.examples:
            help_manager = HelpManager()
            help_manager.show_help()
            return
        
        if args.examples:
            help_manager = HelpManager()
            # Show command-specific examples if a command is specified
            if args.catalogd:
                help_manager.show_help("catalogd_examples")
            elif args.opm:
                help_manager.show_help("opm_examples")
            elif args.list_catalogs:
                help_manager.show_help("list_catalogs_examples")
            elif args.generate_config:
                help_manager.show_help("generate_config_examples")
            else:
                # Show general examples if no specific command
                help_manager.show_examples()
            return
        
        if command_count == 0:
            print("Error: No command specified. Use --help for usage information.")
            sys.exit(1)
        
        if command_count > 1:
            print("Error: Multiple commands specified. Please use only one command at a time.")
            sys.exit(1)
        
        # Apply configuration overrides
        skip_tls = args.skip_tls
        debug = args.debug
        
        if config:
            config_defaults = config
            skip_tls = skip_tls or config_defaults.get('skip_tls', False)
            debug = debug or config_defaults.get('debug', False)
        
        rbac_manager = create_rbac_manager(skip_tls=skip_tls, debug=debug)
        
        try:
            # Execute commands based on flags
            if args.list_catalogs:
                # Configure authentication if URL and token are provided
                if args.openshift_url and args.openshift_token:
                    if not rbac_manager.configure_authentication(args.openshift_url, args.openshift_token):
                        print("Failed to configure OpenShift authentication")
                        sys.exit(1)
                else:
                    # Try to configure with default context
                    rbac_manager.configure_authentication()
                
                exit_code = rbac_manager.list_catalogs()
                sys.exit(exit_code)
            
            elif args.catalogd:
                # If user passed only --catalogd (no operational flags), show help for catalogd
                if not any([args.catalog_name, args.package, args.channel, args.version]):
                    print("No catalogd operation specified. Use --help to see available options for --catalogd.\n")
                    return
                
                # Apply config overrides for catalogd
                catalog_name = args.catalog_name
                package = args.package
                channel = args.channel
                version = args.version
                
                if config and 'catalogd' in config:
                    catalogd_config = config['catalogd']
                    catalog_name = catalog_name or catalogd_config.get('catalog_name')
                    package = package or catalogd_config.get('package')
                    channel = channel or catalogd_config.get('channel')
                    version = version or catalogd_config.get('version')
                
                # Configure authentication
                if args.openshift_url and args.openshift_token:
                    if not rbac_manager.configure_authentication(args.openshift_url, args.openshift_token):
                        print("Failed to configure OpenShift authentication")
                        sys.exit(1)
                else:
                    # Try to configure with default context
                    rbac_manager.configure_authentication()
                
                rbac_manager.query_catalogd(
                    catalog_name=catalog_name,
                    package=package,
                    channel=channel,
                    version=version
                )
            
            elif args.opm:
                # Apply config overrides for opm
                image = args.image
                namespace = args.namespace
                registry_token = args.registry_token
                helm = args.helm
                output = args.output
                
                if config and 'opm' in config:
                    opm_config = config['opm']
                    image = image or opm_config.get('image')
                    namespace = namespace or opm_config.get('namespace', KubernetesConstants.DEFAULT_NAMESPACE)
                    registry_token = registry_token or opm_config.get('registry_token')
                    helm = helm or opm_config.get('helm', False)
                    output = output or opm_config.get('output')
                
                if not image:
                    print("Error: --image is required for OPM operations")
                    sys.exit(1)
                
                rbac_manager.extract_bundle(
                    image=image,
                    namespace=namespace,
                    registry_token=registry_token,
                    helm=helm,
                    output_dir=output,
                    stdout=not output
                )
            
            elif args.generate_config:
                config_file = rbac_manager.generate_config(args.output)
                print(f"Configuration template generated: {config_file}")
        
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
