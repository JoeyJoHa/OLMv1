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

# Catalogd libraries  
from .catalogd import CatalogdService

# OPM libraries
from .opm import BundleProcessor, YAMLGenerator, HelmGenerator

# Help manager (keeping existing)
from .help_manager import HelpManager

logger = logging.getLogger(__name__)


class RBACManager:
    """Main application orchestrator for RBAC Manager tool"""
    
    def __init__(self, skip_tls: bool = False, debug: bool = False):
        """
        Initialize RBAC Manager with microservice architecture
        
        Args:
            skip_tls: Whether to skip TLS verification
            debug: Enable debug logging
        """
        self.skip_tls = skip_tls
        self.debug = debug
        
        # Set up logging
        setup_logging(debug)
        
        if skip_tls:
            disable_ssl_warnings()
        
        # Initialize core services
        self.auth = OpenShiftAuth(skip_tls=skip_tls)
        self.config_manager = ConfigManager()
        self.help_manager = HelpManager()
        
        # Initialize catalogd service (will be configured with auth when needed)
        self.catalogd_service = None
        
        # Initialize OPM services
        self.bundle_processor = BundleProcessor(skip_tls=skip_tls, debug=debug)
        self.yaml_generator = YAMLGenerator()
        self.helm_generator = HelmGenerator()
    
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
                raise ConfigurationError("Catalogd service not initialized. Configure authentication first.")
            
            return self.catalogd_service.display_catalogs_enhanced()
            
        except Exception as e:
            logger.error(f"Failed to list catalogs: {e}")
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
                raise ConfigurationError("Catalogd service not initialized. Configure authentication first.")
            
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
                print(json.dumps(result, indent=2))
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
                print(json.dumps(result, indent=2))
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
                print(json.dumps(result, indent=2))
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
            print(json.dumps(result, indent=2))
            
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
        except Exception as e:
            logger.error(f"Error querying catalogd: {e}")
            print(f"Error: {e}", file=sys.stderr)
    
    def extract_bundle(self, image: str, namespace: str = "default", registry_token: str = None,
                      helm: bool = False, output_dir: str = None, least_privileges: bool = False,
                      stdout: bool = False) -> None:
        """
        Extract RBAC from operator bundle
        
        Args:
            image: Container image URL
            namespace: Target namespace
            registry_token: Registry authentication token (optional)
            helm: Generate Helm values
            output_dir: Output directory (optional)
            least_privileges: Apply least privilege principles
            stdout: Output to stdout instead of files
        """
        try:
            # Check if image is index image
            if self.bundle_processor.is_index_image(image):
                print(f"Error: {image} appears to be an index image.")
                print("Please create a ClusterCatalog for this index image and query it using --catalogd instead.")
                return
            
            # Extract bundle metadata
            print(f"Extracting metadata from bundle image: {image}")
            metadata = self.bundle_processor.extract_bundle_metadata(image, registry_token)
            
            if not metadata:
                print("Failed to extract bundle metadata")
                return
            
            print("Bundle metadata extracted successfully")
            
            # Generate outputs based on flags
            if helm:
                self._generate_helm_output(metadata, least_privileges, output_dir, stdout)
            else:
                self._generate_yaml_output(metadata, namespace, least_privileges, output_dir, stdout)
                
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
    
    def _generate_yaml_output(self, metadata: Dict[str, Any], namespace: str, 
                             least_privileges: bool, output_dir: str, stdout: bool) -> None:
        """Generate YAML manifest output"""
        manifests = self.yaml_generator.generate_manifests(metadata, namespace, least_privileges)
        
        if stdout or not output_dir:
            # Output to stdout
            for manifest_name, manifest_content in manifests.items():
                print(f"\n{'='*50}")
                print(f"{manifest_name.upper()}")
                print("="*50)
                print(manifest_content)
        else:
            # Save to files
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            timestamp = int(time.time())
            hex_suffix = hex(hash(metadata.get('image', '')))[-8:]
            
            for manifest_name, manifest_content in manifests.items():
                filename = f"{manifest_name}-{timestamp}-{hex_suffix}.yaml"
                file_path = output_path / filename
                
                with open(file_path, 'w') as f:
                    f.write(manifest_content)
                
                print(f"{manifest_name} saved to: {file_path}")
    
    def _generate_helm_output(self, metadata: Dict[str, Any], least_privileges: bool,
                             output_dir: str, stdout: bool) -> None:
        """Generate Helm values output"""
        helm_values = self.helm_generator.generate_helm_values(metadata, least_privileges)
        
        if stdout or not output_dir:
            print("\n" + "="*50)
            print("HELM VALUES")
            print("="*50)
            print(helm_values)
        else:
            # Save to files
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            timestamp = int(time.time())
            hex_suffix = hex(hash(metadata.get('image', '')))[-8:]
            
            filename = f"values-{timestamp}-{hex_suffix}.yaml"
            file_path = output_path / filename
            
            with open(file_path, 'w') as f:
                f.write(helm_values)
            
            print(f"Helm values saved to: {file_path}")


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
    parser.add_argument('--namespace', default='default', help='Target namespace')
    parser.add_argument('--openshift-namespace', help='Alias for --namespace')
    parser.add_argument('--registry-token', help='Registry authentication token')
    parser.add_argument('--helm', action='store_true', help='Generate Helm values')
    parser.add_argument('--output', help='Output directory')
    parser.add_argument('--least-privileges', action='store_true', help='Apply least privilege principles')
    
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
            rbac_manager_temp = RBACManager()
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
        
        rbac_manager = RBACManager(skip_tls=skip_tls, debug=debug)
        
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
                least_privileges = args.least_privileges
                
                if config and 'opm' in config:
                    opm_config = config['opm']
                    image = image or opm_config.get('image')
                    namespace = namespace or opm_config.get('namespace', 'default')
                    registry_token = registry_token or opm_config.get('registry_token')
                    helm = helm or opm_config.get('helm', False)
                    output = output or opm_config.get('output')
                    least_privileges = least_privileges or opm_config.get('least_privileges', False)
                
                if not image:
                    print("Error: --image is required for OPM operations")
                    sys.exit(1)
                
                rbac_manager.extract_bundle(
                    image=image,
                    namespace=namespace,
                    registry_token=registry_token,
                    helm=helm,
                    output_dir=output,
                    least_privileges=least_privileges,
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
