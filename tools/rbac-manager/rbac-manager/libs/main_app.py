#!/usr/bin/env python3
"""
RBAC Manager Main Application Module

This module contains the main application logic for the RBAC Manager tool.
"""

import argparse
import json
import logging
import sys
import time
from pathlib import Path

from .catalog_manager import CatalogManager
from .bundle_processor import BundleProcessor
from .yaml_generator import YAMLGenerator
from .helm_generator import HelmGenerator
from .help_manager import HelpManager

logger = logging.getLogger(__name__)


class RBACManager:
    """Main RBAC Manager application"""
    
    def __init__(self, skip_tls: bool = False, debug: bool = False):
        self.skip_tls = skip_tls
        self.debug = debug
        
        if debug:
            logging.getLogger().setLevel(logging.DEBUG)
            logger.debug("Debug mode enabled")
        
        # Initialize components
        self.catalog_manager = CatalogManager(skip_tls=skip_tls, debug=debug)
        self.bundle_processor = BundleProcessor(skip_tls=skip_tls, debug=debug)
        self.yaml_generator = YAMLGenerator()
        self.helm_generator = HelmGenerator()
        self.help_manager = HelpManager()
    
    def query_catalogd(self, catalog_name: str = None, openshift_url: str = None, 
                      openshift_token: str = None, package: str = None, 
                      channel: str = None, version: str = None):
        """Query catalogd service"""
        port_forward_manager = None
        port = None
        
        try:
            # Get catalog name if not provided
            if not catalog_name:
                catalogs = self.catalog_manager.list_catalogs()
                if not catalogs:
                    print("No ClusterCatalogs found in this cluster.")
                    return
                
                print("\nAvailable ClusterCatalogs:")
                for i, catalog in enumerate(catalogs, 1):
                    serving_status = "✓ Serving" if catalog['serving'] else "✗ Not Serving"
                    print(f"{i}. {catalog['name']} ({serving_status})")
                
                while True:
                    try:
                        choice = input(f"\nSelect a catalog (1-{len(catalogs)}): ").strip()
                        if choice.isdigit() and 1 <= int(choice) <= len(catalogs):
                            catalog_name = catalogs[int(choice) - 1]['name']
                            break
                        else:
                            print(f"Please enter a number between 1 and {len(catalogs)}")
                    except KeyboardInterrupt:
                        print("\nOperation cancelled.")
                        return
                    except EOFError:
                        print("\nOperation cancelled.")
                        return
            
            # Start port-forward if using catalogd service
            if not openshift_url:
                print(f"Starting port-forward to catalogd service...", file=sys.stderr)
                port_forward_manager, port, is_https = self.catalog_manager.port_forward_catalogd()
                print(f"Port-forward established on port {port}", file=sys.stderr)
            
            # Query packages
            if not package:
                packages = self.catalog_manager.fetch_catalog_packages(catalog_name, port_forward_manager, openshift_url, openshift_token)
                result = {
                    "catalog": catalog_name,
                    "type": "packages",
                    "data": packages,
                    "total": len(packages)
                }
                print(json.dumps(result, indent=2))
                return
            
            # Query channels
            if not channel:
                channels = self.catalog_manager.fetch_package_channels(catalog_name, package, port_forward_manager, openshift_url, openshift_token)
                result = {
                    "catalog": catalog_name,
                    "package": package,
                    "type": "channels",
                    "data": channels,
                    "total": len(channels)
                }
                print(json.dumps(result, indent=2))
                return
            
            # Query versions
            if not version:
                versions = self.catalog_manager.fetch_channel_versions(catalog_name, package, channel, port_forward_manager, openshift_url, openshift_token)
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
            metadata = self.catalog_manager.fetch_version_metadata(catalog_name, package, channel, version, port_forward_manager, openshift_url, openshift_token)
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
            print(f"Error: {e}")
        finally:
            if port_forward_manager:
                print("Stopping port-forward...", file=sys.stderr)
                port_forward_manager.stop()
    
    def extract_bundle(self, image: str, namespace: str = "default", registry_token: str = None,
                      helm: bool = False, output_dir: str = None, least_privileges: bool = False,
                      stdout: bool = False):
        """Extract bundle metadata and generate RBAC resources"""
        try:
            # Check if image is an index image
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
            
            # Generate RBAC resources
            if helm:
                print("Generating Helm values...")
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
                    helm_file = output_path / f"values-{metadata.get('name', 'operator')}-{timestamp}.yaml"
                    
                    with open(helm_file, 'w') as f:
                        f.write(helm_values)
                    
                    print(f"Helm values saved to: {helm_file}")
            else:
                print("Generating YAML manifests...")
                manifests = self.yaml_generator.generate_yaml_manifests(metadata, namespace, least_privileges)
                
                if stdout or not output_dir:
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
                    hex_suffix = hex(hash(image))[-8:]
                    
                    for manifest_name, manifest_content in manifests.items():
                        filename = f"{manifest_name}-{timestamp}-{hex_suffix}.yaml"
                        file_path = output_path / filename
                        
                        with open(file_path, 'w') as f:
                            f.write(manifest_content)
                        
                        print(f"{manifest_name} saved to: {file_path}")
        
        except Exception as e:
            logger.error(f"Error extracting bundle: {e}")
            print(f"Error: {e}")
    
    def generate_config(self, output_dir: str = None, config_type: str = None):
        """Generate configuration file template"""
        try:
            config_template = {
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
                    "namespace": "default",
                    "registry_token": "",
                    "helm": False,
                    "output": "./output",
                    "least_privileges": False
                }
            }
            
            # Convert to YAML format manually to preserve comments
            config_content = "# RBAC Manager Configuration\n"
            config_content += "# This file contains default values for RBAC Manager commands\n\n"
            config_content += "# Global settings\n"
            config_content += "skip_tls: false\n"
            config_content += "debug: false\n\n"
            config_content += "# Catalogd settings\n"
            config_content += "catalogd:\n"
            config_content += "  catalog_name: \"\"\n"
            config_content += "  openshift_url: \"\"\n"
            config_content += "  openshift_token: \"\"\n"
            config_content += "  package: \"\"\n"
            config_content += "  channel: \"\"\n"
            config_content += "  version: \"\"\n\n"
            config_content += "# OPM settings\n"
            config_content += "opm:\n"
            config_content += "  image: \"\"\n"
            config_content += "  namespace: \"default\"\n"
            config_content += "  registry_token: \"\"\n"
            config_content += "  helm: false\n"
            config_content += "  output: \"./output\"\n"
            config_content += "  least_privileges: false\n"
            
            if output_dir:
                output_path = Path(output_dir)
                output_path.mkdir(parents=True, exist_ok=True)
                config_file = output_path / "rbac-manager-config.yaml"
                
                with open(config_file, 'w') as f:
                    f.write(config_content)
                
                print(f"Configuration template saved to: {config_file}")
            else:
                print("Configuration template:")
                print("=" * 50)
                print(config_content)
        
        except Exception as e:
            logger.error(f"Error generating config: {e}")
            print(f"Error: {e}")
    
    def load_config(self, config_path: str):
        """Load configuration from file"""
        try:
            import yaml
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            return config
        except Exception as e:
            logger.error(f"Error loading config from {config_path}: {e}")
            return {}


def create_argument_parser():
    """Create and configure the argument parser"""
    parser = argparse.ArgumentParser(
        description="RBAC Manager - Operator Bundle Metadata and RBAC Resource Generator",
        add_help=False  # We'll handle help ourselves
    )
    
    # Global flags
    parser.add_argument('--skip-tls', action='store_true', help='Skip TLS verification')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--help', action='store_true', help='Show help')
    parser.add_argument('--examples', action='store_true', help='Show examples')
    
    # Command flags (older version compatibility)
    parser.add_argument('--list-catalogs', action='store_true', help='List available ClusterCatalogs with serving status and age')
    parser.add_argument('--catalogd', action='store_true', help='Query catalogd service')
    parser.add_argument('--opm', action='store_true', help='Extract bundle metadata using opm')
    parser.add_argument('--generate-config', action='store_true', help='Generate configuration template')
    
    # Catalogd flags
    parser.add_argument('--catalog-name', help='Catalog name')
    parser.add_argument('--openshift-url', help='OpenShift cluster URL')
    parser.add_argument('--openshift-token', help='OpenShift token')
    parser.add_argument('--package', help='Package name')
    parser.add_argument('--channel', help='Channel name')
    parser.add_argument('--version', help='Version')
    
    # OPM flags
    parser.add_argument('--image', help='Bundle image URL')
    parser.add_argument('--namespace', help='Target namespace for manifests')
    parser.add_argument('--openshift-namespace', help='Alias for --namespace')
    parser.add_argument('--registry-token', help='Registry authentication token')
    
    # Output flags
    parser.add_argument('--helm', action='store_true', help='Generate Helm values instead of YAML manifests')
    parser.add_argument('--output', help='Output directory for generated files')
    parser.add_argument('--least-privileges', action='store_true', help='Apply least-privilege principles to RBAC rules')
    
    # Configuration flags
    parser.add_argument('--config', help='Path to configuration file')
    
    return parser


def main():
    """Main entry point for the RBAC Manager application"""
    # Handle help command before parsing
    if len(sys.argv) > 1 and sys.argv[1] == 'help':
        help_manager = HelpManager()
        if len(sys.argv) > 2:
            help_manager.show_command_help(sys.argv[2])
        else:
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
    if args.help or (command_count == 0 and not args.examples):
        help_manager = HelpManager()
        help_manager.show_help()
        return
    
    if args.examples:
        help_manager = HelpManager()
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
            exit_code = rbac_manager.catalog_manager.display_catalogs_enhanced()
            sys.exit(exit_code)
        
        elif args.catalogd:
            # Apply config overrides for catalogd
            catalog_name = args.catalog_name
            openshift_url = args.openshift_url
            openshift_token = args.openshift_token
            package = args.package
            channel = args.channel
            version = args.version
            
            if config and 'catalogd' in config:
                catalogd_config = config['catalogd']
                catalog_name = catalog_name or catalogd_config.get('catalog_name')
                openshift_url = openshift_url or catalogd_config.get('openshift_url')
                openshift_token = openshift_token or catalogd_config.get('openshift_token')
                package = package or catalogd_config.get('package')
                channel = channel or catalogd_config.get('channel')
                version = version or catalogd_config.get('version')
            
            rbac_manager.query_catalogd(
                catalog_name=catalog_name,
                openshift_url=openshift_url,
                openshift_token=openshift_token,
                package=package,
                channel=channel,
                version=version
            )
        
        elif args.opm:
            # Apply config overrides for opm
            image = args.image
            namespace = args.namespace or "default"
            registry_token = args.registry_token
            helm = args.helm
            output_dir = args.output
            least_privileges = args.least_privileges
            
            if config and 'opm' in config:
                opm_config = config['opm']
                image = image or opm_config.get('image')
                namespace = namespace or opm_config.get('namespace', 'default')
                registry_token = registry_token or opm_config.get('registry_token')
                helm = helm or opm_config.get('helm', False)
                output_dir = output_dir or opm_config.get('output')
                least_privileges = least_privileges or opm_config.get('least_privileges', False)
            
            if not image:
                print("Error: --image is required for OPM operations")
                sys.exit(1)
            
            # Determine if output should go to stdout (for piping)
            stdout = output_dir is None
            
            rbac_manager.extract_bundle(
                image=image,
                namespace=namespace,
                registry_token=registry_token,
                helm=helm,
                output_dir=output_dir,
                least_privileges=least_privileges,
                stdout=stdout
            )
        
        elif args.generate_config:
            output_dir = args.output
            rbac_manager.generate_config(output_dir=output_dir)
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
