#!/usr/bin/env python3
"""
Unified RBAC Manager for OLM Operators.

Fixed version addressing:
1. Code duplication (DRY principle)
2. RBAC resource naming consistency
"""

import argparse
import logging
import sys

# Import our library modules
from libs.openshift_auth import OpenShiftAuth
from libs.rbac_manager_core import RBACManager
from libs.port_forward_utils import PortForwardManager
from libs.logging_utils import setup_logging
from libs.config_utils import ConfigManager, generate_sample_config_file


def main():
    """Main function with unified CLI interface."""
    
    # First, create a minimal parser to check for --config and --generate-config
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument('--config', 
                           help='Path to configuration file (default: search standard locations)')
    pre_parser.add_argument('--generate-config', 
                           help='Generate sample configuration file at specified path and exit')
    
    pre_args, remaining_args = pre_parser.parse_known_args()
    
    # Handle config file generation first
    if pre_args.generate_config:
        try:
            config_path = generate_sample_config_file(pre_args.generate_config)
            print(f"✅ Sample configuration file created: {config_path}")
            print(f"\n📝 Edit the file to set your default values:")
            print(f"   nano {config_path}")
            print("\n💡 The configuration file supports environment variable expansion using ${VAR_NAME}")
            return 0
        except Exception as e:
            print(f"❌ Error creating config file: {e}")
            return 1
    
    # Load configuration
    config_manager = ConfigManager(custom_config_path=pre_args.config)
    config_data = config_manager.load_config()
    config_defaults = config_manager.get_defaults_for_argparse()
    
    # Create the main parser
    parser = argparse.ArgumentParser(
        description='Unified RBAC Manager for OLM Operators (Port-Forward Version)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Print RBAC YAML to stdout (default)
  %(prog)s --catalogd --package prometheus
  
  # Deploy RBAC directly to cluster
  %(prog)s --catalogd --package cert-manager --deploy
  
  # Save RBAC files to custom directory
  %(prog)s --catalogd --package jaeger --output ./my-rbac-files
  
  # Use explicit cluster URL (if auto-discovery fails)
  %(prog)s --catalogd --openshift-url https://api.cluster.com:6443 --package prometheus
  
  # Extract via OPM image (print to stdout)
  %(prog)s --opm --image quay.io/operatorhubio/catalog:latest --package prometheus
  
  # List all packages - auto-discovers cluster URL
  %(prog)s --catalogd --list-packages
  
  # Using service account token - auto-discovers cluster URL
  %(prog)s --catalogd --openshift-token sha256~abc123... --package grafana --deploy

Configuration File:
  The tool supports configuration files to set default values for frequently used options.
  Default locations (in order): ./rbac-manager.yaml, ~/.rbac-manager.yaml, ~/.config/rbac-manager.yaml
  
  Generate a sample config: %(prog)s --generate-config ~/.rbac-manager.yaml
  Use custom config file: %(prog)s --config /path/to/config.yaml --catalogd --package prometheus
        """
    )
    
    # Query method selection (mutually exclusive)
    query_group = parser.add_mutually_exclusive_group(required=True)
    query_group.add_argument('--opm', action='store_true',
                            help='Use OPM image queries')
    query_group.add_argument('--catalogd', action='store_true',
                            help='Use ClusterCatalog API queries via port-forward')
    
    # OPM-specific options
    parser.add_argument('--image', 
                       help='Catalog image reference (required for --opm)')
    
    # ClusterCatalog API options (port-forward approach)
    parser.add_argument('--openshift-url', 
                       help='OpenShift API URL (optional, will auto-discover from kubeconfig if not provided)')
    parser.add_argument('--openshift-token',
                       help='OpenShift authentication token (or set OPENSHIFT_TOKEN env var)')
    parser.add_argument('--catalog-name', default='operatorhubio',
                       help='Catalog name (default: operatorhubio)')
    
    # Port-forward configuration
    parser.add_argument('--local-port', type=int, default=8080,
                       help='Local port for port-forward (default: 8080)')
    parser.add_argument('--catalogd-namespace', default='openshift-catalogd',
                       help='Namespace containing catalogd service (default: openshift-catalogd)')
    parser.add_argument('--catalogd-service', default='catalogd-service',
                       help='Name of catalogd service (default: catalogd-service)')
    
    # Common options
    parser.add_argument('--package',
                       help='Specific package name to query')
    parser.add_argument('--insecure', action='store_true',
                       help='Skip TLS certificate verification')
    
    # Output mode options (mutually exclusive)
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument('--output', metavar='DIR',
                             help='Save YAML files to specified directory')
    output_group.add_argument('--deploy', action='store_true',
                             help='Deploy RBAC resources directly to cluster using oc apply')
    
    # Action options
    parser.add_argument('--list-packages', action='store_true',
                       help='List all available packages and exit')
    parser.add_argument('--all-namespaces-packages', action='store_true',
                       help='List packages supporting AllNamespaces install mode')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    # Configuration options
    parser.add_argument('--config',
                       help='Path to configuration file (default: search standard locations)')
    parser.add_argument('--generate-config',
                       help='Generate sample configuration file at specified path and exit')
    
    # Apply configuration defaults (CLI args will override these)
    if config_defaults:
        parser.set_defaults(**config_defaults)
        logging.debug(f"Applied config defaults: {list(config_defaults.keys())}")
    
    args = parser.parse_args()
    
    # Setup logging first
    setup_logging(verbose=args.verbose)
    
    # Show config file info if loaded
    config_info = config_manager.get_config_info()
    if config_info['has_config']:
        logging.info(f"📁 Using configuration file: {config_info['config_file']}")
        if config_defaults:
            logging.debug(f"Config defaults applied: {list(config_defaults.keys())}")
    
    # Validate arguments
    if args.opm and not args.image:
        parser.error("--image is required when using --opm")
    
    
    try:
        # Initialize RBAC manager
        manager = RBACManager(
            output_dir=args.output, 
            deploy=args.deploy, 
            insecure=args.insecure
        )
        
        # Setup query method
        if args.opm:
            # OPM-based queries
            if args.list_packages:
                packages = manager.get_all_packages_via_opm(args.image)
                print(f"Found {len(packages)} packages:")
                for package in packages:
                    print(f"  - {package}")
                return 0
            
            # Extract RBAC via OPM for specific package
            if args.package:
                rbac_resources = manager.extract_rbac_via_opm(args.image, args.package)
                if rbac_resources:
                    manager.process_package_rbac(args.package, rbac_resources)
                else:
                    logging.error(f"No RBAC permissions found for package '{args.package}'")
                    return 1
            else:
                # Extract RBAC for all packages
                packages = manager.get_all_packages_via_opm(args.image)
                processed_count = 0
                for package in packages:
                    try:
                        rbac_resources = manager.extract_rbac_via_opm(args.image, package)
                        if rbac_resources:
                            manager.process_package_rbac(package, rbac_resources)
                            processed_count += 1
                    except Exception as e:
                        logging.warning(f"Skipping package {package}: {e}")
                logging.info(f"Processed RBAC for {processed_count}/{len(packages)} packages")
            
        elif args.catalogd:
            # ClusterCatalog API-based queries with port-forward
            logging.info("🔐 Authenticating with OpenShift...")
            openshift_auth = OpenShiftAuth(
                api_url=args.openshift_url,  # None is OK, will auto-discover
                token=args.openshift_token,
                insecure=args.insecure,
                verify_catalogd_permissions=True
            )
            openshift_auth.login()
            
            # Setup port-forward using context manager
            logging.info("🔗 Setting up port-forward to catalogd service...")
            with PortForwardManager(
                namespace=args.catalogd_namespace,
                service=args.catalogd_service,
                local_port=args.local_port
            ) as catalog_api_url:
                # Setup catalog API with the port-forward URL
                manager.set_catalog_api_url(catalog_api_url)
                
                if args.list_packages:
                    packages = manager.get_all_packages_via_catalogd(args.catalog_name)
                    print(f"Found {len(packages)} packages:")
                    for package in packages:
                        print(f"  - {package}")
                    return 0
                
                if args.all_namespaces_packages:
                    packages = manager.catalog_lib.get_packages_with_all_namespaces(args.catalog_name)
                    print(f"Packages supporting AllNamespaces (no webhooks):")
                    for package in packages:
                        print(f"  - {package}")
                    return 0
                
                # Extract RBAC via ClusterCatalog API for specific package
                if args.package:
                    rbac_resources = manager.extract_rbac_via_catalogd(args.package, args.catalog_name)
                    if rbac_resources:
                        manager.process_package_rbac(args.package, rbac_resources)
                    else:
                        logging.error(f"No RBAC permissions found for package '{args.package}'")
                        return 1
                else:
                    # Extract RBAC for all packages
                    packages = manager.get_all_packages_via_catalogd(args.catalog_name)
                    processed_count = 0
                    for package in packages:
                        try:
                            rbac_resources = manager.extract_rbac_via_catalogd(package, args.catalog_name)
                            if rbac_resources:
                                manager.process_package_rbac(package, rbac_resources)
                                processed_count += 1
                        except Exception as e:
                            logging.warning(f"Skipping package {package}: {e}")
                    logging.info(f"Processed RBAC for {processed_count}/{len(packages)} packages")
        
        # Final completion message based on output mode
        if manager.deploy:
            logging.info("🎉 RBAC extraction and deployment complete!")
        elif manager.output_dir:
            logging.info(f"🎉 RBAC extraction complete. Files saved to: {manager.output_dir}")
        else:
            logging.info("🎉 RBAC extraction complete. YAML output printed above.")
        return 0
        
    except KeyboardInterrupt:
        logging.info("Interrupted by user")
        return 1
    except Exception as e:
        logging.error(f"Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
