"""
Main RBAC Manager Application Class.

This module contains the main application orchestration logic following the 
Application class pattern. It coordinates between different layers and manages
the overall workflow.
"""

import logging
import sys
from typing import Optional
import argparse

from .config_utils import CLIInterface, ConfigManager, generate_sample_config_file
from .core_utils import setup_logging, PortForwardManager
from .catalog_query import CatalogAPIQueryLib, CatalogSelectionUI
from .openshift_auth import OpenShiftAuth
from .rbac_manager_core import RBACManager


class RBACManagerApplication:
    """
    Main application class that orchestrates the RBAC Manager workflow.
    
    This class follows the Application pattern, coordinating between different
    layers and managing the overall application lifecycle.
    """
    
    def __init__(self):
        """Initialize the application."""
        self.cli_interface = CLIInterface()
        self.catalog_ui = CatalogSelectionUI()
        self.config_manager: Optional[ConfigManager] = None
        self.rbac_manager: Optional[RBACManager] = None
        self.args: Optional[argparse.Namespace] = None
    
    def run(self) -> int:
        """
        Main application entry point.
        
        Returns:
            Exit code (0 for success, non-zero for error)
        """
        try:
            # Phase 1: Handle configuration file generation if requested
            exit_code = self._handle_config_generation()
            if exit_code is not None:
                return exit_code
            
            # Phase 2: Setup configuration and CLI
            self._setup_configuration_and_cli()
            
            # Phase 3: Setup logging and validate arguments
            self._setup_logging_and_validation()
            
            # Phase 4: Initialize core components
            self._initialize_core_components()
            
            # Phase 5: Execute requested workflow
            return self._execute_workflow()
            
        except KeyboardInterrupt:
            logging.info("Interrupted by user")
            return 1
        except Exception as e:
            logging.error(f"Error: {e}")
            return 1
    
    def _handle_config_generation(self) -> Optional[int]:
        """
        Handle configuration file generation if requested.
        
        Returns:
            Exit code if config generation was requested, None otherwise
        """
        # Parse only config-related arguments first
        pre_parser = argparse.ArgumentParser(add_help=False)
        pre_parser.add_argument('--config')
        pre_parser.add_argument('--generate-config')
        pre_args, _ = pre_parser.parse_known_args()
        
        if pre_args.generate_config:
            try:
                config_path = generate_sample_config_file(pre_args.generate_config)
                print(f"Sample configuration file created: {config_path}")
                print(f"\nEdit the file to set your default values:")
                print(f"   nano {config_path}")
                print("\nNote: The configuration file supports environment variable expansion using ${VAR_NAME}")
                return 0
            except Exception as e:
                print(f"Error creating config file: {e}")
                return 1
        
        # Store for later use
        self.config_manager = self.cli_interface.setup_config_manager(pre_args.config)
        return None
    
    def _setup_configuration_and_cli(self) -> None:
        """Setup configuration manager and CLI interface."""
        if not self.config_manager:
            self.config_manager = self.cli_interface.setup_config_manager()
        
        # Load configuration and setup CLI parser
        config_data = self.config_manager.load_config()
        config_defaults = self.config_manager.get_defaults_for_argparse()
        
        # Create main parser and parse arguments
        parser = self.cli_interface.create_argument_parser(config_defaults)
        self.args = parser.parse_args()
    
    def _setup_logging_and_validation(self) -> None:
        """Setup logging and validate arguments."""
        setup_logging(verbose=self.args.verbose)
        
        # Show config file info if loaded
        config_info = self.config_manager.get_config_info()
        if config_info['has_config']:
            logging.info(f"Using configuration file: {config_info['config_file']}")
            if config_info.get('config_defaults'):
                logging.debug(f"Config defaults applied: {list(config_info['config_defaults'].keys())}")
        
        # Validate arguments
        self.cli_interface.validate_arguments(self.args)
    
    def _initialize_core_components(self) -> None:
        """Initialize core application components."""
        self.rbac_manager = RBACManager(
            output_dir=self.args.output,
            deploy=self.args.deploy,
            insecure=self.args.insecure
        )
    
    def _execute_workflow(self) -> int:
        """
        Execute the requested workflow based on arguments.
        
        Returns:
            Exit code
        """
        if self.args.opm:
            return self._execute_opm_workflow()
        elif self.args.catalogd:
            return self._execute_catalogd_workflow()
        else:
            logging.error("No query method specified")
            return 1
    
    def _execute_opm_workflow(self) -> int:
        """Execute OPM-based workflow."""
        if self.args.list_packages:
            packages = self.rbac_manager.get_all_packages_via_opm(self.args.image)
            print(f"Found {len(packages)} packages:")
            for package in packages:
                print(f"  - {package}")
            return 0
        
        # Extract RBAC via OPM for specific package
        if self.args.package:
            rbac_resources = self.rbac_manager.extract_rbac_via_opm(self.args.image, self.args.package)
            if rbac_resources:
                self.rbac_manager.process_package_rbac(self.args.package, rbac_resources)
            else:
                logging.error(f"No RBAC permissions found for package '{self.args.package}'")
                return 1
        else:
            # Extract RBAC for all packages
            packages = self.rbac_manager.get_all_packages_via_opm(self.args.image)
            processed_count = 0
            for package in packages:
                try:
                    rbac_resources = self.rbac_manager.extract_rbac_via_opm(self.args.image, package)
                    if rbac_resources:
                        self.rbac_manager.process_package_rbac(package, rbac_resources)
                        processed_count += 1
                except Exception as e:
                    logging.warning(f"Skipping package {package}: {e}")
            logging.info(f"Processed RBAC for {processed_count}/{len(packages)} packages")
        
        self._display_completion_message()
        return 0
    
    def _execute_catalogd_workflow(self) -> int:
        """Execute ClusterCatalog API-based workflow."""
        # Authenticate with OpenShift
        logging.info("Authenticating with OpenShift...")
        openshift_auth = OpenShiftAuth(
            api_url=self.args.openshift_url,
            token=self.args.openshift_token,
            insecure=self.args.insecure,
            verify_catalogd_permissions=True
        )
        openshift_auth.login()
        
        # Setup port-forward and execute operations
        logging.info("Setting up port-forward to catalogd service...")
        with PortForwardManager(
            namespace=self.args.catalogd_namespace,
            service=self.args.catalogd_service,
            local_port=self.args.local_port
        ) as catalog_api_url:
            self.rbac_manager.set_catalog_api_url(catalog_api_url)
            return self._execute_catalogd_operations()
    
    def _execute_catalogd_operations(self) -> int:
        """Execute specific CatalogD operations."""
        if self.args.list_catalogs:
            return self._list_catalogs()
        elif self.args.list_packages:
            return self._list_packages()
        elif self.args.all_namespaces_packages:
            return self._list_all_namespaces_packages()
        else:
            return self._extract_rbac()
    
    def _list_catalogs(self) -> int:
        """List available ClusterCatalogs."""
        try:
            catalogs = CatalogAPIQueryLib.get_available_clustercatalogs()
            
            if not catalogs:
                print("No ClusterCatalogs found in this cluster.")
                return 1
            
            print(f"\nAvailable ClusterCatalogs:")
            print("-" * 80)
            print(f"{'Name':<40} {'Serving':<8} {'Last Unpacked':<25} {'Age':<20}")
            print("-" * 80)
            
            for catalog in catalogs:
                serving_status = "True" if catalog['serving'] else "False"
                print(f"{catalog['name']:<40} {serving_status:<8} {catalog['lastUnpacked']:<25} {catalog['age']:<20}")
            
            print("-" * 80)
            print(f"\nTotal: {len(catalogs)} ClusterCatalogs")
            print("Note: Only serving catalogs can be reliably queried for packages.")
            
            return 0
        except Exception as e:
            print(f"Error listing ClusterCatalogs: {e}")
            return 1
    
    def _list_packages(self) -> int:
        """List packages from selected catalog."""
        catalog_to_query = self.catalog_ui.determine_catalog_to_use(self.args, "list-packages")
        logging.info(f"Listing packages from catalog: {catalog_to_query}")
        
        packages = self.rbac_manager.get_all_packages_via_catalogd(catalog_to_query)
        print(f"Found {len(packages)} packages in '{catalog_to_query}':")
        for package in packages:
            print(f"  - {package}")
        return 0
    
    def _list_all_namespaces_packages(self) -> int:
        """List packages supporting AllNamespaces install mode."""
        catalog_to_query = self.catalog_ui.determine_catalog_to_use(self.args, "all-namespaces-packages")
        logging.info(f"Querying AllNamespaces packages from catalog: {catalog_to_query}")
        
        packages = self.rbac_manager.catalog_lib.get_packages_with_all_namespaces(catalog_to_query)
        print(f"Packages supporting AllNamespaces (no webhooks) in '{catalog_to_query}':")
        for package in packages:
            print(f"  - {package}")
        return 0
    
    def _extract_rbac(self) -> int:
        """Extract RBAC for packages."""
        catalog_to_use = self.catalog_ui.determine_catalog_to_use(self.args, "package extraction")
        
        if self.args.package:
            # Extract RBAC for specific package
            print(f"Extracting RBAC from catalog: {catalog_to_use}")
            rbac_resources = self.rbac_manager.extract_rbac_via_catalogd(self.args.package, catalog_to_use)
            if rbac_resources:
                self.rbac_manager.process_package_rbac(self.args.package, rbac_resources)
                self._display_completion_message()
                return 0
            else:
                logging.error(f"No RBAC permissions found for package '{self.args.package}'")
                return 1
        else:
            # Extract RBAC for all packages
            print(f"Extracting RBAC for all packages from catalog: {catalog_to_use}")
            packages = self.rbac_manager.get_all_packages_via_catalogd(catalog_to_use)
            processed_count = 0
            for package in packages:
                try:
                    rbac_resources = self.rbac_manager.extract_rbac_via_catalogd(package, catalog_to_use)
                    if rbac_resources:
                        self.rbac_manager.process_package_rbac(package, rbac_resources)
                        processed_count += 1
                except Exception as e:
                    logging.warning(f"Skipping package {package}: {e}")
            
            logging.info(f"Processed RBAC for {processed_count}/{len(packages)} packages")
            self._display_completion_message()
            return 0
    
    def _display_completion_message(self) -> None:
        """Display appropriate completion message."""
        if self.rbac_manager.deploy:
            logging.info("RBAC extraction and deployment complete.")
        elif self.rbac_manager.output_dir:
            logging.info(f"RBAC extraction complete. Files saved to: {self.rbac_manager.output_dir}")
        else:
            logging.info("RBAC extraction complete. YAML output printed above.")
