"""
Main RBAC Manager Application Class.

This module contains the main application orchestration logic following the 
Application class pattern. It coordinates between different layers and manages
the overall workflow.
"""

import logging
import os
import sys
from typing import Optional, Dict, List, Any, Union
import argparse
from pathlib import Path

from .cli_interface import CLIInterface
from .config_manager import ConfigManager, generate_sample_config_file
from .config_manager import setup_logging
from .core_utils import PortForwardManager, OpenShiftAuth, list_openshift_clustercatalogs, create_flow_style_yaml_dumper
from .catalog_query import CatalogAPIQueryLib, CatalogSelectionUI
from .opm_query import OPMQueryLib
from .rbac_converter import RBACConverter, RBACConverterError, RBACRuleBuilder
# RBACRuleBuilder is now part of rbac_converter.py
from .data_models import BundleData, CSVManifest, RBACData, RBACResources, ExecutionContext
from .data_models import DiscoveryResult
from .opm_query import create_opm_discoverer, discover_bundles_via_opm, DiscoveryMethod
from .catalog_query import create_catalogd_discoverer, discover_bundles_via_catalogd


class RBACManagerApplication:
    """
    Main application class that orchestrates the RBAC Manager workflow.
    
    This class follows the Application pattern with Dependency Injection,
    coordinating between different layers and managing the overall application lifecycle.
    Dependencies can be injected for improved testability and modularity.
    """
    
    def __init__(self, 
                 cli_interface: Optional[CLIInterface] = None,
                 catalog_ui: Optional[CatalogSelectionUI] = None,
                 config_manager: Optional[ConfigManager] = None,
                 rule_builder: Optional[RBACRuleBuilder] = None,
                 opm_lib: Optional[OPMQueryLib] = None,
                 catalog_lib: Optional[CatalogAPIQueryLib] = None,
):
        """
        Initialize the application with optional dependency injection.
        
        Args:
            cli_interface: CLI interface for argument parsing (auto-created if None)
            catalog_ui: Catalog selection UI (auto-created if None)  
            config_manager: Configuration manager (auto-created if None)
            rule_builder: RBAC rule builder (auto-created if None)
            opm_lib: OPM query library (auto-created if None)
            catalog_lib: Catalog API query library (auto-created if None)
        """
        # Inject dependencies or create defaults
        self.cli_interface = cli_interface or self._create_default_cli_interface()
        self.catalog_ui = catalog_ui or self._create_default_catalog_ui()
        self.config_manager = config_manager
        self.args: Optional[argparse.Namespace] = None  # Legacy - will be replaced by context
        self.context: Optional[ExecutionContext] = None  # Clean, typed execution context
        
        # Core RBAC processing components (formerly in RBACManager)
        self.output_dir = None
        self.insecure = False
        self.rule_builder = rule_builder  # Will be created/injected during initialization
        self.opm_lib = opm_lib  # Will be created/injected during initialization
        self.catalog_lib = catalog_lib  # Will be created/injected during initialization
    
    # Factory methods for default dependency creation
    def _create_default_cli_interface(self) -> CLIInterface:
        """Create default CLI interface."""
        return CLIInterface()
    
    def _create_default_catalog_ui(self) -> CatalogSelectionUI:
        """Create default catalog UI."""
        return CatalogSelectionUI()
    
    def _create_default_rule_builder(self) -> RBACRuleBuilder:
        """Create default RBAC rule builder."""
        return RBACRuleBuilder(logging.getLogger(__name__))
    
    def _create_default_opm_lib(self, insecure: bool = False) -> OPMQueryLib:
        """Create default OPM query library."""
        return OPMQueryLib(insecure=insecure)
    
    def _create_default_catalog_lib(self, api_url: str, insecure: bool = False) -> CatalogAPIQueryLib:
        """Create default catalog API query library."""
        return CatalogAPIQueryLib(api_url, insecure=insecure)
    
    
    def _get_target_namespace(self) -> str:
        """
        Get the target namespace for RBAC resources.
        
        Returns:
            Namespace from --openshift-namespace or auto-discovered namespace
        """
        # Check if user provided --openshift-namespace
        if self.context.openshift_namespace:
            namespace = self.context.openshift_namespace
            logging.info(f"Using user-specified OpenShift namespace: {namespace}")
            return namespace
        
        # Auto-discover namespace from OpenShift context
        namespace = self._discover_openshift_namespace()
        logging.info(f"Using auto-discovered OpenShift namespace: {namespace}")
        return namespace
    
    def _discover_openshift_namespace(self) -> str:
        """
        Discover the current OpenShift namespace from cluster context.
        
        Returns:
            Current namespace or 'default' if not discoverable
        """
        try:
            import subprocess
            
            # Try to get current namespace from oc context
            result = subprocess.run(['oc', 'project', '-q'], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0 and result.stdout.strip():
                namespace = result.stdout.strip()
                logging.debug(f"Discovered current OpenShift namespace: {namespace}")
                return namespace
                
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError) as e:
            logging.debug(f"Could not discover OpenShift namespace from 'oc project': {e}")
        
        # Fallback: try kubectl context
        try:
            import subprocess
            
            result = subprocess.run(['kubectl', 'config', 'view', '--minify', '--output', 'jsonpath={..namespace}'], 
                                  capture_output=True, text=True, timeout=5)
                                  
            if result.returncode == 0 and result.stdout.strip():
                namespace = result.stdout.strip()
                logging.debug(f"Discovered current Kubernetes namespace: {namespace}")
                return namespace
                
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError) as e:
            logging.debug(f"Could not discover Kubernetes namespace from kubectl: {e}")
        
        logging.debug("Could not auto-discover namespace, using 'default'")
        return 'default'

    def _extract_bundle_data_for_helm(self, bundle_image: str, registry_token: str = None) -> tuple:
        """Extract bundle data for Helm values generation."""
        try:
            from libs.bundle_processor import BundleProcessor
            
            processor = BundleProcessor()
            bundle_data = processor.render_bundle_image(bundle_image)
            
            # bundle_data is now a BundleData dataclass, access documents attribute
            manifests = bundle_data.documents if hasattr(bundle_data, 'documents') else []
            
            csv_data = None
            rbac_data = None
            
            # Find CSV in manifests
            for manifest in manifests:
                if isinstance(manifest, dict) and manifest.get('kind') == 'ClusterServiceVersion':
                    csv_data = manifest
                    logging.debug(f"Found CSV: {csv_data.get('metadata', {}).get('name', 'unknown') if isinstance(csv_data, dict) else getattr(csv_data, 'name', 'unknown')}")
                    # Extract RBAC from CSV
                    rbac_data = processor.extract_rbac_from_csv(csv_data)
                    logging.debug(f"Extracted RBAC data: {rbac_data is not None}")
                    if rbac_data:
                        logging.debug(f"RBAC keys: {list(rbac_data.keys()) if isinstance(rbac_data, dict) else type(rbac_data)}")
                    break
            
            if csv_data is None:
                logging.error("No ClusterServiceVersion found in bundle manifests")
            if rbac_data is None:
                logging.error("No RBAC data extracted from CSV")
            
            return csv_data, rbac_data, bundle_data
            
        except Exception as e:
            logging.error(f"Failed to extract bundle data: {e}")
            import traceback
            logging.debug(f"Full traceback: {traceback.format_exc()}")
            return None, None, None
    
    # _generate_helm_values_from_data method removed - functionality consolidated into _handle_output
    
    def _save_rbac_to_files(self, rbac_resources: Union[RBACResources, Dict[str, Any]], output_dir: str) -> None:
        """Save RBAC resources to YAML files in the specified directory."""
        import os
        import yaml
        from pathlib import Path
        import datetime
        import secrets
        
        # Create output directory if it doesn't exist
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Generate unique identifier to prevent file overwrites
        timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        random_suffix = secrets.token_hex(4)  # 8-character hex string
        unique_id = f"{timestamp}-{random_suffix}"
        
        logging.info(f"Saving RBAC resources to {output_dir} with unique ID: {unique_id}")
        
        # Define file names for each resource type with unique identifier
        file_mapping = {
            'service_accounts': f'service-accounts-{unique_id}.yaml',
            'roles': f'roles-{unique_id}.yaml', 
            'cluster_roles': f'cluster-roles-{unique_id}.yaml',
            'role_bindings': f'role-bindings-{unique_id}.yaml',
            'cluster_role_bindings': f'cluster-role-bindings-{unique_id}.yaml'
        }
        
        # Convert to dict if needed for backward compatibility
        from dataclasses import is_dataclass, asdict
        if is_dataclass(rbac_resources):
            resources_dict = asdict(rbac_resources)
        elif isinstance(rbac_resources, RBACResources):
            resources_dict = rbac_resources.to_dict()  # Custom logic for mixed resource types
        else:
            resources_dict = rbac_resources
            
        # Save each resource type to separate files
        for resource_type, filename in file_mapping.items():
            resources = resources_dict.get(resource_type, [])
            if resources:
                file_path = output_path / filename
                with open(file_path, 'w') as f:
                    f.write("---\n")
                    f.write("# Generated RBAC Resources\n")
                    f.write("# Generated by RBAC Manager Tool\n")
                    f.write(f"# Resource type: {resource_type}\n")
                    f.write("---\n")
                    
                    # Use flow-style dumper for RBAC rules
                    FlowStyleDumper = create_flow_style_yaml_dumper()
                    for resource in resources:
                        f.write(yaml.dump(resource, Dumper=FlowStyleDumper, default_flow_style=False, indent=2))
                        f.write("---\n")
                
                logging.info(f"Saved {len(resources)} {resource_type} to {filename}")

    def _print_rbac_resources(self, rbac_resources: Union[RBACResources, Dict[str, Any]]) -> None:
        """Print RBAC resources as YAML to stdout."""
        import yaml
        
        if not rbac_resources:
            print("No RBAC resources found.")
            return
        
        # Convert to dict if needed for backward compatibility
        from dataclasses import is_dataclass, asdict
        if is_dataclass(rbac_resources):
            resources_dict = asdict(rbac_resources)
        elif isinstance(rbac_resources, RBACResources):
            resources_dict = rbac_resources.to_dict()  # Custom logic for mixed resource types
        else:
            resources_dict = rbac_resources
        
        # Count total resources using the correct field names
        total_resources = 0
        # Map from display names to actual field names in RBACResources
        field_mapping = {
            'serviceAccounts': 'service_accounts',
            'clusterRoles': 'cluster_roles', 
            'roles': 'roles',
            'clusterRoleBindings': 'cluster_role_bindings',
            'roleBindings': 'role_bindings'
        }
        
        for display_name, field_name in field_mapping.items():
            resource_count = len(resources_dict.get(field_name, []))
            total_resources += resource_count
        
        if total_resources == 0:
            print("No Kubernetes resources generated.")
            return
        
        print("---")
        print("# Generated RBAC Resources")
        print("# Generated by RBAC Manager Tool")
        print(f"# Total resources: {total_resources}")
        print("---")
        
        # Print each resource type using correct field names
        resource_count = 0
        # Use flow-style dumper for RBAC rules
        FlowStyleDumper = create_flow_style_yaml_dumper()
        for display_name, field_name in field_mapping.items():
            resources = resources_dict.get(field_name, [])
            for resource in resources:
                if resource_count > 0:
                    print("---")
                print(yaml.dump(resource, Dumper=FlowStyleDumper, default_flow_style=False, indent=2))
                resource_count += 1

    def _display_completion_message(self) -> None:
        """Display appropriate completion message."""
        if hasattr(self.args, 'helm') and self.args.helm:
            logging.info("Helm values.yaml generation complete.")
        elif hasattr(self.args, 'output') and self.args.output:
            logging.info(f"RBAC extraction complete. Files saved to: {self.args.output}")
        else:
            logging.info("RBAC extraction complete. YAML output printed above.")

    def _extract_package_name_from_csv(self, csv_data, bundle_image: str) -> str:
        """Extract package name from CSV data or bundle image."""
        if csv_data and 'metadata' in csv_data:
            return csv_data['metadata'].get('name', 'unknown-operator')
        
        # Fallback: extract from bundle image URL
        try:
            # Extract name from image URL (e.g., quay.io/quay/quay-operator-bundle@sha256:...)
            image_parts = bundle_image.split('/')
            if len(image_parts) >= 2:
                bundle_part = image_parts[-1]  # e.g., quay-operator-bundle@sha256:...
                
                # Handle both : and @ separators
                if '@' in bundle_part:
                    name_part = bundle_part.split('@')[0]  # e.g., quay-operator-bundle
                else:
                    name_part = bundle_part.split(':')[0]  # e.g., quay-operator-bundle
                
                # Remove -bundle suffix if present
                if name_part.endswith('-bundle'):
                    name_part = name_part[:-7]  # e.g., quay-operator
                    
                return name_part
        except Exception as e:
            logging.debug(f"Failed to extract name from bundle image: {e}")
            pass
        
        return 'unknown-operator'
    
    def _get_registry_token(self) -> Optional[str]:
        """
        Get registry token from args, environment variable, or credential discovery.
        
        Returns:
            Registry token if available, None otherwise
        """
        # First check command line arguments
        if hasattr(self.args, 'registry_token') and self.args.registry_token:
            return self.args.registry_token
        
        # Then check environment variable
        registry_token = os.getenv('REGISTRY_TOKEN')
        if registry_token:
            logging.debug("Using registry token from REGISTRY_TOKEN environment variable")
            return registry_token
        
        # Try credential discovery from standard locations
        registry_token = self._discover_registry_credentials()
        if registry_token:
            return registry_token
        
        logging.debug("No registry token found")
        return None
    
    def _discover_registry_credentials(self) -> Optional[str]:
        """
        Discover registry credentials from standard locations.
        
        Returns:
            Registry token/credentials or None if not found
        """
        import json
        import os
        from pathlib import Path
        
        # Standard credential locations in order of preference
        credential_paths = [
            # Docker credentials
            Path.home() / ".docker" / "config.json",
            # Podman credentials  
            Path.home() / ".config" / "containers" / "auth.json",
            # Runtime credentials (XDG spec)
            Path(os.environ.get('XDG_RUNTIME_DIR', '/tmp')) / "containers" / "auth.json"
        ]
        
        for cred_path in credential_paths:
            try:
                if cred_path.exists() and cred_path.is_file():
                    logging.debug(f"Checking credentials at: {cred_path}")
                    with open(cred_path, 'r') as f:
                        cred_data = json.load(f)
                    
                    # Check for registry auths
                    if 'auths' in cred_data and cred_data['auths']:
                        logging.debug(f"Found {len(cred_data['auths'])} registry auth entries in {cred_path}")
                        # For now, signal that credentials are available
                        # The actual auth will be handled by the container runtime (podman/docker)
                        return "discovered"
                    
                    # Check for credential helpers
                    if 'credHelpers' in cred_data and cred_data['credHelpers']:
                        logging.debug(f"Found credential helpers in {cred_path}")
                        return "discovered"
                        
            except (json.JSONDecodeError, PermissionError, IOError) as e:
                logging.debug(f"Could not read credentials from {cred_path}: {e}")
                continue
        
        logging.debug("No registry credentials discovered")
        return None
    
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
            
            # Phase 3: Handle examples display if requested
            exit_code = self._handle_examples_display()
            if exit_code is not None:
                return exit_code
            
            # Phase 4: Setup logging and validate arguments
            self._setup_logging_and_validation()
            
            # Phase 5: Initialize core components
            self._initialize_core_components()
            
            # Phase 6: Execute requested workflow
            return self._execute_workflow()
            
        except KeyboardInterrupt:
            logging.info("Interrupted by user")
            return 1
        except Exception as e:
            logging.error(f"Error: {e}")
            return 1
    
    def _handle_examples_display(self) -> Optional[int]:
        """
        Handle examples display if requested.
        
        Returns:
            Exit code if examples were requested, None otherwise
        """
        if self._should_show_examples(self.context):
            # Show examples based on operation mode
            operation_mode = self.context.get_operation_mode()
            if operation_mode == "opm":
                self._show_opm_examples()
            elif operation_mode == "catalogd":
                self._show_catalogd_examples()
            elif operation_mode == "list_catalogs":
                self._show_list_catalogs_examples()
            else:
                self._show_all_examples()
            return 0
        return None
    
    def _show_opm_examples(self) -> None:
        """Show OPM-specific examples."""
        print("""
OPM Examples - RBAC extraction from operator bundle images

Basic RBAC extraction:
  python3 rbac_manager.py --opm --image quay.io/operatorhubio/argocd-operator:v0.7.0

Generate Helm values.yaml:
  python3 rbac_manager.py --opm --image quay.io/operatorhubio/argocd-operator:v0.7.0 --helm

Save to directory:
  python3 rbac_manager.py --opm --image quay.io/operatorhubio/argocd-operator:v0.7.0 --output ./rbac-files/

Custom namespace:
  python3 rbac_manager.py --opm --image quay.io/operatorhubio/argocd-operator:v0.7.0 --openshift-namespace production

Least-privilege RBAC (expand wildcard verbs):
  python3 rbac_manager.py --opm --image quay.io/operatorhubio/argocd-operator:v0.7.0 --least-privileges

Least-privilege with Helm output:
  python3 rbac_manager.py --opm --image quay.io/operatorhubio/argocd-operator:v0.7.0 --least-privileges --helm

Save Helm values to file:
  python3 rbac_manager.py --opm --image quay.io/operatorhubio/argocd-operator:v0.7.0 --helm --output ./helm-values/

Note: --least-privileges expands wildcard (*) verbs to explicit verbs for security auditing.
      Use with caution as it may break operator functionality if the operator requires wildcards.
""")

    def _show_catalogd_examples(self) -> None:
        """Show Catalogd-specific examples."""
        print("""
Catalogd Examples - Query package metadata from OpenShift catalogs

Query package information and get bundle URLs:
  python3 rbac_manager.py --catalogd --package prometheus --insecure

Query from specific catalog:
  python3 rbac_manager.py --catalogd --package prometheus --catalog-name openshift-community-operators --insecure

List all packages in a catalog:
  python3 rbac_manager.py --catalogd --list-packages --insecure

List OLMv1 compatible packages:
  python3 rbac_manager.py --catalogd --all-namespaces-packages --insecure

Generate config file:
  python3 rbac_manager.py --generate-config ~/.rbac-catalogd.yaml

Note: catalogd only queries metadata. To extract RBAC, copy the bundle URL and use:
  python3 rbac_manager.py --opm --image <bundle-url-from-catalogd>
""")
    
    def _show_list_catalogs_examples(self) -> None:
        """Show list-catalogs-specific examples."""
        print("""
List Catalogs Examples - Display available ClusterCatalogs

Basic usage:
  python3 rbac_manager.py --list-catalogs --insecure

With verbose output:
  python3 rbac_manager.py --list-catalogs --insecure --verbose

Custom authentication:
  python3 rbac_manager.py --list-catalogs --openshift-url https://api.cluster.com:6443 --openshift-token $OPENSHIFT_TOKEN --insecure

Generate config:
  python3 rbac_manager.py --generate-config ~/.rbac-list-catalogs.yaml
""")
    
    def _show_all_examples(self) -> None:
        """Show examples for all operation modes."""
        print("""
RBAC Manager Examples - Comprehensive usage examples

Operation Modes:

1. OPM Mode (Bundle Images):
   python3 rbac_manager.py --opm --image quay.io/operatorhubio/argocd-operator:v0.7.0 --helm

2. Catalogd Mode (OpenShift Catalogs):
   python3 rbac_manager.py --catalogd --package prometheus --insecure

3. List Catalogs Mode:
   python3 rbac_manager.py --list-catalogs --insecure

For mode-specific examples:
  python3 rbac_manager.py --opm --examples
  python3 rbac_manager.py --catalogd --examples
  python3 rbac_manager.py --list-catalogs --examples
""")
    
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
        
        # Create clean, typed execution context from CLI arguments
        self.context = ExecutionContext.from_args(self.args)
    
    def _setup_logging_and_validation(self) -> None:
        """Setup logging and validate arguments."""
        setup_logging(verbose=self.context.verbose)
        
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
        # Set up RBAC processing parameters
        self.output_dir = Path(self.context.output_directory) if self.context.output_directory else None
        if self.output_dir:
            self.output_dir.mkdir(exist_ok=True)
        self.insecure = self.context.insecure
        
        # Initialize RBAC processing components using dependency injection
        if not self.rule_builder:
            self.rule_builder = self._create_default_rule_builder()
        if not self.opm_lib:
            self.opm_lib = self._create_default_opm_lib(insecure=self.context.insecure)
        # catalog_lib will be initialized when API URL is set
        
    
    # ============================================================================
    # Context-Based Business Logic Methods (Decoupled from CLI)
    # ============================================================================
    
    def _should_show_examples(self, context: ExecutionContext) -> bool:
        """Check if examples should be shown (business logic decoupled from CLI)."""
        return context.show_examples
    
    def _get_output_mode(self, context: ExecutionContext) -> str:
        """Get the output mode from context (business logic decoupled from CLI)."""
        return context.output_mode
    
    def _should_use_helm_format(self, context: ExecutionContext) -> bool:
        """Check if Helm format should be used (business logic decoupled from CLI)."""
        return context.is_helm_output()
    
    def _should_save_to_directory(self, context: ExecutionContext) -> bool:
        """Check if output should be saved to directory (business logic decoupled from CLI)."""
        return context.is_directory_output()
    
    def _get_bundle_image_url(self, context: ExecutionContext) -> Optional[str]:
        """Get bundle image URL from context (business logic decoupled from CLI)."""
        return context.bundle_image
    
    def _get_package_name(self, context: ExecutionContext) -> Optional[str]:
        """Get package name from context (business logic decoupled from CLI)."""
        return context.package_name
    
    def _get_target_namespace_from_context(self, context: ExecutionContext) -> str:
        """Get target namespace from context (business logic decoupled from CLI)."""
        return context.get_target_namespace()
    
    def _discover_bundles(self, context: ExecutionContext) -> DiscoveryResult:
        """
        Discover bundle URLs using simplified discovery approach.
        
        This replaces the complex factory pattern with direct method calls
        based on the operation mode in the context.
        """
        try:
            if context.opm_mode and context.bundle_image:
                # OPM discovery
                bundle_urls = discover_bundles_via_opm(
                    bundle_image=context.bundle_image,
                    package_name=context.package_name,
                    insecure=context.insecure
                )
                return DiscoveryResult(
                    method=DiscoveryMethod.OPM.value,
                    bundle_urls=bundle_urls,
                    metadata={
                        'context_operation': context.get_operation_mode(),
                        'bundle_count': len(bundle_urls),
                        'insecure': context.insecure
                    },
                    success=True
                )
            elif context.catalogd_mode and self.catalog_lib and context.package_name:
                # Catalogd discovery
                bundle_urls = discover_bundles_via_catalogd(
                    catalog_lib=self.catalog_lib,
                    package_name=context.package_name,
                    catalog_name=context.catalog_name or "operatorhubio"
                )
                return DiscoveryResult(
                    method=DiscoveryMethod.CATALOGD.value,
                    bundle_urls=bundle_urls,
                    metadata={
                        'context_operation': context.get_operation_mode(),
                        'bundle_count': len(bundle_urls),
                        'insecure': context.insecure
                    },
                    success=True
                )
            else:
                raise ValueError(f"No discovery method available for operation mode: {context.get_operation_mode()}")
                
        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.error(f"Discovery failed: {e}")
            return DiscoveryResult(
                method="unknown",
                bundle_urls=[],
                metadata={'error_details': str(e)},
                success=False,
                error_message=str(e)
        )
    
    def _execute_workflow(self) -> int:
        """
        Execute the requested workflow based on arguments using command map pattern.
        
        Returns:
            Exit code
        """
        workflow_command = self._determine_workflow_command()
        
        if not workflow_command:
            # Provide helpful guidance when no operation mode is specified
            print("ERROR: No operation mode specified")
            print("")
            print("For complete help and examples, run:")
            print("    python3 rbac_manager.py --help")
            print("")
            print("Available operation modes:")
            print("   --opm       Extract RBAC from OLM bundle images")
            print("   --catalogd  Query OpenShift catalogs via catalogd API")
            print("   --list-catalogs  List available ClusterCatalogs")
            print("")
            print("Quick examples:")
            print("    python3 rbac_manager.py --catalogd --package prometheus --insecure")
            print("    python3 rbac_manager.py --opm --image quay.io/operatorhubio/argocd-operator:v0.7.0 --helm")
            print("    python3 rbac_manager.py --list-catalogs --insecure")
            return 1
        
        # Use command map for workflow execution
        workflow_command_map = {
            'list_catalogs': self._execute_list_catalogs_workflow,
            'opm': self._execute_opm_workflow,
            'catalogd': self._execute_catalogd_workflow
        }
        
        handler = workflow_command_map.get(workflow_command)
        if handler:
            return handler()
        else:
            logging.error(f"Unknown workflow command: {workflow_command}")
            return 1
    
    def _determine_workflow_command(self) -> Optional[str]:
        """
        Determine which workflow command to execute based on arguments.
        
        Returns:
            Command name or None if no valid command found
        """
        if self.args.list_catalogs:
            return 'list_catalogs'
        elif self.args.opm:
            return 'opm'
        elif self.args.catalogd:
            return 'catalogd'
        else:
            return None
    
    def _execute_list_catalogs_workflow(self) -> int:
        """
        Execute standalone list-catalogs workflow (no query method needed).
        
        This workflow uses direct OpenShift API access - no catalogd service needed.
        """
        # Import only when needed to avoid circular imports
        from .core_utils import OpenShiftAuth, list_openshift_clustercatalogs
        
        # Authenticate with OpenShift (no catalogd verification needed)
        logging.info("Authenticating with OpenShift...")
        openshift_auth = OpenShiftAuth(
            api_url=self.args.openshift_url,
            token=self.args.openshift_token,
            insecure=self.args.insecure,
            verify_catalogd_permissions=False  # No catalogd access needed
        )
        openshift_auth.login()
        
        # List catalogs using direct Kubernetes API
        return list_openshift_clustercatalogs()
    
    def _execute_opm_workflow(self) -> int:
        """
        Execute OPM-based workflow following clean 'discover then process' data flow.
        
        This method demonstrates the proper separation of concerns:
        1. Discovery phase: Use OPM to discover bundle URLs
        2. Processing phase: Process discovered URLs through the bundle processing pipeline
        """
        # Check if user provided the required --image flag
        if not self.args.image:
            print("The --opm flag requires the --image flag to specify a bundle image.")
            print("")
            print("For a complete list of opm operations and examples, run:")
            print("    python3 rbac_manager.py --opm --help")
            print("")
            print("Common opm operations:")
            print("    --image BUNDLE --helm                Generate values.yaml for Helm chart (GitOps approach)")
            print("    --image BUNDLE --output DIR          Save files to directory")
            print("    --image BUNDLE                       Print YAML to stdout (default)")
            print("")
            print("Examples:")
            print("    python3 rbac_manager.py --opm --image quay.io/operatorhubio/argocd-operator:v0.7.0 --helm")
            print("    python3 rbac_manager.py --opm --image registry.redhat.io/operator-bundle:latest --output ./rbac-files")
            return 1
        
        # Step 1: Discovery Phase - Use OPM to discover bundle URLs
        bundle_image = self.args.image
        logging.info(f"Starting OPM discovery for image: {bundle_image}")
        
        # Get registry token from args or environment variable
        registry_token = self._get_registry_token()
        if registry_token:
            logging.info("Using registry authentication token")
        
        # Use pure discovery to get bundle URLs
        discovered_bundle_urls = self._discover_bundle_urls_via_opm(bundle_image)
        if not discovered_bundle_urls:
            logging.error(f"OPM discovery failed: No bundle URLs found for image {bundle_image}")
            return 1
        
        logging.info(f"Discovery phase complete: found {len(discovered_bundle_urls)} bundle(s)")
        
        # Step 2: Processing Phase - Process discovered bundle URLs
        if self.args.helm:
            # For Helm mode, process the first discovered bundle for Helm values
            return self._process_bundles_for_helm(discovered_bundle_urls, registry_token)
        else:
            # For standard YAML mode, process all discovered bundles
            return self._process_bundles_for_yaml(discovered_bundle_urls, registry_token)
    
    def _discover_bundle_urls_via_opm(self, bundle_image: str) -> List[str]:
        """
        Pure discovery method to get bundle URLs from OPM.
        
        This method uses the OPM query library for pure discovery, returning
        only bundle URLs without any processing.
        
        Args:
            bundle_image: Bundle image or catalog index image
            
        Returns:
            List of discovered bundle URLs
        """
        try:
            # Use the existing pure discovery function
            from .opm_query import discover_bundles_via_opm
            
            discovered_urls = discover_bundles_via_opm(
                bundle_image=bundle_image,
                package_name=getattr(self.args, 'package', None),  # Optional package filtering
                insecure=self.insecure
            )
            
            logging.debug(f"OPM discovery returned {len(discovered_urls)} URL(s)")
            return discovered_urls
            
        except Exception as e:
            logging.error(f"OPM discovery failed for image {bundle_image}: {e}")
            return []
    
    def _process_bundles_for_helm(self, bundle_urls: List[str], registry_token: Optional[str]) -> int:
        """
        Process discovered bundle URLs for Helm output.
        
        Args:
            bundle_urls: List of discovered bundle URLs
            registry_token: Optional registry authentication token
            
        Returns:
            Exit code (0 for success, 1 for failure)
        """
        if not bundle_urls:
            logging.error("No bundle URLs to process for Helm output")
            return 1
        
        # For Helm mode, process the first bundle (most common use case)
        bundle_url = bundle_urls[0]
        if len(bundle_urls) > 1:
            logging.info(f"Multiple bundles discovered, processing first: {bundle_url}")
        
        try:
            # Extract data for Helm processing
            csv_data, rbac_data, bundle_data = self._extract_bundle_data_for_helm(bundle_url, registry_token)
            
            if not rbac_data:
                logging.error(f"Failed to extract RBAC data from bundle: {bundle_url}")
                return 1
            
            # Convert to Helm values structure
            rbac_converter = RBACConverter()
            package_name = csv_data.name if csv_data and hasattr(csv_data, 'name') and csv_data.name else "operator"
            
            # Get the HelmChartValues object (clean data structure)
            helm_values_obj = rbac_converter.convert_rbac_to_helm_values(rbac_data, package_name, csv_data)
            
            # Add security header for final YAML output
            security_header = rbac_converter._generate_security_notice_header()
            
            # Convert to YAML string with security header
            final_helm_yaml = helm_values_obj.to_yaml(security_header)
            
            # Handle output
            if not self._handle_helm_yaml_output(final_helm_yaml):
                return 1
            
            return 0
            
        except Exception as e:
            logging.error(f"Failed to process bundle for Helm output: {e}")
            return 1
    
    def _process_bundles_for_yaml(self, bundle_urls: List[str], registry_token: Optional[str]) -> int:
        """
        Process discovered bundle URLs for standard YAML output.
        
        Args:
            bundle_urls: List of discovered bundle URLs
            registry_token: Optional registry authentication token
            
        Returns:
            Exit code (0 for success, 1 for failure)
        """
        if not bundle_urls:
            logging.error("No bundle URLs to process for YAML output")
            return 1
        
        try:
            # Use the existing bundle processing pipeline
            rbac_resources = self.extract_rbac_via_bundle_processing(bundle_urls, registry_token)
            
            if not rbac_resources:
                logging.error("Failed to extract RBAC resources from discovered bundles")
                return 1
            
            # Use consolidated output handling
            if not self._handle_output(rbac_resources, "rbac"):
                return 1
            
            return 0
            
        except Exception as e:
            logging.error(f"Failed to process bundles for YAML output: {e}")
            return 1
    
    def _execute_catalogd_workflow(self) -> int:
        """Execute ClusterCatalog API-based workflow."""
        # Check if user provided required operation parameters
        valid_operations = [
            (hasattr(self.args, 'package') and self.args.package),
            (hasattr(self.args, 'catalog_name') and self.args.catalog_name),
            (hasattr(self.args, 'list_packages') and self.args.list_packages),
            (hasattr(self.args, 'all_namespaces_packages') and self.args.all_namespaces_packages),
            (hasattr(self.args, 'examples') and self.args.examples)
        ]
        
        if not any(valid_operations):
            print("The --catalogd flag requires an operation to be specified.")
            print("")
            print("For a complete list of catalogd operations and examples, run:")
            print("    python3 rbac_manager.py --catalogd --help")
            print("")
            print("Common catalogd operations:")
            print("    --catalog-name CATALOG           Query specific catalog directly")
            print("    --package PACKAGE                Query package metadata and get bundle URLs")
            print("    --list-packages                  List all available packages")
            print("    --all-namespaces-packages        List packages supporting AllNamespaces install mode")
            print("    --examples                       Show detailed catalogd examples")
            print("")
            print("Examples:")
            print("    python3 rbac_manager.py --catalogd --catalog-name redhat-custom-catalog --insecure")
            print("    python3 rbac_manager.py --catalogd --package prometheus --insecure")
            print("    python3 rbac_manager.py --catalogd --list-packages --insecure")
            print("    python3 rbac_manager.py --catalogd --all-namespaces-packages --insecure")
            print("    python3 rbac_manager.py --catalogd --examples --insecure")
            return 1
        
        # Handle examples first - no auth needed
        if hasattr(self.args, 'examples') and self.args.examples:
            return self._show_catalogd_examples()
            
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
            self.set_catalog_api_url(catalog_api_url)
            return self._execute_catalogd_operations()
    
    def _execute_catalogd_operations(self) -> int:
        """Execute specific Catalogd operations."""
        if self.args.list_catalogs:
            return self._list_catalogs()
        elif self.args.list_packages:
            return self._list_packages()
        elif self.args.all_namespaces_packages:
            return self._list_all_namespaces_packages()
        elif hasattr(self.args, 'catalog_name') and self.args.catalog_name and not self.args.package:
            # If only catalog-name is provided (without package), list packages in that catalog
            return self._list_packages_in_catalog(self.args.catalog_name)
        else:
            return self._query_package_metadata()
    
    def _list_packages_in_catalog(self, catalog_name: str) -> int:
        """List all packages in a specific catalog in JSON format."""
        try:
            import json
            
            packages = self.get_all_packages_via_catalogd(catalog_name)
            
            if not packages:
                error_output = {
                    "error": f"No packages found in catalog '{catalog_name}'",
                    "possible_issues": [
                        "Catalog name is incorrect",
                        "Catalog is not available or empty",
                        "Catalogd service is not responding"
                    ]
                }
                print(json.dumps(error_output, indent=2))
                return 1
            
            output = {
                "catalog": catalog_name,
                "packages": sorted(packages)
            }
            
            print(json.dumps(output, indent=2))
            return 0
            
        except Exception as e:
            import json
            error_output = {
                "error": f"Error listing packages in catalog '{catalog_name}': {e}"
            }
            print(json.dumps(error_output, indent=2))
            logging.error(f"Error listing packages in catalog: {e}")
        return 1
    
    def _show_catalogd_examples(self) -> int:
        """Show detailed catalogd examples."""
        print("""
Catalogd Examples - Query package metadata from OpenShift catalogs

Note: Catalogd only returns package metadata and bundle URLs. For RBAC extraction, use the provided bundle URLs with --opm.

Query specific catalog directly:
  python3 rbac_manager.py --catalogd --catalog-name redhat-custom-catalog --insecure

Query package metadata and get bundle URLs:
  python3 rbac_manager.py --catalogd --package prometheus --insecure

Custom catalog and connection settings:
  python3 rbac_manager.py --catalogd --catalog-name custom-catalog --package argocd-operator --insecure

List all packages in a catalog:
  python3 rbac_manager.py --catalogd --list-packages --insecure

List packages supporting AllNamespaces install mode:
  python3 rbac_manager.py --catalogd --all-namespaces-packages --insecure

With custom catalogd service:
  python3 rbac_manager.py --catalogd --list-packages --catalogd-namespace custom-ns --catalogd-service custom-svc --insecure

List available cluster catalogs:
  python3 rbac_manager.py --list-catalogs --insecure

Using with OpenShift authentication:
  python3 rbac_manager.py --catalogd --package prometheus --openshift-url https://api.cluster.local:6443 --openshift-token TOKEN

Using environment variables:
  export OPENSHIFT_TOKEN="your-token-here"
  python3 rbac_manager.py --catalogd --list-packages --openshift-url https://api.cluster.local:6443

Configuration file usage:
  python3 rbac_manager.py --catalogd --package prometheus --config ./catalogd-config.yaml

Generate configuration template:
  python3 rbac_manager.py --catalogd --generate-config ./my-catalogd-config.yaml

Workflow Example:
  # 1. Query package to get bundle URLs
  python3 rbac_manager.py --catalogd --package prometheus --insecure
  
  # 2. Copy a bundle URL from the output and extract RBAC
  python3 rbac_manager.py --opm --image quay.io/openshift-community-operators/prometheus@sha256:...
        """)
        return 0
    
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
        
        packages = self.get_all_packages_via_catalogd(catalog_to_query)
        print(f"Found {len(packages)} packages in '{catalog_to_query}':")
        for package in packages:
            print(f"  - {package}")
        return 0
    
    def _list_all_namespaces_packages(self) -> int:
        """List packages supporting AllNamespaces install mode."""
        catalog_to_query = self.catalog_ui.determine_catalog_to_use(self.args, "all-namespaces-packages")
        logging.info(f"Querying AllNamespaces packages from catalog: {catalog_to_query}")
        
        packages = self.catalog_lib.get_packages_with_all_namespaces(catalog_to_query)
        print(f"Packages supporting AllNamespaces (no webhooks) in '{catalog_to_query}':")
        for package in packages:
            print(f"  - {package}")
        return 0
    
    def _query_package_metadata(self) -> int:
        """Query package metadata from catalog."""
        # Use catalog_name if provided, otherwise use UI to determine catalog
        if hasattr(self.args, 'catalog_name') and self.args.catalog_name:
            catalog_to_use = self.args.catalog_name
            print(f"Using specified catalog: {catalog_to_use}")
        else:
            catalog_to_use = self.catalog_ui.determine_catalog_to_use(self.args, "package metadata query")
        
        if self.args.package:
            # Determine the type of query based on provided flags
            has_channel = hasattr(self.args, 'channel') and self.args.channel
            has_version = hasattr(self.args, 'version') and self.args.version
            
            if has_channel and has_version:
                # Complete query with all flags - return JSON format
                print(f"Querying complete package metadata from catalog: {catalog_to_use}")
                success = self._query_package_via_catalogd(self.args.package, catalog_to_use)
            elif has_channel:
                # Query versions in a specific channel - human readable
                print(f"Querying versions in channel '{self.args.channel}' for package '{self.args.package}' from catalog: {catalog_to_use}")
                success = self._query_channel_versions(self.args.package, self.args.channel, catalog_to_use)
            else:
                # Query available channels - human readable
                print(f"Querying available channels for package '{self.args.package}' from catalog: {catalog_to_use}")
                success = self._query_package_channels(self.args.package, catalog_to_use)
            
            if success:
                return 0
            else:
                logging.error(f"Failed to query package '{self.args.package}' from catalog '{catalog_to_use}'")
                return 1
        else:
            # List all packages from catalog in JSON format
            import json
            packages = self.get_all_packages_via_catalogd(catalog_to_use)
            
            output = {
                "catalog": catalog_to_use,
                "packages": sorted(packages)
            }
            
            print(json.dumps(output, indent=2))
            logging.info(f"Listed {len(packages)} packages from catalog {catalog_to_use}")
            return 0
    
    def _query_package_via_catalogd(self, package_name: str, catalog_name: str) -> bool:
        """
        Query package metadata via catalogd API and display information for manual use.
        
        This method queries the catalogd API to get package metadata and displays
        bundle URLs and other information that can be used manually with --opm flag.
        
        Args:
            package_name: Name of the package to query
            catalog_name: Name of the catalog to query
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not self.catalog_lib:
                logging.error("Catalog library not initialized")
                return False
            
            # Get package metadata from catalogd
            logging.info(f"Querying package '{package_name}' from catalog '{catalog_name}'")
            package_data = self.catalog_lib.get_package_metadata(package_name, catalog_name)
            
            if not package_data:
                print(f"ERROR: Package '{package_name}' not found in catalog '{catalog_name}'")
                return False
            
            # Display package information
            self._display_package_metadata(package_data, package_name, catalog_name)
            
            return True
            
        except Exception as e:
            logging.error(f"Failed to query package via catalogd: {e}")
            print(f"ERROR: Error querying package '{package_name}': {e}")
            return False
    
    def _display_package_metadata(self, package_data: Dict[str, Any], package_name: str, catalog_name: str) -> None:
        """
        Display package metadata. For specific version queries, show minimal JSON.
        For general queries, show full metadata.
        
        Args:
            package_data: Package metadata from catalogd API
            package_name: Name of the package
            catalog_name: Name of the catalog
        """
        import json
        
        # Check if this is a specific version query
        requested_channel = getattr(self.args, 'channel', None)
        requested_version = getattr(self.args, 'version', None)
        
        if requested_channel and requested_version:
            # Specific version query - return minimal, focused JSON
            self._display_specific_version_metadata(package_data, package_name, catalog_name, requested_channel, requested_version)
        else:
            # General query - return full metadata
            self._display_full_package_metadata(package_data, package_name, catalog_name)
    
    def _display_specific_version_metadata(self, package_data: Dict[str, Any], package_name: str, catalog_name: str, requested_channel: str, requested_version: str) -> None:
        """
        Display metadata for a specific version only - minimal JSON output.
        """
        import json
        
        # Find the specific bundle in the package data
        target_bundle = None
        bundles = package_data.get('bundles', [])
        olmv1_compatible = package_data.get('olmv1_compatible_bundles', [])
        
        # Look for the requested version in bundles
        for bundle in bundles:
            bundle_name = bundle.get('name', '')
            # Match both exact name and version patterns
            if (bundle_name == requested_version or 
                bundle_name.endswith(f".{requested_version}") or
                bundle_name.endswith(f"v{requested_version}")):
                
                # Check if this bundle is OLMv1 compatible
                is_olmv1_compatible = bundle in olmv1_compatible
                
                target_bundle = {
                    "package": package_name,
                    "channel": requested_channel,
                    "version": requested_version,
                    "image": bundle.get('image', 'unknown'),
                    "olmv1_compatible": is_olmv1_compatible
                }
                break
        
        if target_bundle:
            print(json.dumps(target_bundle, indent=2))
        else:
            error_msg = {
                "error": f"Version '{requested_version}' not found in channel '{requested_channel}' for package '{package_name}'"
            }
            print(json.dumps(error_msg, indent=2))
    
    def _display_full_package_metadata(self, package_data: Dict[str, Any], package_name: str, catalog_name: str) -> None:
        """
        Display full package metadata (fallback for general queries).
        """
        import json
        
        # Build clean JSON output structure
        bundles = package_data.get('bundles', [])
        olmv1_compatible = package_data.get('olmv1_compatible_bundles', [])
        
        # Create structured output for automation
        output = {
            "package": {
                "name": package_name,
                "catalog": catalog_name,
                "default_channel": package_data.get('default_channel', 'unknown'),
                "latest_version": package_data.get('latest_version', 'unknown')
            },
            "channels": [
                {
                    "name": channel.get('name', 'unknown'),
                    "entries_count": len(channel.get('entries', [])),
                    "entries": [
                        {
                            "name": entry.get('name', 'unknown'),
                            "version": entry.get('name', 'unknown')  # In OLM, entry name is typically the version
                        }
                        for entry in channel.get('entries', [])
                    ]
                }
                for channel in package_data.get('channels', [])
            ],
            "bundle_summary": {
                "total_bundles": len(bundles),
                "olmv1_compatible": len(olmv1_compatible)
            },
            "olmv1_compatible_bundles": [
                {
                    "image": bundle.get('image', 'unknown'),
                    "version": bundle.get('version', bundle.get('name', 'unknown')),
                    "name": bundle.get('name', 'unknown'),
                    "compatibility": {
                        "all_namespaces_supported": bundle.get('olmv1_info', {}).get('all_namespaces_supported', False),
                        "has_webhooks": bundle.get('olmv1_info', {}).get('has_webhooks', True),
                        "compatible": bundle.get('olmv1_info', {}).get('compatible', False)
                    }
                }
                for bundle in olmv1_compatible
            ],
            "all_bundles": [
                {
                    "image": bundle.get('image', 'unknown'),
                    "version": bundle.get('version', bundle.get('name', 'unknown')),
                    "name": bundle.get('name', 'unknown'),
                    "olmv1_compatible": bundle in olmv1_compatible
                }
                for bundle in bundles
            ],
            "usage": {
                "next_steps": [
                    "Copy an image URL from olmv1_compatible_bundles",
                    "Use the provided opm_commands to extract RBAC",
                    "Deploy the generated RBAC resources before ClusterExtension"
                ],
                "example_workflow": [
                    f"python3 rbac_manager.py --catalogd --package {package_name} --catalog-name {catalog_name}",
                    "# Copy bundle image URL from JSON output",
                    "python3 rbac_manager.py --opm --image <bundle-url>",
                    "# Apply generated RBAC YAML to cluster"
                ]
            }
        }
        
        # Output clean JSON
        print(json.dumps(output, indent=2))
    
    def _query_package_channels(self, package_name: str, catalog_name: str) -> bool:
        """
        Query and display available channels for a package in JSON format.
        
        Args:
            package_name: Name of the package
            catalog_name: Name of the catalog
            
        Returns:
            True if successful, False otherwise
        """
        try:
            import json
            
            if not self.catalog_lib:
                logging.error("Catalog library not initialized")
                return False
            
            # Get channel information
            channels = self.catalog_lib.get_package_channels(package_name, catalog_name)
            
            if not channels:
                error_output = {
                    "error": f"No channels found for package '{package_name}' in catalog '{catalog_name}'"
                }
                print(json.dumps(error_output, indent=2))
                return False
            
            # Build JSON output
            output = {
                "package": package_name,
                "catalog": catalog_name,
                "channels": [channel.get('name', 'unknown') for channel in channels]
            }
            
            print(json.dumps(output, indent=2))
            return True
            
        except Exception as e:
            import json
            logging.error(f"Failed to query channels for package '{package_name}': {e}")
            error_output = {
                "error": f"Failed to query channels for package '{package_name}': {e}"
            }
            print(json.dumps(error_output, indent=2))
            return False
    
    def _query_channel_versions(self, package_name: str, channel_name: str, catalog_name: str) -> bool:
        """
        Query and display available versions in a channel in JSON format.
        
        Args:
            package_name: Name of the package
            channel_name: Name of the channel
            catalog_name: Name of the catalog
            
        Returns:
            True if successful, False otherwise
        """
        try:
            import json
            
            if not self.catalog_lib:
                logging.error("Catalog library not initialized")
                return False
            
            # Get version information
            versions = self.catalog_lib.get_channel_versions(package_name, channel_name, catalog_name)
            
            if not versions:
                error_output = {
                    "error": f"No versions found for package '{package_name}' in channel '{channel_name}' from catalog '{catalog_name}'"
                }
                print(json.dumps(error_output, indent=2))
                return False
            
            # Build JSON output
            output = {
                "package": package_name,
                "catalog": catalog_name,
                "channel": channel_name,
                "versions": versions
            }
            
            print(json.dumps(output, indent=2))
            return True
            
        except Exception as e:
            import json
            logging.error(f"Failed to query versions for package '{package_name}' in channel '{channel_name}': {e}")
            error_output = {
                "error": f"Failed to query versions for package '{package_name}' in channel '{channel_name}': {e}"
            }
            print(json.dumps(error_output, indent=2))
            return False

    # ============================================================================
    # RBAC PROCESSING METHODS (formerly in RBACManager)
    # ============================================================================
    
    def set_catalog_api_url(self, api_url: str):
        """Set the catalog API URL and initialize the catalog library."""
        if not self.catalog_lib:
            self.catalog_lib = self._create_default_catalog_lib(api_url, insecure=self.insecure)
    
    def discover_and_process_catalog_package(self, catalog_image: str, package_name: str, registry_token: Optional[str] = None) -> Optional[RBACResources]:
        """
        Discover bundle URLs from a catalog index for a specific package, then process them.
        
        This method demonstrates the clean "discover then process" data flow:
        1. Use OPMQueryLib for pure discovery (find bundle URLs)
        2. Use extract_rbac_via_bundle_processing for processing
        
        Args:
            catalog_image: Catalog index image reference
            package_name: Name of the package to discover and process
            registry_token: Optional registry authentication token
            
        Returns:
            RBACResources with complete Kubernetes RBAC resources, or None if discovery/processing fails
        """
        logging.info(f"Starting discover-then-process workflow for package '{package_name}' in catalog '{catalog_image}'")
        
        # Step 1: Pure Discovery - find bundle URLs for the package
        if not self.opm_lib:
            self.opm_lib = OPMQueryLib(insecure=self.insecure)
        
        bundle_urls = self.opm_lib.discover_package_bundle_urls(catalog_image, package_name)
        if not bundle_urls:
            logging.error(f"No bundle URLs discovered for package '{package_name}' in catalog '{catalog_image}'")
            return None
        
        logging.info(f"Discovery phase complete: found {len(bundle_urls)} bundle(s)")
        
        # Step 2: Processing - use the discovered URLs with the existing processing pipeline
        return self.extract_rbac_via_bundle_processing(bundle_urls, registry_token)

    def extract_rbac_via_bundle_processing(self, bundle_image_urls: List[str], registry_token: Optional[str] = None, namespace_template: Optional[str] = None) -> Optional[RBACResources]:
        """
        Extract RBAC using the complete bundle processing pipeline with OPM render.
        
        This method processes bundle images directly using:
        1. OPM render on each bundle image
        2. CSV extraction from bundle manifests  
        3. RBAC parsing from CSV specifications
        4. Kubernetes resource generation
        
        Args:
            bundle_image_urls: List of bundle image URLs to process
            registry_token: Optional registry authentication token for private images
            namespace_template: Template for namespace in RBAC resources. If None, will be determined from context.
            
        Returns:
            RBACResources with complete Kubernetes RBAC resources ready for deployment,
            or None if extraction fails
        """
        # Import bundle processing components only when needed
        from .bundle_processor import BundleProcessor, BundleProcessorError
        
        bundle_processor = BundleProcessor(insecure=self.insecure, registry_token=registry_token)
        rbac_converter = RBACConverter()
        
        # Determine namespace template if not provided
        if namespace_template is None:
            # This method is used for YAML generation (not Helm), so use actual namespace
            namespace_template = self._get_target_namespace()
        
        logging.info(f"Starting bundle processing for {len(bundle_image_urls)} bundle image(s)")
        
        # Collect all RBAC resources from all bundles using typed structure
        all_rbac_resources = RBACResources()
        
        successful_bundles = 0
        
        for i, bundle_image_url in enumerate(bundle_image_urls, 1):
            logging.info(f"Processing bundle {i}/{len(bundle_image_urls)}: {bundle_image_url}")
            
            try:
                # Step 1: Render bundle image with OPM
                bundle_data = bundle_processor.render_bundle_image(bundle_image_url)
                
                # Step 2: Extract CSV from bundle
                csv_data = bundle_processor.extract_csv_from_bundle(bundle_data)
                if not csv_data:
                    logging.warning(f"No CSV found in bundle {bundle_image_url}, skipping")
                    continue
                
                # Step 3: Extract RBAC permissions from CSV
                rbac_data = bundle_processor.extract_rbac_from_csv(csv_data)
                
                # Step 4: Convert to Kubernetes RBAC resources
                # Extract package name from CSV metadata, or use a generic name
                csv_name = csv_data.name if hasattr(csv_data, 'name') and csv_data.name else 'extracted-operator'
                
                # Handle both dataclass and dict for RBAC data
                from dataclasses import is_dataclass, asdict
                if is_dataclass(rbac_data):
                    rbac_data_dict = asdict(rbac_data)
                else:
                    rbac_data_dict = rbac_data if isinstance(rbac_data, dict) else {}
                
                k8s_resources_dict = rbac_converter.convert_csv_rbac_to_k8s_resources(
                    rbac_data_dict, csv_name, namespace_template, self.context.least_privileges, csv_data
                )
                
                # Merge resources from this bundle into typed structure
                if 'serviceAccounts' in k8s_resources_dict:
                    all_rbac_resources.service_accounts.extend([
                        resource for resource in k8s_resources_dict['serviceAccounts']
                    ])
                if 'clusterRoles' in k8s_resources_dict:
                    all_rbac_resources.cluster_roles.extend([
                        resource for resource in k8s_resources_dict['clusterRoles']
                    ])  
                if 'roles' in k8s_resources_dict:
                    all_rbac_resources.roles.extend([
                        resource for resource in k8s_resources_dict['roles']
                    ])
                if 'clusterRoleBindings' in k8s_resources_dict:
                    all_rbac_resources.cluster_role_bindings.extend([
                        resource for resource in k8s_resources_dict['clusterRoleBindings']
                    ])
                if 'roleBindings' in k8s_resources_dict:
                    all_rbac_resources.role_bindings.extend([
                        resource for resource in k8s_resources_dict['roleBindings']
                    ])
                
                successful_bundles += 1
                logging.info(f"Successfully processed bundle {i}/{len(bundle_image_urls)}")
                
            except (BundleProcessorError, RBACConverterError) as e:
                logging.warning(f"Failed to process bundle {bundle_image_url}: {e}")
                continue
            except Exception as e:
                logging.error(f"Unexpected error processing bundle {bundle_image_url}: {e}")
                continue
        
        if successful_bundles == 0:
            logging.error("Failed to process any of the provided bundle images")
            return None
        
        logging.info(f"Bundle processing completed: {successful_bundles}/{len(bundle_image_urls)} successful")
        return all_rbac_resources
    
    def get_all_packages_via_catalogd(self, catalog_name: str = "operatorhubio") -> List[str]:
        """Get all packages via ClusterCatalog API."""
        if not self.catalog_lib:
            raise Exception("Catalog API URL not set. Use set_catalog_api_url() first.")
        
        return self.catalog_lib.list_packages(catalog_name)
    def _handle_output(self, data: Any, data_type: str = "rbac") -> bool:
        """
        Centralized output handling for all workflow types.
        
        This method consolidates all output logic (Helm values, RBAC files, stdout)
        into a single place, adhering to the DRY principle.
        
        Args:
            data: The data to output (RBACResources, HelmChartValues, or processed data)
            data_type: Type of data being output ("rbac", "helm", "csv", "bundle")
            
        Returns:
            True if output was successful, False otherwise
        """
        try:
            if self.args.helm and data_type in ["rbac", "helm"]:
                return self._handle_helm_output(data)
            elif self.args.output:
                return self._handle_directory_output(data, data_type)
            else:
                return self._handle_stdout_output(data, data_type)
        except Exception as e:
            logging.error(f"Output handling failed: {e}")
            return False
    
    def _handle_helm_yaml_output(self, helm_yaml: str) -> bool:
        """Handle output of final Helm YAML string."""
        try:
            if self.args.output:
                # Save to specified directory with unique values.yaml filename
                from pathlib import Path
                import datetime
                import secrets
                
                output_path = Path(self.args.output)
                output_path.mkdir(parents=True, exist_ok=True)
                
                # Generate unique identifier to prevent file overwrites
                timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
                random_suffix = secrets.token_hex(4)  # 8-character hex string
                unique_id = f"{timestamp}-{random_suffix}"
                
                values_path = output_path / f"values-{unique_id}.yaml"
                
                with open(values_path, 'w') as f:
                    f.write(helm_yaml)
                logging.info(f"Helm values.yaml saved to: {values_path}")
            else:
                # Print to stdout
                print(helm_yaml)
            
            logging.info("Helm values.yaml generation complete.")
            return True
            
        except Exception as e:
            logging.error(f"Failed to output Helm YAML: {e}")
            return False
    
    def _handle_helm_output(self, data: Any) -> bool:
        """Handle Helm values.yaml output."""
        try:
            if hasattr(data, 'to_yaml'):
                # Data is already a HelmChartValues object
                # Check if security header was added
                security_header = getattr(data, 'security_header', None)
                if security_header:
                    helm_values_yaml = data.to_yaml(security_header)
                else:
                    helm_values_yaml = data.to_yaml()
            else:
                # Data needs to be converted to Helm format
                # This handles the case where we have RBACResources or other data
                logging.error("Helm output requires HelmChartValues object")
                return False
            
            if self.args.output:
                # Save to specified directory with values.yaml filename
                from pathlib import Path
                output_path = Path(self.args.output)
                output_path.mkdir(parents=True, exist_ok=True)
                values_path = output_path / "values.yaml"
                
                with open(values_path, 'w') as f:
                    f.write(helm_values_yaml)
                
                print(f"Helm values.yaml saved to: {values_path}")
                logging.info("Helm values.yaml generation complete.")
            else:
                # Print to stdout
                print(helm_values_yaml)
                logging.info("Helm values.yaml generation complete.")
            
            return True
        except Exception as e:
            logging.error(f"Helm output failed: {e}")
            return False
    
    def _handle_directory_output(self, data: Any, data_type: str) -> bool:
        """Handle directory/file output."""
        try:
            if data_type == "rbac":
                self._save_rbac_to_files(data, self.args.output)
                print(f"RBAC files saved to: {self.args.output}")
                logging.info(f"RBAC extraction complete. Files saved to: {self.args.output}")
            else:
                logging.error(f"Directory output not supported for data type: {data_type}")
                return False
            
            return True
        except Exception as e:
            logging.error(f"Directory output failed: {e}")
            return False
    
    def _handle_stdout_output(self, data: Any, data_type: str) -> bool:
        """Handle stdout output."""
        try:
            if data_type == "rbac":
                self._print_rbac_resources(data)
                logging.info("RBAC extraction complete. YAML output printed above.")
            else:
                logging.error(f"Stdout output not supported for data type: {data_type}")
                return False
            
            return True
        except Exception as e:
            logging.error(f"Stdout output failed: {e}")
            return False
    
    def _display_completion_message(self) -> None:
        """Display appropriate completion message."""
        # This method is now simplified as completion messages are handled in _handle_output
        pass
