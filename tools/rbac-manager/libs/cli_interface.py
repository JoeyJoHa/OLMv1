"""
CLI Interface Module.

This module contains the command-line interface classes for the RBAC Manager tool.
It handles argument parsing, contextual help, and CLI workflow management.

Separated from config_utils.py to follow the Single Responsibility Principle.
"""

import argparse
import logging
import sys
from typing import Dict, List, Optional, Any, Union

from .config_manager import ConfigManager


# Set up logger
logger = logging.getLogger(__name__)


# ============================================================================
# TERMINAL UTILITIES (Moved from core_utils.py)
# ============================================================================

def check_terminal_output() -> bool:
    """
    Check if output is being piped (not connected to terminal).
    
    Returns:
        True if output is connected to terminal, False if piped
    """
    return sys.stdout.isatty()


def display_pipe_error_message(command_context: str) -> None:
    """
    Display helpful error message when output is piped for interactive operations.
    
    Args:
        command_context: Context description for the command that failed
    """
    print(f"\nError: {command_context} requires interactive terminal output.")
    print("This operation cannot be used with pipes or redirects.")
    print("""
Suggested solutions:
  1. Run the command directly in your terminal (without | or >)
  2. Use specific flags instead of interactive selection:
     --catalog-name <catalog_name>  # Specify catalog directly
     --package <package_name>       # Specify package directly
""")
    
    print("\nAvailable catalogs can be listed with: python3 rbac_manager.py --list-catalogs --insecure")


class ContextualHelpParser(argparse.ArgumentParser):
    """Custom ArgumentParser that provides contextual help based on operation mode and flags."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cli_interface = None
        
    def parse_args(self, args=None, namespace=None):
        """Override parse_args to handle contextual help."""
        # Check for contextual help requests before normal parsing
        if args is None:
            args = sys.argv[1:]
        
        # Handle contextual help requests
        if self._should_show_contextual_help(args):
            self._show_contextual_help(args)
            self.exit()
        
        return super().parse_args(args, namespace)
    
    def _should_show_contextual_help(self, args: List[str]) -> bool:
        """Check if we should show contextual help."""
        return '--help' in args or '-h' in args
    
    def _show_contextual_help(self, args: List[str]) -> None:
        """Show contextual help based on the flags provided."""
        # Check for specific flag combinations
        if '--opm' in args and '--help' in args:
            self._show_opm_help()
        elif '--catalogd' in args and '--help' in args:
            self._show_catalogd_help()
        elif '--list-catalogs' in args and '--help' in args:
            self._show_list_catalogs_help()
        elif '--examples' in args:
            self._show_examples(args)
        else:
            # Show regular help without examples
            self._show_flags_only_help()
    
    def _show_flags_only_help(self) -> None:
        """Show help with flags only, no examples."""
        # Get the regular help but remove examples section
        help_text = super().format_help()
        
        # Find and remove examples section
        lines = help_text.split('\n')
        result_lines = []
        skip_examples = False
        
        for line in lines:
            if 'Examples:' in line or 'examples:' in line:
                skip_examples = True
                # Add a note about examples
                result_lines.append('')
                result_lines.append('For detailed examples:')
                result_lines.append('  --examples                   Show comprehensive examples for all operations')
                result_lines.append('  --opm --examples            Show OPM-specific examples')
                result_lines.append('  --catalogd --examples       Show Catalogd-specific examples')
                result_lines.append('  --list-catalogs --examples  Show list-catalogs-specific examples')
                break
            if not skip_examples:
                result_lines.append(line)
        
        print('\n'.join(result_lines))
    
    def _show_opm_help(self) -> None:
        """Show OPM-specific help."""
        help_text = """
OPM Operations - Extract RBAC from operator bundle images

Usage:
  python3 rbac_manager.py --opm --image BUNDLE_IMAGE [OPTIONS]

Required Arguments:
  --image BUNDLE_IMAGE         Bundle image reference (REQUIRED for --opm)

General Options:
--openshift-namespace NAMESPACE  Target OpenShift namespace for generated resources (auto-discovered from current context)

Output Options (mutually exclusive):
  --helm                       Generate values.yaml for operator-olmv1 Helm chart
  --output DIR                 Save files to specified directory (default: print to stdout)
  

Registry Authentication (for private registries):
  --registry-token TOKEN       Registry authentication token for private bundle images
                               (or set REGISTRY_TOKEN environment variable)

Registry Credential Discovery (automatic):
  - ~/.docker/config.json      (Docker credentials)
  - ~/.config/containers/auth.json (Podman credentials) 
  - $XDG_RUNTIME_DIR/containers/auth.json (Runtime credentials)

Global Flags:
  --insecure                   Skip TLS certificate verification for image pulls
  --verbose, -v                Enable verbose logging

Configuration:
  --config FILE                Path to configuration file
  --generate-config FILE       Generate OPM-specific configuration file and exit

For examples: python3 rbac_manager.py --opm --examples
"""
        print(help_text)
    
    def _show_catalogd_help(self) -> None:
        """Show Catalogd-specific help."""
        help_text = """
Catalogd Operations - Extract JSON metadata from OpenShift catalogs

Note: Catalogd returns JSON metadata only. For actual RBAC extraction from bundle images, use --opm.

Usage:
  python3 rbac_manager.py --catalogd [OPTIONS]

Required Arguments (OpenShift Authentication):
  --openshift-url URL           OpenShift API URL (auto-discovers from kubeconfig if not provided)
  --openshift-token TOKEN       OpenShift authentication token (or set OPENSHIFT_TOKEN env var)

Catalogd Connection:
  --catalog-name CATALOG        Name of catalog to query (interactive selection if not specified)
  --local-port PORT             Local port for port-forward (default: 8080)
  --catalogd-namespace NS       Namespace containing catalogd service (default: openshift-catalogd)
  --catalogd-service SERVICE    Name of catalogd service (default: catalogd-service)

Operation Options:
  --list-catalogs              List available ClusterCatalogs in the cluster with their status
  --list-packages             List all available packages from selected catalog
  --all-namespaces-packages   List packages supporting AllNamespaces install mode

Package Query Options:
  --package PACKAGE            Specific package name to query
  --channel CHANNEL            Specific channel name (optional)
  --version VERSION            Specific version (optional)

Global Flags:
  --insecure                   Skip TLS certificate verification
  --verbose, -v                Enable verbose logging

Configuration:
  --config FILE                Path to configuration file
  --generate-config FILE       Generate Catalogd-specific configuration file and exit

For examples: python3 rbac_manager.py --catalogd --examples
"""
        print(help_text)
    
    def _show_list_catalogs_help(self) -> None:
        """Show list-catalogs-specific help."""
        help_text = """
List Catalogs Operation - Display available ClusterCatalogs

Usage:
  python3 rbac_manager.py --list-catalogs [OPTIONS]

Description:
  Lists all available ClusterCatalogs in the OpenShift cluster with their 
  status information. This is a read-only operation that helps you discover
  which catalogs are available for package queries.

OpenShift Authentication (REQUIRED):
  --openshift-url URL          OpenShift API URL (auto-discovers from kubeconfig if not provided)
  --openshift-token TOKEN      OpenShift authentication token (or set OPENSHIFT_TOKEN env var)

Connection Options:
  --catalogd-namespace NS      Namespace containing catalogd service (default: openshift-catalogd)
  --catalogd-service SERVICE   Name of catalogd service (default: catalogd-service)
  --local-port PORT           Local port for port-forward (default: 8080)

Global Flags:
  --insecure                   Skip TLS certificate verification
  --verbose, -v                Enable verbose logging

Configuration:
  --config FILE                Path to configuration file
  --generate-config FILE       Generate configuration file and exit

Output:
  Displays a formatted table with:
  - Catalog Name
  - Status (Ready/NotReady)
  - Last Updated timestamp
  - Source information

For examples: python3 rbac_manager.py --list-catalogs --examples
"""
        print(help_text)
    
    def _show_examples(self, args: List[str]) -> None:
        """Show examples based on the operation mode."""
        if '--opm' in args:
            self._show_opm_examples()
        elif '--catalogd' in args:
            self._show_catalogd_examples()
        elif '--list-catalogs' in args:
            self._show_list_catalogs_examples()
        else:
            self._show_all_examples()
    
    def _show_opm_examples(self) -> None:
        """Show OPM-specific examples."""
        examples_text = """
OPM Examples - RBAC extraction from operator bundle images

Basic Operations:

  # Generate Helm values.yaml and print to stdout (GitOps approach)
  python3 rbac_manager.py --opm --image quay.io/operatorhubio/argocd-operator:v0.7.0 --helm
  
  # Save Helm values.yaml to directory
  python3 rbac_manager.py --opm --image quay.io/jaegertracing/jaeger-operator-bundle:1.29.0 --helm --output ./helm-values/
  
  # Extract RBAC YAML and print to stdout (default)
  python3 rbac_manager.py --opm --image quay.io/prometheus-operator/prometheus-operator-bundle:v0.47.0
  
  # Extract RBAC YAML with custom OpenShift namespace
  python3 rbac_manager.py --opm --image quay.io/operatorhubio/argocd-operator:v0.7.0 --openshift-namespace argocd-system

Private Registry Examples:

  # Generate Helm values from private registry
  python3 rbac_manager.py --opm --image registry.redhat.io/ubi8/cert-manager-bundle@sha256:abc123 --registry-token token123 --helm
  
  # Extract RBAC YAML with custom namespace from private registry
  python3 rbac_manager.py --opm --image private.registry.com/my-operator:latest --registry-token mytoken --openshift-namespace production
  
  # Save files to directory from private registry
  python3 rbac_manager.py --opm --image private.registry.com/my-operator:latest --registry-token mytoken --output ./private-rbac

Deployment Examples:

  # Apply RBAC directly to cluster using kubectl/oc
  python3 rbac_manager.py --opm --image quay.io/operatorhubio/argocd-operator:v0.7.0 --openshift-namespace argocd-system | kubectl apply -f -
  
  # Save to file and apply
  python3 rbac_manager.py --opm --image quay.io/operatorhubio/argocd-operator:v0.7.0 --openshift-namespace production > rbac.yaml
  kubectl apply -f rbac.yaml
  
  # Apply from private registry
  python3 rbac_manager.py --opm --image private.registry.com/operator:v1.0 --registry-token $REGISTRY_TOKEN --openshift-namespace my-namespace | oc apply -f -

Configuration File Examples:

  # Generate an OPM-specific configuration file
  python3 rbac_manager.py --generate-config ~/.rbac-opm.yaml
  
  # Using configuration file for defaults (Helm values)
  python3 rbac_manager.py --config ~/.rbac-opm.yaml --opm --image bundle:latest --helm
  
  # Using configuration file for RBAC YAML
  python3 rbac_manager.py --config ~/.rbac-opm.yaml --opm --image bundle:latest --openshift-namespace production
"""
        print(examples_text)
    
    def _show_catalogd_examples(self) -> None:
        """Show Catalogd-specific examples."""
        examples_text = """
Catalogd Examples - JSON metadata extraction from OpenShift catalogs

Basic Operations:

  # List all packages in a catalog  
  python3 rbac_manager.py --catalogd --catalog-name openshift-certified-operators --list-packages --insecure
  
  # List packages from default catalog
  python3 rbac_manager.py --catalogd --list-packages --insecure

Package Querying:

  # Get package metadata (channels, versions, bundle URLs)
  python3 rbac_manager.py --catalogd --catalog-name openshift-community-operators --package prometheus --insecure
  
  # Get specific version metadata
  python3 rbac_manager.py --catalogd --catalog-name redhat-custom-catalog --package prometheus --version v0.47.0 --insecure

Authentication Examples:

  # Using custom OpenShift cluster
  python3 rbac_manager.py --catalogd --openshift-url https://api.my-cluster.com:6443 --package prometheus --insecure
  
  # Using service account token
  python3 rbac_manager.py --catalogd --openshift-token sha256~abc123... --package grafana --insecure

Configuration Examples:

  # Generate a Catalogd-specific configuration file
  python3 rbac_manager.py --generate-config ~/.rbac-catalogd.yaml
  
  # Using configuration file (cluster URL and tokens pre-configured)
  python3 rbac_manager.py --config ~/.rbac-catalogd.yaml --catalogd --package prometheus --insecure
"""
        print(examples_text)
    
    def _show_list_catalogs_examples(self) -> None:
        """Show list-catalogs-specific examples."""
        examples_text = """
List Catalogs Examples - Display available ClusterCatalogs

Basic Operations:

  # List all available catalogs (basic usage)
  python3 rbac_manager.py --list-catalogs --insecure
  
  # List catalogs with verbose output for debugging
  python3 rbac_manager.py --list-catalogs --insecure --verbose

Authentication Examples:

  # Using explicit cluster URL and token
  python3 rbac_manager.py --list-catalogs --openshift-url https://api.cluster.com:6443 --openshift-token $OPENSHIFT_TOKEN --insecure
  
  # Using environment variables for authentication
  export OPENSHIFT_TOKEN="sha256~abc123..."
  python3 rbac_manager.py --list-catalogs --insecure

Custom Connection Examples:

  # Using custom catalogd namespace
  python3 rbac_manager.py --list-catalogs --catalogd-namespace custom-catalogd --insecure
  
  # Using custom port for port-forwarding
  python3 rbac_manager.py --list-catalogs --local-port 9090 --insecure

Configuration Examples:

  # Generate a list-catalogs-specific configuration file
  python3 rbac_manager.py --generate-config ~/.rbac-list-catalogs.yaml
  
  # Using configuration file for default settings
  python3 rbac_manager.py --config ~/.rbac-list-catalogs.yaml --list-catalogs --insecure

Output Information:
  The command displays:
  - Catalog names available in the cluster
  - Status (Ready/NotReady/Syncing)
  - Last updated timestamps
  - Source repository information
  
  Use this information to choose a catalog for package queries with --catalogd --catalog-name
"""
        print(examples_text)
    
    def _show_all_examples(self) -> None:
        """Show examples for all operation modes."""
        examples_text = """
RBAC Manager Examples - Comprehensive usage examples

Operation Modes:

  # OPM mode - Extract RBAC from bundle images
  python3 rbac_manager.py --opm --image quay.io/operatorhubio/argocd-operator:v0.7.0 --openshift-namespace argocd-system
  
  # Catalogd mode - Query catalog metadata
  python3 rbac_manager.py --catalogd --package prometheus --insecure
  
  # List catalogs - Standalone operation
  python3 rbac_manager.py --list-catalogs --insecure

Output Options:

  # Generate Helm values.yaml (GitOps approach)
  python3 rbac_manager.py --opm --image bundle:latest --helm
  
  # Save RBAC files to directory
  python3 rbac_manager.py --opm --image bundle:latest --output ./rbac-files
  
  # Print to stdout (default)
  python3 rbac_manager.py --opm --image bundle:latest --openshift-namespace default
  
  # Apply directly to cluster using kubectl
  python3 rbac_manager.py --opm --image bundle:latest --openshift-namespace production | kubectl apply -f -

For mode-specific examples:
  python3 rbac_manager.py --opm --examples
  python3 rbac_manager.py --catalogd --examples
"""
        print(examples_text)

class CLIInterface:
    """Handles command-line interface setup and argument parsing."""
    
    def __init__(self):
        """Initialize CLI interface."""
        self.config_manager: Optional[ConfigManager] = None
        self.parser: Optional[ContextualHelpParser] = None
    
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
    
    def create_argument_parser(self, config_defaults: Optional[Dict[str, Any]] = None) -> ContextualHelpParser:
        """
        Create and configure the main argument parser with contextual help.
        
        Args:
            config_defaults: Default values from configuration file
            
        Returns:
            Configured ContextualHelpParser instance
        """
        parser = ContextualHelpParser(
            description='Unified RBAC Manager for OLM Operators (Port-Forward Version)',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=self._get_help_epilog()
        )
        parser.cli_interface = self
        
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
        query_group = parser.add_mutually_exclusive_group(required=False)
        query_group.add_argument('--opm', action='store_true',
                                help='Use OPM image queries')
        query_group.add_argument('--catalogd', action='store_true',
                                help='Use ClusterCatalog API queries via port-forward')
    
    def _add_opm_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add OPM-specific arguments."""
        parser.add_argument('--image', 
                           help='Catalog image reference (required for --opm)')
        parser.add_argument('--least-privileges', action='store_true',
                           help='Expand wildcard (*) verbs to explicit verbs for least-privilege RBAC. '
                                'By default, wildcards from operator bundles are preserved to maintain '
                                'operator functionality. Use this flag only if you need explicit verbs '
                                'and understand it may break operator deployment.')
    
    def _add_catalogd_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add ClusterCatalog API arguments."""
        parser.add_argument('--openshift-url', 
                           help='OpenShift API URL (optional, will auto-discover from kubeconfig if not provided)')
        parser.add_argument('--openshift-token',
                           help='OpenShift authentication token (or set OPENSHIFT_TOKEN env var)')
        parser.add_argument('--catalog-name', 
                           help='Name of catalog to query. If not specified, you will be prompted to choose from available catalogs. Use standalone --list-catalogs command to see available options.')
        
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
        """Add output arguments."""
        output_group = parser.add_mutually_exclusive_group()
        output_group.add_argument('--output', metavar='DIR',
                                 help='Save files to specified directory (YAML files or values.yaml)')
        output_group.add_argument('--helm', action='store_true',
                                 help='Generate values.yaml for operator-olmv1 Helm chart (default: print to stdout)')
        
        # OpenShift namespace argument for YAML generation (not used with --helm which uses templates)
        parser.add_argument('--openshift-namespace', metavar='NAMESPACE',
                           help='Target OpenShift namespace for generated RBAC resources')
    
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
        parser.add_argument('--examples', action='store_true',
                           help='Show detailed examples for the specified operation mode')
    
    def _get_help_epilog(self) -> str:
        """Return the help epilog text."""
        return """
Quick Start:
  %(prog)s --opm --image quay.io/operatorhubio/argocd-operator:v0.7.0 --openshift-namespace argocd-system
  %(prog)s --catalogd --package prometheus --insecure
  %(prog)s --list-catalogs --insecure

For detailed examples:
  %(prog)s --examples                     Show comprehensive examples for all operations
  %(prog)s --opm --examples              Show OPM-specific examples  
  %(prog)s --catalogd --examples         Show Catalogd-specific examples
  %(prog)s --list-catalogs --examples    Show list-catalogs-specific examples

For operation-specific help:
  %(prog)s --opm --help                  Show OPM-specific flags and options
  %(prog)s --catalogd --help             Show Catalogd-specific flags and options
  %(prog)s --list-catalogs --help        Show list-catalogs-specific flags and options

Configuration File:
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
        # No additional validation needed - let workflows handle their own requirements
        pass
