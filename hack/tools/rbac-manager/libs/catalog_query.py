"""
ClusterCatalog API Query and User Interface Module.

This module provides ClusterCatalog API querying functionality with caching,
improved error handling, and interactive catalog selection UI.
Consolidates catalog operations and user interaction in one cohesive module.
"""

import logging
import requests
import urllib3
import sys
from typing import Dict, List, Optional, Any
import argparse

# Import shared RBAC utilities
from . import rbac_utils
from .core_utils import check_terminal_output, display_pipe_error_message

# Set up logger
logger = logging.getLogger(__name__)


class CatalogAPIQueryLib:
    """Library class for ClusterCatalog API queries."""
    
    def __init__(self, base_url: str, insecure: bool = False):
        """
        Initialize API query library.
        
        Args:
            base_url: Base URL for the catalog API
            insecure: Skip TLS verification
        """
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        
        # Cache for storing catalog entries to avoid repeated API calls
        self._catalog_cache: Dict[str, List[Dict]] = {}
        
        if insecure:
            self.session.verify = False
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    @staticmethod
    def get_available_clustercatalogs() -> List[Dict[str, str]]:
        """
        Get list of available ClusterCatalogs from the cluster.
        
        Returns:
            List of catalog information dictionaries
        """
        try:
            from kubernetes import client
            api_client = client.CustomObjectsApi()
            cluster_catalogs = api_client.list_cluster_custom_object(
                group="olm.operatorframework.io",
                version="v1",
                plural="clustercatalogs"
            )
            catalogs_info = []
            for catalog in cluster_catalogs.get('items', []):
                metadata = catalog.get('metadata', {})
                status = catalog.get('status', {})
                
                # Parse serving status from conditions array
                serving_status = False
                conditions = status.get('conditions', [])
                for condition in conditions:
                    if condition.get('type') == 'Serving' and condition.get('status') == 'True':
                        serving_status = True
                        break
                
                catalog_info = {
                    'name': metadata.get('name', 'unknown'),
                    'lastUnpacked': status.get('lastUnpacked', 'never'),
                    'serving': serving_status,
                    'age': metadata.get('creationTimestamp', 'unknown')
                }
                catalogs_info.append(catalog_info)
            logger.info(f"Found {len(catalogs_info)} ClusterCatalogs")
            return catalogs_info
        except Exception as e:
            raise Exception(f"Failed to query ClusterCatalogs: {e}")
    
    def _make_request(self, endpoint: str) -> requests.Response:
        """Make HTTP request with error handling."""
        url = f"{self.base_url}{endpoint}"
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            logger.error(f"API request failed for {url}: {e}")
            raise Exception(f"API request failed: {e}")
    
    def get_all_entries(self, catalog_name: str = "operatorhubio") -> List[Dict]:
        """
        Get all entries from catalog with caching support.
        
        Args:
            catalog_name: Name of the catalog
            
        Returns:
            List of catalog entries
        """
        # Check cache first
        if catalog_name in self._catalog_cache:
            logger.debug(f"Using cached data for catalog: {catalog_name}")
            return self._catalog_cache[catalog_name]
        
        logger.info(f"Fetching all entries from catalog: {catalog_name}")
        
        endpoint = f"/catalogs/{catalog_name}/api/v1/all"
        response = self._make_request(endpoint)
        
        # Parse NDJSON (newline-delimited JSON) response
        data = []
        response_text = response.text.strip()
        if response_text:
            import json
            for line in response_text.split('\n'):
                line = line.strip()
                if line:
                    try:
                        data.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        logger.warning(f"Skipping invalid JSON line: {line[:100]}... Error: {e}")
        
        # Cache the results for future use
        self._catalog_cache[catalog_name] = data
        
        logger.info(f"Retrieved and cached {len(data)} catalog entries")
        return data
    
    def clear_cache(self, catalog_name: Optional[str] = None) -> None:
        """
        Clear cached catalog data.
        
        Args:
            catalog_name: Specific catalog to clear, or None to clear all
        """
        if catalog_name:
            self._catalog_cache.pop(catalog_name, None)
            logger.debug(f"Cleared cache for catalog: {catalog_name}")
        else:
            self._catalog_cache.clear()
            logger.debug("Cleared all catalog cache")
    
    def list_packages(self, catalog_name: str = "operatorhubio") -> List[str]:
        """
        List all packages in catalog.
        
        Args:
            catalog_name: Name of the catalog
            
        Returns:
            List of package names
        """
        entries = self.get_all_entries(catalog_name)
        
        packages = []
        for entry in entries:
            if entry.get('schema') == 'olm.package':
                packages.append(entry['name'])
        
        packages.sort()
        return packages
    
    def get_package_bundles(self, package_name: str, 
                          catalog_name: str = "operatorhubio") -> List[Dict]:
        """
        Get all bundles for a specific package.
        
        Args:
            package_name: Name of the package
            catalog_name: Name of the catalog
            
        Returns:
            List of bundle entries
        """
        entries = self.get_all_entries(catalog_name)
        
        bundles = []
        for entry in entries:
            if (entry.get('schema') == 'olm.bundle' and 
                entry.get('package') == package_name):
                bundles.append(entry)
        
        return bundles
    
    def _has_all_namespaces_support(self, csv_data: Dict) -> bool:
        """
        Check if CSV supports AllNamespaces install mode.
        
        Args:
            csv_data: CSV metadata
            
        Returns:
            True if AllNamespaces is supported
        """
        return rbac_utils.has_all_namespaces_support(csv_data)
    
    def _has_webhooks(self, bundle_entry: Dict) -> bool:
        """
        Check if bundle has webhook definitions.
        
        Args:
            bundle_entry: Bundle entry data
            
        Returns:
            True if webhooks are defined
        """
        return rbac_utils.has_webhooks(bundle_entry)
    
    def _get_csv_metadata(self, bundle_entry: Dict) -> Optional[Dict]:
        """
        Extract CSV metadata from bundle entry.
        
        Args:
            bundle_entry: Bundle entry data
            
        Returns:
            CSV metadata or None if not found
        """
        return rbac_utils.get_csv_metadata(bundle_entry)

    def get_packages_with_all_namespaces(self, catalog_name: str = "operatorhubio") -> List[str]:
        """
        Get packages that support AllNamespaces install mode without webhooks.
        
        Args:
            catalog_name: Name of the catalog
            
        Returns:
            List of package names
        """
        logger.info("Finding packages with AllNamespaces support (no webhooks)")
        
        entries = self.get_all_entries(catalog_name)
        packages = set()
        
        for entry in entries:
            if entry.get('schema') == 'olm.bundle':
                csv_data = self._get_csv_metadata(entry)
                if not csv_data:
                    continue
                
                # Check conditions using helper methods
                if (self._has_all_namespaces_support(csv_data) and 
                    not self._has_webhooks(entry)):
                    packages.add(entry.get('package'))
        
        result = sorted(list(packages))
        logger.info(f"Found {len(result)} packages supporting AllNamespaces without webhooks")
        return result
    
    def extract_rbac_resources(self, package_name: str, 
                               catalog_name: str = "operatorhubio") -> Optional[Dict]:
        """
        Extract RBAC resources for a package as Kubernetes YAML structures.
        
        Args:
            package_name: Name of the package
            catalog_name: Name of the catalog
            
        Returns:
            Dict with clusterRoles, roles, and serviceAccount, or None if not found
        """
        bundles = self.get_package_bundles(package_name, catalog_name)
        return rbac_utils.extract_rbac_from_bundles(bundles, package_name)


# ============================================================================
# CATALOG SELECTION USER INTERFACE
# ============================================================================

class CatalogSelectionUI:
    """Handles interactive catalog selection and user interface concerns."""
    
    @staticmethod
    def select_catalog_interactively() -> str:
        """
        Display available ClusterCatalogs and let user choose one interactively.
        
        Returns:
            Selected catalog name
            
        Raises:
            SystemExit: If user cancels or no catalogs available
        """
        try:
            catalogs = CatalogAPIQueryLib.get_available_clustercatalogs()
            
            if not catalogs:
                print("No ClusterCatalogs found in this cluster.")
                sys.exit(1)
            
            CatalogSelectionUI._display_catalog_table(catalogs)
            return CatalogSelectionUI._get_user_selection(catalogs)
            
        except Exception as e:
            print(f"Error fetching ClusterCatalogs: {e}")
            print("Falling back to default catalog: operatorhubio")
            return "operatorhubio"
    
    @staticmethod
    def determine_catalog_to_use(args: argparse.Namespace, command_context: str) -> str:
        """
        Determine which catalog to use based on arguments and terminal context.
        
        Args:
            args: Parsed command line arguments
            command_context: Context string for error messages
            
        Returns:
            Selected catalog name
            
        Raises:
            SystemExit: If piped output requires --catalog-name but it's not provided
        """
        if args.catalog_name:
            # User explicitly specified a catalog name
            return args.catalog_name
        
        # Check if output is being piped (not connected to terminal)
        if not check_terminal_output():
            display_pipe_error_message(command_context)
            sys.exit(1)
        
        # No catalog specified, let user choose interactively
        print("No catalog specified. Discovering available ClusterCatalogs...")
        return CatalogSelectionUI.select_catalog_interactively()
    
    @staticmethod
    def _display_catalog_table(catalogs: List[Dict[str, Any]]) -> None:
        """Display catalogs in a formatted table."""
        print(f"\nAvailable ClusterCatalogs:")
        print("-" * 70)
        print(f"{'  #':<4} {'Name':<35} {'Serving':<8} {'Last Unpacked':<20}")
        print("-" * 70)
        
        serving_catalogs = []
        for i, catalog in enumerate(catalogs, 1):
            serving_status = "True" if catalog['serving'] else "False"
            
            print(f"{i:>3} {catalog['name']:<35} {serving_status:<8} {catalog['lastUnpacked']:<20}")
            if catalog['serving']:
                serving_catalogs.append((i, catalog['name']))
        
        print("-" * 70)
        
        if not serving_catalogs:
            print("WARNING: No serving ClusterCatalogs found. All catalogs appear to be offline.")
            print("Note: You can still try to query them, but the requests may fail.")
        else:
            print(f"\nNote: Only serving catalogs can be reliably queried for packages.")
    
    @staticmethod
    def _get_user_selection(catalogs: List[Dict[str, Any]]) -> str:
        """Get user's catalog selection."""
        while True:
            try:
                choice = input(f"\nSelect a catalog (1-{len(catalogs)}) or 'q' to quit: ").strip()
                
                if choice.lower() == 'q':
                    print("Exiting.")
                    sys.exit(0)
                
                choice_num = int(choice)
                if 1 <= choice_num <= len(catalogs):
                    selected_catalog = catalogs[choice_num - 1]
                    
                    if not selected_catalog['serving']:
                        print(f"WARNING: '{selected_catalog['name']}' is not currently serving. This query may fail.")
                        confirm = input("Continue anyway? (y/N): ").strip().lower()
                        if confirm != 'y':
                            continue
                    
                    print(f"Selected catalog: {selected_catalog['name']}")
                    return selected_catalog['name']
                else:
                    print(f"Invalid choice. Please enter a number between 1 and {len(catalogs)}")
                    
            except ValueError:
                print("Invalid input. Please enter a valid number or 'q' to quit")
            except KeyboardInterrupt:
                print("\nExiting.")
                sys.exit(0)
