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

# Import core utilities
from .cli_interface import check_terminal_output, display_pipe_error_message

# Set up logger
logger = logging.getLogger(__name__)


def create_catalogd_discoverer(base_url: str, insecure: bool = False) -> 'CatalogAPIQueryLib':
    """
    Create a catalogd discoverer (simplified factory function).
    
    Args:
        base_url: Base URL for the catalog API
        insecure: Skip TLS verification
        
    Returns:
        Configured Catalog API query library
    """
    return CatalogAPIQueryLib(base_url=base_url, insecure=insecure)


def discover_bundles_via_catalogd(catalog_lib: 'CatalogAPIQueryLib', package_name: str, catalog_name: str = "operatorhubio") -> List[str]:
    """
    Simplified bundle discovery via catalogd API (replaces complex factory pattern).
    
    Args:
        catalog_lib: Configured CatalogAPIQueryLib instance
        package_name: Name of the package to search for
        catalog_name: Name of the catalog to query
        
    Returns:
        List of bundle image URLs
    """
    # This is a simplified version - in practice, this would extract bundle URLs from the API
    # For now, return empty list as catalogd bundle discovery needs more implementation
    logger.info(f"Catalogd bundle discovery for package '{package_name}' in catalog '{catalog_name}'")
    return []


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
        # Index for efficient data access by schema type
        self._entries_by_schema: Dict[str, List[Dict]] = {}
        
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
        
        # Cache the results and create index for future use
        self._catalog_cache[catalog_name] = data
        self._index_entries(data)
        
        logger.info(f"Retrieved, cached, and indexed {len(data)} catalog entries")
        return data
    
    def _index_entries(self, entries: List[Dict]) -> None:
        """
        Create an index of entries by their schema for faster lookups.
        
        This optimization eliminates the need for repeated full scans of the dataset
        when querying for specific schema types (e.g., 'olm.package', 'olm.bundle').
        
        Args:
            entries: List of catalog entries to index
        """
        self._entries_by_schema = {}
        for entry in entries:
            schema = entry.get('schema')
            if schema:
                if schema not in self._entries_by_schema:
                    self._entries_by_schema[schema] = []
                self._entries_by_schema[schema].append(entry)
        
        logger.debug(f"Indexed {len(entries)} entries across {len(self._entries_by_schema)} schema types")
    
    def clear_cache(self, catalog_name: Optional[str] = None) -> None:
        """
        Clear cached catalog data and indexes.
        
        Args:
            catalog_name: Specific catalog to clear, or None to clear all
        """
        if catalog_name:
            self._catalog_cache.pop(catalog_name, None)
            # Clear index when cache is cleared (will be rebuilt on next access)
            self._entries_by_schema.clear()
            logger.debug(f"Cleared cache and index for catalog: {catalog_name}")
        else:
            self._catalog_cache.clear()
            self._entries_by_schema.clear()
            logger.debug("Cleared all catalog cache and indexes")
    
    def list_packages(self, catalog_name: str = "operatorhubio") -> List[str]:
        """
        List all packages in catalog using the index.
        
        Args:
            catalog_name: Name of the catalog
            
        Returns:
            List of package names (sorted)
        """
        # Ensures data is loaded and indexed
        self.get_all_entries(catalog_name)
        
        # Use index for efficient lookup
        package_entries = self._entries_by_schema.get('olm.package', [])
        packages = sorted([entry['name'] for entry in package_entries if entry.get('name')])
        
        return packages
    
    def get_package_bundles(self, package_name: str, 
                          catalog_name: str = "operatorhubio") -> List[Dict]:
        """
        Get all bundles for a specific package using the index.
        
        Args:
            package_name: Name of the package
            catalog_name: Name of the catalog
            
        Returns:
            List of bundle entries
        """
        # Ensures data is loaded and indexed
        self.get_all_entries(catalog_name)
        
        # Use index for efficient lookup
        bundle_entries = self._entries_by_schema.get('olm.bundle', [])
        bundles = [entry for entry in bundle_entries if entry.get('package') == package_name]
        
        return bundles
    
    def _has_all_namespaces_support(self, csv_data: Dict) -> bool:
        """
        Check if CSV supports AllNamespaces install mode.
        
        Args:
            csv_data: CSV metadata
            
        Returns:
            True if AllNamespaces is supported
        """
        install_modes = csv_data.get('installModes', [])
        for mode in install_modes:
            if mode.get('type') == 'AllNamespaces' and mode.get('supported', False):
                return True
        return False
    
    def _has_webhooks(self, bundle_entry: Dict) -> bool:
        """
        Check if bundle has webhook definitions.
        
        Args:
            bundle_entry: Bundle entry data
            
        Returns:
            True if webhooks are defined
        """
        properties = bundle_entry.get('properties', [])
        for prop in properties:
            if prop.get('type') == 'olm.webhook':
                return True
        return False
    
    def _get_csv_metadata(self, bundle_entry: Dict) -> Optional[Dict]:
        """
        Extract CSV metadata from bundle entry.
        
        Args:
            bundle_entry: Bundle entry data
            
        Returns:
            CSV metadata or None if not found
        """
        properties = bundle_entry.get('properties', [])
        for prop in properties:
            if prop.get('type') == 'olm.csv.metadata':
                return prop.get('value', {})
        return None

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
    
    def get_package_metadata(self, package_name: str, 
                           catalog_name: str = "operatorhubio") -> Optional[Dict[str, Any]]:
        """
        Get comprehensive package metadata including versions, channels, and bundle URLs.
        
        This method extracts metadata needed for OPM bundle processing, not RBAC extraction.
        RBAC extraction will be done later using 'opm render <bundle-image-url>'.
        
        Args:
            package_name: Name of the package
            catalog_name: Name of the catalog
            
        Returns:
            Dict with package metadata:
            {
                'package_name': str,
                'channels': [{'name': str, 'entries': [{'name': str, 'version': str}]}],
                'bundles': [{'name': str, 'version': str, 'image': str, 'olmv1_compatible': bool}],
                'latest_version': str,
                'default_channel': str
            }
            Or None if package not found
        """
        entries = self.get_all_entries(catalog_name)
        
        # Find package entry first
        package_info = None
        for entry in entries:
            if (entry.get('schema') == 'olm.package' and 
                entry.get('name') == package_name):
                package_info = entry
                break
        
        if not package_info:
            logger.warning(f"Package '{package_name}' not found in catalog '{catalog_name}'")
            return None
        
        # Extract channels and versions
        channels_data = []
        for entry in entries:
            if (entry.get('schema') == 'olm.channel' and 
                entry.get('package') == package_name):
                
                channel_info = {
                    'name': entry.get('name'),
                    'entries': entry.get('entries', [])
                }
                channels_data.append(channel_info)
        
        # Extract bundle information with OLMv1 compatibility check
        bundles_data = []
        for entry in entries:
            if (entry.get('schema') == 'olm.bundle'):
                # Check if this bundle belongs to our package
                is_package_bundle = False
                for prop in entry.get('properties', []):
                    if (prop.get('type') == 'olm.package' and
                        prop.get('value', {}).get('packageName') == package_name):
                        is_package_bundle = True
                        break
                
                if is_package_bundle:
                    bundle_image = entry.get('image')
                    bundle_version = entry.get('name', 'unknown')
                    
                    # Check OLMv1 compatibility and get detailed info
                    olmv1_info = self._is_olmv1_compatible(entry)
                    olmv1_compatible = olmv1_info['compatible']
                    
                    bundle_info = {
                        'name': bundle_version,
                        'version': bundle_version.split('.')[-1] if '.' in bundle_version else bundle_version,
                        'image': bundle_image,
                        'olmv1_compatible': olmv1_compatible,
                        'olmv1_info': olmv1_info,
                        'full_entry': entry  # Include full entry for advanced processing
                    }
                    bundles_data.append(bundle_info)
        
        # Get default channel and latest version
        default_channel = package_info.get('defaultChannel', 'stable')
        
        # Find latest version from channels
        latest_version = 'unknown'
        if channels_data:
            for channel in channels_data:
                if channel['name'] == default_channel and channel['entries']:
                    # Get the last entry (usually latest)
                    latest_version = channel['entries'][-1].get('name', 'unknown')
                    break
        
        metadata = {
            'package_name': package_name,
            'catalog_name': catalog_name,
            'default_channel': default_channel,
            'latest_version': latest_version,
            'channels': channels_data,
            'bundles': bundles_data,
            'olmv1_compatible_bundles': [b for b in bundles_data if b.get('olmv1_info', {}).get('compatible', False)],
            'total_bundles': len(bundles_data),
            'compatible_bundles_count': len([b for b in bundles_data if b.get('olmv1_info', {}).get('compatible', False)])
        }
        
        logger.info(f"Package '{package_name}' metadata: {metadata['compatible_bundles_count']}/{metadata['total_bundles']} OLMv1 compatible bundles")
        return metadata
    
    def _is_olmv1_compatible(self, bundle_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check OLMv1 compatibility and extract detailed compatibility info.
        
        Args:
            bundle_entry: Bundle entry from catalog
            
        Returns:
            Dictionary with compatibility details: compatible, webhooks, installModes
        """
        compatibility_info = {
            'compatible': False,
            'has_webhooks': False,
            'install_modes': {},
            'all_namespaces_supported': False
        }
        
        properties = bundle_entry.get('properties', [])
        
        # Look for olm.csv.metadata property which indicates CSV presence
        for prop in properties:
            if prop.get('type') == 'olm.csv.metadata':
                csv_data = prop.get("value", {})
                compatibility_info['compatible'] = True
                
                # Check for webhooks
                webhooks = csv_data.get("webhookdefinitions", [])
                compatibility_info['has_webhooks'] = len(webhooks) > 0
                
                # Extract install modes
                install_modes = csv_data.get("installModes", [])
                for mode in install_modes:
                    mode_type = mode.get("type")
                    supported = mode.get("supported", False)
                    compatibility_info['install_modes'][mode_type] = supported
                    
                    if mode_type == "AllNamespaces" and supported:
                        compatibility_info['all_namespaces_supported'] = True
                
                break
        
        return compatibility_info
    
    def get_bundle_images_for_opm(self, package_name: str, 
                                catalog_name: str = "operatorhubio") -> List[str]:
        """
        Get bundle image URLs for a package that can be used with 'opm render'.
        
        This is the method that should be used for RBAC extraction workflow:
        1. Get bundle image URLs from this method
        2. Use 'opm render <bundle-image-url>' to get CSV
        3. Extract RBAC from CSV
        
        Args:
            package_name: Name of the package  
            catalog_name: Name of the catalog
            
        Returns:
            List of bundle image URLs suitable for 'opm render'
        """
        metadata = self.get_package_metadata(package_name, catalog_name)
        
        if not metadata:
            return []
        
        bundle_images = []
        compatible_bundles = [b for b in metadata.get('bundles', []) if b.get('olmv1_info', {}).get('compatible', False)]
        for bundle in compatible_bundles:
            image_url = bundle.get('image')
            if image_url:
                bundle_images.append(image_url)
        
        logger.info(f"Found {len(bundle_images)} OLMv1 compatible bundle images for package '{package_name}'")
        return bundle_images

    def get_package_channels(self, package_name: str, 
                           catalog_name: str = "operatorhubio") -> Optional[List[Dict[str, Any]]]:
        """
        Get only the channels for a package.
        
        Args:
            package_name: Name of the package
            catalog_name: Name of the catalog
            
        Returns:
            List of channel information dictionaries
        """
        try:
            entries = self.get_all_entries(catalog_name)
            
            # Find package entry
            package_entry = None
            for entry in entries:
                if (entry.get("schema") == "olm.package" and 
                    entry.get("name") == package_name):
                    package_entry = entry
                    break
            
            if not package_entry:
                logger.warning(f"Package '{package_name}' not found in catalog '{catalog_name}'")
                return None
            
            # Find channels for this package
            channels = []
            for entry in entries:
                if (entry.get("schema") == "olm.channel" and 
                    entry.get("package") == package_name):
                    channels.append({
                        'name': entry.get("name"),
                        'package': entry.get("package"),
                        'entries': entry.get("entries", [])
                    })
            
            logger.info(f"Found {len(channels)} channels for package '{package_name}'")
            return channels
            
        except Exception as e:
            logger.error(f"Error retrieving channels for package '{package_name}': {e}")
            return None

    def get_channel_versions(self, package_name: str, channel_name: str,
                           catalog_name: str = "operatorhubio") -> Optional[List[str]]:
        """
        Get all versions available in a specific channel.
        
        Args:
            package_name: Name of the package
            channel_name: Name of the channel
            catalog_name: Name of the catalog
            
        Returns:
            List of version names in the channel
        """
        try:
            entries = self.get_all_entries(catalog_name)
            
            # Find the specific channel
            for entry in entries:
                if (entry.get("schema") == "olm.channel" and 
                    entry.get("package") == package_name and
                    entry.get("name") == channel_name):
                    
                    versions = [e.get("name") for e in entry.get("entries", []) if e.get("name")]
                    logger.info(f"Found {len(versions)} versions in channel '{channel_name}' for package '{package_name}'")
                    return sorted(versions)
            
            logger.warning(f"Channel '{channel_name}' not found for package '{package_name}' in catalog '{catalog_name}'")
            return None
            
        except Exception as e:
            logger.error(f"Error retrieving versions for channel '{channel_name}': {e}")
            return None

    def get_version_metadata(self, package_name: str, version_name: str,
                           catalog_name: str = "operatorhubio") -> Optional[Dict[str, Any]]:
        """
        Get detailed metadata for a specific version.
        
        Args:
            package_name: Name of the package
            version_name: Name of the version
            catalog_name: Name of the catalog
            
        Returns:
            Dictionary with detailed version metadata
        """
        try:
            entries = self.get_all_entries(catalog_name)
            
            # Find the specific bundle for this version
            for entry in entries:
                if entry.get("schema") == "olm.bundle":
                    # Check if this bundle matches our package and version
                    for prop in entry.get("properties", []):
                        if (prop.get("type") == "olm.package" and 
                            prop.get("value", {}).get("packageName") == package_name and
                            (prop.get("value", {}).get("version") == version_name or
                             entry.get("name") == version_name)):
                            
                            # Extract CSV metadata if available
                            csv_metadata = None
                            for p in entry.get("properties", []):
                                if p.get("type") == "olm.csv.metadata":
                                    csv_metadata = p.get("value")
                                    break
                            
                            # Build detailed metadata with enhanced compatibility info
                            olmv1_info = self._is_olmv1_compatible(entry)
                            metadata = {
                                'name': entry.get("name"),
                                'package': package_name,
                                'version': version_name,
                                'image': entry.get("image"),
                                'schema': entry.get("schema"),
                                'olmv1_compatible': olmv1_info['compatible'],
                                'olmv1_info': olmv1_info,
                                'csv_metadata': csv_metadata,
                                'properties': entry.get("properties", []),
                                'related_images': entry.get("relatedImages", [])
                            }
                            
                            logger.info(f"Found detailed metadata for version '{version_name}' of package '{package_name}'")
                            return metadata
            
            logger.warning(f"Version '{version_name}' not found for package '{package_name}' in catalog '{catalog_name}'")
            return None
            
        except Exception as e:
            logger.error(f"Error retrieving metadata for version '{version_name}': {e}")
            return None


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
                logging.warning("No ClusterCatalogs found in this cluster")
                print("No ClusterCatalogs found in this cluster.")
                sys.exit(1)
            
            CatalogSelectionUI._display_catalog_table(catalogs)
            return CatalogSelectionUI._get_user_selection(catalogs)
            
        except Exception as e:
            logging.error(f"Error fetching ClusterCatalogs: {e}")
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


# ============================================================================
# BUNDLE DISCOVERY moved to bundle_processor.py
# ============================================================================
# BundleDiscovery class has been moved to bundle_processor.py for better
# organization - bundle discovery is more closely related to bundle processing
# than catalog querying.
