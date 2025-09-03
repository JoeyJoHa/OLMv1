"""
ClusterCatalog API Query Library.

This module provides ClusterCatalog API querying functionality with caching
and improved error handling.
"""

import logging
import requests
import urllib3
from typing import Dict, List, Optional

# Import shared RBAC utilities
from . import rbac_utils

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
        
        data = response.json()
        
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
    

