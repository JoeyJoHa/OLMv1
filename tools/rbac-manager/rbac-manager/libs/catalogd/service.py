"""
Catalogd Service

High-level service for catalogd operations including catalog listing and querying.
"""

import json
import logging
import sys
from typing import Dict, List, Any, Optional

from kubernetes import client
from kubernetes.client.rest import ApiException

from ..core.exceptions import CatalogdError, AuthenticationError
from ..core.utils import is_output_piped
from .client import CatalogdClient
from .parser import NDJSONParser

logger = logging.getLogger(__name__)


class CatalogdService:
    """High-level service for catalogd operations"""
    
    def __init__(self, core_api: client.CoreV1Api = None, custom_api: client.CustomObjectsApi = None, 
                 skip_tls: bool = False, debug: bool = False):
        """
        Initialize catalogd service
        
        Args:
            core_api: Kubernetes CoreV1Api client
            custom_api: Kubernetes CustomObjectsApi client
            skip_tls: Whether to skip TLS verification
            debug: Enable debug logging
        """
        self.core_api = core_api
        self.custom_api = custom_api
        self.skip_tls = skip_tls
        self.debug = debug
        
        # Initialize client and parser
        self.client = CatalogdClient(core_api, skip_tls) if core_api else None
        self.parser = NDJSONParser()
    
    def list_cluster_catalogs(self) -> List[Dict[str, Any]]:
        """
        List all ClusterCatalogs from Kubernetes API
        
        Returns:
            List of ClusterCatalog objects with enhanced information
            
        Raises:
            CatalogdError: If listing fails
        """
        if not self.custom_api:
            raise CatalogdError("Kubernetes client not available. Please ensure kubeconfig is properly configured or use --openshift-url and --openshift-token flags.")
        
        try:
            logger.info("Fetching ClusterCatalogs from the cluster...")
            cluster_catalogs = self.custom_api.list_cluster_custom_object(
                group="olm.operatorframework.io",
                version="v1",
                plural="clustercatalogs"
            )
            
            logger.info(f"Found {len(cluster_catalogs.get('items', []))} ClusterCatalogs")
            return cluster_catalogs.get('items', [])
            
        except ApiException as e:
            error_msg = str(e).lower()
            if any(keyword in error_msg for keyword in ["certificate verify failed", "ssl", "certificate", "tls", "handshake"]):
                raise CatalogdError(
                    "SSL certificate verification failed. This cluster appears to use self-signed certificates. "
                    "Please use the --skip-tls flag to bypass certificate verification."
                )
            if "unauthorized" in error_msg or "401" in error_msg:
                raise AuthenticationError(
                    "Unauthorized (401). Verify that your token is valid and has permissions. "
                    "If passing via shell, ensure correct syntax (zsh/bash: $TOKEN, PowerShell: $env:TOKEN)."
                )
            logger.error(f"Failed to list ClusterCatalogs: {e}")
            raise CatalogdError(f"Failed to list ClusterCatalogs: {e}")
        except Exception as e:
            error_msg = str(e).lower()
            if any(keyword in error_msg for keyword in ["certificate verify failed", "ssl", "certificate", "tls", "handshake", "verify failed"]):
                raise CatalogdError(
                    "SSL certificate verification failed. This cluster appears to use self-signed certificates. "
                    "Please use the --skip-tls flag to bypass certificate verification."
                )
            if "unauthorized" in error_msg or "401" in error_msg:
                raise AuthenticationError(
                    "Unauthorized (401). Verify that your token is valid and has permissions. "
                    "If passing via shell, ensure correct syntax (zsh/bash: $TOKEN, PowerShell: $env:TOKEN)."
                )
            logger.error(f"Failed to list ClusterCatalogs: {e}")
            raise CatalogdError(f"Failed to list ClusterCatalogs: {e}")
    
    def display_catalogs_enhanced(self) -> int:
        """
        Display ClusterCatalogs with enhanced formatting
        
        Returns:
            int: Exit code (0 for success, 1 for error)
        """
        try:
            catalogs = self.list_cluster_catalogs()
            
            if not catalogs:
                print("No ClusterCatalogs found in this cluster.")
                return 0
            
            # Prepare catalog data for output
            catalog_data = []
            for catalog in catalogs:
                name = catalog.get('metadata', {}).get('name', 'Unknown')
                
                # Determine serving status
                status = catalog.get('status', {})
                conditions = status.get('conditions', [])
                serving = False
                
                for condition in conditions:
                    if condition.get('type') == 'Serving' and condition.get('status') == 'True':
                        serving = True
                        break
                
                # Get creation timestamp and calculate age
                creation_timestamp = catalog.get('metadata', {}).get('creationTimestamp')
                age = self._calculate_age(creation_timestamp) if creation_timestamp else 'Unknown'
                
                catalog_info = {
                    'name': name,
                    'serving': serving,
                    'age': age,
                    'status': 'Serving' if serving else 'Not Serving'
                }
                catalog_data.append(catalog_info)
            
            # Output format depends on whether output is piped
            if is_output_piped():
                # JSON output for piping
                print(json.dumps(catalog_data, indent=2))
            else:
                # Human-readable output
                print(f"\nFound {len(catalog_data)} ClusterCatalog(s):")
                print("-" * 60)
                print(f"{'NAME':<30} {'STATUS':<15} {'AGE':<15}")
                print("-" * 60)
                
                for catalog in catalog_data:
                    status_symbol = "✓" if catalog['serving'] else "✗"
                    print(f"{catalog['name']:<30} {status_symbol} {catalog['status']:<14} {catalog['age']:<15}")
                
                print("-" * 60)
                serving_count = sum(1 for c in catalog_data if c['serving'])
                print(f"Total: {len(catalog_data)} catalogs ({serving_count} serving)")
            
            return 0
            
        except Exception as e:
            logger.error(f"Failed to display ClusterCatalogs: {e}")
            print(f"Error listing ClusterCatalogs: {e}", file=sys.stderr)
            return 1
    
    def query_catalog_data(self, catalog_name: str, auth_headers: Dict[str, str] = None) -> List[Dict[str, Any]]:
        """
        Query catalog data from catalogd service
        
        Args:
            catalog_name: Name of the catalog to query
            auth_headers: Authentication headers
            
        Returns:
            List of parsed catalog items
            
        Raises:
            CatalogdError: If query fails
        """
        if not self.client:
            raise CatalogdError("Catalogd client not available. Ensure Kubernetes client is initialized.")
        
        try:
            # Create port-forward to catalogd service
            port_forward_manager, port, is_https = self.client.create_port_forward()
            
            try:
                # Make request to catalogd API
                url = f"/catalogs/{catalog_name}/api/v1/all"
                logger.info(f"Fetching catalog data for: {catalog_name}")
                logger.debug(f"Making request to: {url}")
                
                response_body = self.client.make_catalogd_request(url, port_forward_manager, auth_headers)
                
                # Parse NDJSON response
                items = self.parser.parse_stream(response_body)
                return items
                
            finally:
                port_forward_manager.stop()
                
        except Exception as e:
            raise CatalogdError(f"Failed to query catalog data: {e}")
    
    def get_catalog_packages(self, catalog_name: str, auth_headers: Dict[str, str] = None) -> List[str]:
        """
        Get list of packages in a catalog
        
        Args:
            catalog_name: Name of the catalog
            auth_headers: Authentication headers
            
        Returns:
            List of package names
        """
        items = self.query_catalog_data(catalog_name, auth_headers)
        return self.parser.extract_packages(items)
    
    def get_package_channels(self, catalog_name: str, package_name: str, 
                           auth_headers: Dict[str, str] = None) -> List[str]:
        """
        Get list of channels for a package
        
        Args:
            catalog_name: Name of the catalog
            package_name: Name of the package
            auth_headers: Authentication headers
            
        Returns:
            List of channel names
        """
        items = self.query_catalog_data(catalog_name, auth_headers)
        return self.parser.extract_channels(items, package_name)
    
    def get_channel_versions(self, catalog_name: str, package_name: str, channel_name: str,
                           auth_headers: Dict[str, str] = None) -> List[str]:
        """
        Get list of versions for a package channel
        
        Args:
            catalog_name: Name of the catalog
            package_name: Name of the package
            channel_name: Name of the channel
            auth_headers: Authentication headers
            
        Returns:
            List of version names
        """
        items = self.query_catalog_data(catalog_name, auth_headers)
        return self.parser.extract_versions(items, package_name, channel_name)
    
    def get_version_metadata(self, catalog_name: str, package_name: str, channel_name: str, 
                           version: str, auth_headers: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Get metadata for a specific version
        
        Args:
            catalog_name: Name of the catalog
            package_name: Name of the package
            channel_name: Name of the channel
            version: Version to get metadata for
            auth_headers: Authentication headers
            
        Returns:
            Bundle metadata dictionary
        """
        items = self.query_catalog_data(catalog_name, auth_headers)
        return self.parser.find_bundle_by_version(items, package_name, channel_name, version)
    
    def _calculate_age(self, creation_timestamp: str) -> str:
        """
        Calculate age from creation timestamp
        
        Args:
            creation_timestamp: ISO format timestamp
            
        Returns:
            Human-readable age string
        """
        try:
            from datetime import datetime, timezone
            
            # Parse the timestamp
            created = datetime.fromisoformat(creation_timestamp.replace('Z', '+00:00'))
            now = datetime.now(timezone.utc)
            
            # Calculate age
            age_delta = now - created
            days = age_delta.days
            hours = age_delta.seconds // 3600
            minutes = (age_delta.seconds % 3600) // 60
            
            if days > 0:
                return f"{days}d"
            elif hours > 0:
                return f"{hours}h"
            else:
                return f"{minutes}m"
                
        except Exception:
            return "Unknown"
