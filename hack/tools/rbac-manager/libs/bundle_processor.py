"""
Bundle Processor Module.

This module provides functionality to process bundle images using OPM render,
extract ClusterServiceVersion (CSV) manifests, and parse RBAC permissions
from the CSV specifications.

This module implements the core bundle processing logic that bridges the gap
between bundle image discovery and RBAC resource conversion.
"""

import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

import yaml

from .data_models import BundleData, CSVManifest, RBACData, dict_to_rbac_data, dict_to_permission_sets, PermissionSet, PermissionRule

# Set up module logger
logger = logging.getLogger(__name__)


# ============================================================================
# BUNDLE DISCOVERY (Moved from catalog_query.py)
# ============================================================================

class BundleDiscoveryError(Exception):
    """Custom exception for bundle discovery errors."""
    pass


class BundleDiscovery:
    """
    Discovers bundle image URLs from various catalog sources.
    
    This class handles the discovery of bundle image URLs from:
    - Catalogd API endpoints
    - Catalog index images via OPM
    
    It implements filtering logic equivalent to jq queries to identify
    bundles compatible with OLMv1 and specific package requirements.
    """
    
    def __init__(self):
        """Initialize the bundle discovery service."""
        self.logger = logging.getLogger(__name__)
        
    def get_bundle_images_from_catalogd(self, 
                                       catalog_api,  # Type hint removed to avoid circular import
                                       package_name: str, 
                                       catalog_name: str) -> List[Dict[str, Any]]:
        """
        Get bundle images for a package from catalogd API.
        
        Implements jq logic equivalent to:
        jq -s '.[] | select(.schema == "olm.bundle" and 
                           any(.properties[] ; .type == "olm.package" and 
                               .value.packageName == "package_name")) | 
                    {name, image, SupportAllNamespaces: ...}'
        
        Args:
            catalog_api: Initialized CatalogAPIQueryLib instance
            package_name: Name of the package to search for
            catalog_name: Name of the catalog to query
            
        Returns:
            List of bundle information dictionaries containing:
            - name: Bundle name
            - image: Bundle image URL (the key information needed)
            - package: Package name
            - supportsAllNamespaces: Boolean indicating AllNamespaces support
            - properties: Raw bundle properties
            
        Raises:
            BundleDiscoveryError: If catalog query fails or no bundles found
        """
        self.logger.info(f"Discovering bundle images for package '{package_name}' in catalog '{catalog_name}'")
        
        try:
            # Get all catalog entries using the correct method name
            entries = catalog_api.get_all_entries(catalog_name)
        except Exception as e:
            raise BundleDiscoveryError(f"Failed to fetch catalog entries from '{catalog_name}': {e}")
        
        if not entries:
            raise BundleDiscoveryError(f"No entries found in catalog '{catalog_name}'")
        
        bundle_entries = []
        
        for entry in entries:
            # Filter: schema == "olm.bundle" 
            if entry.get('schema') != 'olm.bundle':
                continue
                
            # Filter: has olm.package property with matching packageName
            properties = entry.get('properties', [])
            package_match = False
            
            for prop in properties:
                if (prop.get('type') == 'olm.package' and
                    prop.get('value', {}).get('packageName') == package_name):
                    package_match = True
                    break
            
            if not package_match:
                continue
                
            # Extract bundle information
            bundle_info = {
                'name': entry.get('name', 'unknown'),
                'image': entry.get('image'),  # This is the bundle image URL we need!
                'package': package_name,
                'supportsAllNamespaces': False,  # Default value
                'properties': properties
            }
            
            # Extract AllNamespaces support info from CSV metadata
            bundle_info['supportsAllNamespaces'] = self._extract_all_namespaces_support(properties)
            
            # Only include bundles with valid image URLs
            if bundle_info['image']:
                bundle_entries.append(bundle_info)
                self.logger.debug(f"Found bundle: {bundle_info['name']} -> {bundle_info['image']}")
            else:
                self.logger.warning(f"Bundle '{bundle_info['name']}' has no image URL, skipping")
        
        if not bundle_entries:
            raise BundleDiscoveryError(f"No bundle images found for package '{package_name}' in catalog '{catalog_name}'")
        
        self.logger.info(f"Found {len(bundle_entries)} bundle image(s) for package '{package_name}'")
        return bundle_entries
    
    def get_bundle_images_from_catalog_index(self,
                                           opm_lib,  # Type hint removed to avoid circular import
                                           catalog_image: str,
                                           package_name: str) -> List[str]:
        """
        Extract bundle image URLs from catalog index image using OPM.
        
        This method uses OPM to render a catalog index image and extract
        bundle image URLs for a specific package.
        
        Args:
            opm_lib: Initialized OPMQueryLib instance
            catalog_image: Catalog index image URL
            package_name: Name of the package to search for
            
        Returns:
            List of bundle image URLs
            
        Raises:
            BundleDiscoveryError: If OPM operations fail or no bundles found
        """
        self.logger.info(f"Discovering bundle images for package '{package_name}' from catalog index '{catalog_image}'")
        
        try:
            catalog_entries = opm_lib.render_catalog(catalog_image)
        except Exception as e:
            raise BundleDiscoveryError(f"Failed to render catalog index '{catalog_image}': {e}")
        
        bundle_images = []
        
        for entry in catalog_entries:
            # Filter for bundle entries matching our package
            if entry.get('schema') == 'olm.bundle':
                # Check if this bundle belongs to our target package
                properties = entry.get('properties', [])
                for prop in properties:
                    if (prop.get('type') == 'olm.package' and 
                        prop.get('value', {}).get('packageName') == package_name):
                        
                        image_url = entry.get('image')
                        if image_url:
                            bundle_images.append(image_url)
                            self.logger.debug(f"Found bundle image: {image_url}")
                        break
        
        if not bundle_images:
            raise BundleDiscoveryError(f"No bundle images found for package '{package_name}' in catalog index '{catalog_image}'")
        
        self.logger.info(f"Found {len(bundle_images)} bundle image(s) for package '{package_name}'")
        return bundle_images
    
    def validate_bundle_url(self, bundle_url: str) -> str:
        """
        Validate and normalize bundle image URL.
        
        Handles various bundle URL formats:
        - registry.redhat.io/ubi8/operator:v1.0.0
        - registry.redhat.io/ubi8/operator@sha256:abc123...
        - quay.io/namespace/bundle:latest
        
        Args:
            bundle_url: Raw bundle image URL
            
        Returns:
            Normalized and validated bundle URL
            
        Raises:
            BundleDiscoveryError: If URL format is invalid
        """
        if not bundle_url or not isinstance(bundle_url, str):
            raise BundleDiscoveryError(f"Invalid bundle URL: {bundle_url}")
        
        bundle_url = bundle_url.strip()
        
        # Basic format validation
        if not ('/' in bundle_url and len(bundle_url.split('/')) >= 2):
            raise BundleDiscoveryError(f"Invalid bundle URL format: {bundle_url}")
        
        # Normalize URL - add :latest if no tag or digest
        if '@sha256:' not in bundle_url and ':' not in bundle_url.split('/')[-1]:
            bundle_url = f"{bundle_url}:latest"
            self.logger.debug(f"Added default tag: {bundle_url}")
        
        return bundle_url
    
    def _extract_all_namespaces_support(self, properties: List[Dict[str, Any]]) -> bool:
        """
        Extract AllNamespaces support information from bundle properties.
        
        Searches through bundle properties to find CSV metadata and determine
        if the operator supports AllNamespaces install mode.
        
        Args:
            properties: List of bundle properties from catalog entry
            
        Returns:
            True if AllNamespaces is supported, False otherwise
        """
        for prop in properties:
            if prop.get('type') == 'olm.csv.metadata':
                csv_metadata = prop.get('value', {})
                install_modes = csv_metadata.get('installModes', [])
                
                for mode in install_modes:
                    if mode.get('type') == 'AllNamespaces':
                        supported = mode.get('supported', False)
                        self.logger.debug(f"AllNamespaces support: {supported}")
                        return supported
        
        # Default to False if no explicit AllNamespaces mode found
        self.logger.debug("No AllNamespaces install mode found, defaulting to False")
        return False
    
    def get_bundle_summary(self, bundle_entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate a summary of discovered bundle information.
        
        Provides useful statistics and information about the discovered bundles
        for logging and user feedback.
        
        Args:
            bundle_entries: List of bundle information dictionaries
            
        Returns:
            Dictionary containing bundle summary information
        """
        if not bundle_entries:
            return {
                'total_bundles': 0,
                'all_namespaces_count': 0,
                'bundle_names': [],
                'unique_images': 0
            }
        
        all_namespaces_count = sum(1 for bundle in bundle_entries 
                                  if bundle.get('supportsAllNamespaces', False))
        
        bundle_names = [bundle.get('name', 'unknown') for bundle in bundle_entries]
        unique_images = len(set(bundle.get('image') for bundle in bundle_entries if bundle.get('image')))
        
        summary = {
            'total_bundles': len(bundle_entries),
            'all_namespaces_count': all_namespaces_count,
            'bundle_names': bundle_names,
            'unique_images': unique_images
        }
        
        self.logger.debug(f"Bundle summary: {summary}")
        return summary


class BundleProcessorError(Exception):
    """Custom exception for bundle processing errors."""
    pass


class BundleProcessor:
    """
    Processes bundle images to extract CSV and RBAC data.
    
    This class handles the execution of OPM render commands on bundle images,
    parses the resulting manifests, and extracts RBAC permissions from
    ClusterServiceVersion specifications.
    
    Features:
    - OPM render execution with proper error handling
    - YAML/JSON manifest parsing
    - CSV identification and extraction
    - RBAC permission parsing from CSV specs
    - Caching for expensive operations
    - Retry logic for network failures
    """
    
    def __init__(self, insecure: bool = False, cache_dir: Optional[Union[str, Path]] = None, registry_token: Optional[str] = None):
        """
        Initialize the bundle processor.
        
        Args:
            insecure: Skip TLS verification for image pulls
            cache_dir: Directory for caching bundle data (None to disable caching)
            registry_token: Optional registry authentication token for private images
        """
        self.insecure = insecure
        self.registry_token = registry_token
        self.logger = logging.getLogger(__name__)
        
        # Initialize cache
        self.bundle_cache = {}
        self.cache_dir = None
        if cache_dir:
            self.cache_dir = Path(cache_dir)
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            self.logger.info(f"Bundle caching enabled: {self.cache_dir}")
        
    def render_bundle_image(self, bundle_image_url: str, max_retries: int = 3) -> BundleData:
        """
        Render a specific bundle image using OPM render command with retry logic.
        
        Args:
            bundle_image_url: Complete bundle image URL 
                             (e.g., "registry.redhat.io/ubi8/prometheus-operator-bundle@sha256:abc123...")
            max_retries: Maximum number of retry attempts for network failures
        
        Returns:
            Parsed bundle content with CSV, CRDs, and other manifests
            
        Raises:
            BundleProcessorError: If bundle rendering fails after retries
        """
        # Check cache first
        if bundle_image_url in self.bundle_cache:
            self.logger.debug(f"Using cached bundle data for {bundle_image_url}")
            return self.bundle_cache[bundle_image_url]
        
        # Check persistent cache if enabled
        if self.cache_dir:
            cached_data = self._load_from_persistent_cache(bundle_image_url)
            if cached_data:
                self.bundle_cache[bundle_image_url] = cached_data
                return cached_data
        
        self.logger.info(f"Rendering bundle image: {bundle_image_url}")
        
        # Validate bundle URL format
        self._validate_bundle_url(bundle_image_url)
        
        # Attempt rendering with retry logic
        for attempt in range(max_retries):
            try:
                bundle_data = self._execute_opm_render(bundle_image_url)
                
                # Cache the successful result
                self.bundle_cache[bundle_image_url] = bundle_data
                if self.cache_dir:
                    self._save_to_persistent_cache(bundle_image_url, bundle_data)
                
                return BundleData.from_dict(bundle_data)
                
            except subprocess.TimeoutExpired:
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt  # Exponential backoff
                    self.logger.warning(f"Bundle render timeout (attempt {attempt + 1}/{max_retries}), "
                                      f"retrying in {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    raise BundleProcessorError(f"Bundle render timeout after {max_retries} attempts: {bundle_image_url}")
                    
            except subprocess.CalledProcessError as e:
                error_msg = e.stderr.strip() if e.stderr else str(e)
                
                # Handle specific error conditions
                if "manifest unknown" in error_msg.lower() or "not found" in error_msg.lower():
                    raise BundleProcessorError(f"Bundle image not found: {bundle_image_url}")
                elif "unauthorized" in error_msg.lower() or "access denied" in error_msg.lower():
                    raise BundleProcessorError(f"Access denied to bundle image: {bundle_image_url}")
                elif attempt < max_retries - 1 and "network" in error_msg.lower():
                    wait_time = 2 ** attempt
                    self.logger.warning(f"Network error (attempt {attempt + 1}/{max_retries}), "
                                      f"retrying in {wait_time}s: {error_msg}")
                    time.sleep(wait_time)
                else:
                    raise BundleProcessorError(f"Failed to render bundle {bundle_image_url}: {error_msg}")
            except Exception as e:
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    self.logger.warning(f"Unexpected error (attempt {attempt + 1}/{max_retries}), "
                                      f"retrying in {wait_time}s: {e}")
                    time.sleep(wait_time)
                else:
                    raise BundleProcessorError(f"Failed to render bundle {bundle_image_url}: {e}")
        
        # Should never reach here due to the loop structure
        raise BundleProcessorError(f"Unexpected failure after {max_retries} attempts")
    
    def extract_csv_from_bundle(self, bundle_data: Union[BundleData, Dict[str, Any]]) -> Optional[CSVManifest]:
        """
        Extract ClusterServiceVersion from bundle data.
        
        The CSV contains the actual RBAC permissions in:
        - spec.install.spec.permissions (namespace-scoped)
        - spec.install.spec.clusterPermissions (cluster-scoped)
        
        Args:
            bundle_data: Parsed bundle data from render_bundle_image() (BundleData or dict)
            
        Returns:
            ClusterServiceVersion manifest as CSVManifest, or None if not found
        """
        # Handle both BundleData objects and legacy dict format
        if isinstance(bundle_data, BundleData):
            csv_manifest = bundle_data.get_csv()
            if csv_manifest:
                self.logger.debug(f"Found ClusterServiceVersion: {csv_manifest.name}")
            return csv_manifest
        
        # Handle both dataclass and dict for backward compatibility
        if hasattr(bundle_data, 'documents'):
            documents = bundle_data.documents
        else:
            documents = bundle_data.get('documents', []) if isinstance(bundle_data, dict) else []
        
        for doc in documents:
            if (doc.get('kind') == 'ClusterServiceVersion' and 
                doc.get('apiVersion', '').startswith('operators.coreos.com/')):
                
                csv_name = doc.get('metadata', {}).get('name', 'unknown')
                self.logger.debug(f"Found ClusterServiceVersion: {csv_name}")
                return CSVManifest.from_dict(doc)
        
        self.logger.warning("No ClusterServiceVersion found in bundle")
        return None
    
    def extract_rbac_from_csv(self, csv_data: Union[CSVManifest, Dict[str, Any]]) -> RBACData:
        """
        Extract RBAC permissions from ClusterServiceVersion.
        
        This is the core function that extracts the actual RBAC data from the CSV
        install strategy specifications.
        
        Args:
            csv_data: ClusterServiceVersion manifest (CSVManifest or dict)
            
        Returns:
            RBACData containing extracted RBAC data with typed structure
        """
        if not csv_data:
            raise BundleProcessorError("CSV data is None or empty")
        
        # Handle both CSVManifest objects and legacy dict format
        if isinstance(csv_data, CSVManifest):
            csv_dict = csv_data.to_dict()  # Returns raw_manifest data, not dataclass structure
        else:
            csv_dict = csv_data
        
        # Navigate to install strategy spec
        install_strategy = csv_dict.get('spec', {}).get('install', {})
        
        if install_strategy.get('strategy') != 'deployment':
            self.logger.warning(f"Unsupported install strategy: {install_strategy.get('strategy')}")
        
        install_spec = install_strategy.get('spec', {})
        
        # Extract RBAC permissions and convert to typed format
        permissions_data = install_spec.get('permissions', [])
        cluster_permissions_data = install_spec.get('clusterPermissions', [])
        deployments_data = install_spec.get('deployments', [])
        
        # Convert to typed permission sets
        permissions = dict_to_permission_sets(permissions_data)
        cluster_permissions = dict_to_permission_sets(cluster_permissions_data)
        
        # Extract service account name from deployments
        service_account_name = self._extract_service_account_name(deployments_data)
        
        # Create typed RBAC data
        rbac_data = RBACData(
            permissions=permissions,
            cluster_permissions=cluster_permissions,
            service_account_name=service_account_name,
            deployments=deployments_data
        )
        
        # Log extraction results
        perm_count = len(rbac_data.permissions)
        cluster_perm_count = len(rbac_data.cluster_permissions)
        deployment_count = len(rbac_data.deployments)
        
        self.logger.info(f"Extracted RBAC: {perm_count} permission set(s), "
                        f"{cluster_perm_count} cluster permission set(s), "
                        f"{deployment_count} deployment(s)")
        
        if rbac_data.service_account_name:
            self.logger.debug(f"Service account: {rbac_data.service_account_name}")
        
        return rbac_data
    
    def get_bundle_manifest_summary(self, bundle_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a summary of bundle manifest contents.
        
        Provides useful information about what manifests are included in the bundle
        for debugging and analysis purposes.
        
        Args:
            bundle_data: Parsed bundle data from render_bundle_image()
            
        Returns:
            Summary dictionary with manifest counts and types
        """
        # Handle both dataclass and dict for backward compatibility
        if hasattr(bundle_data, 'documents'):
            documents = bundle_data.documents
        else:
            documents = bundle_data.get('documents', []) if isinstance(bundle_data, dict) else []
        
        kind_counts = {}
        api_versions = set()
        
        for doc in documents:
            kind = doc.get('kind', 'Unknown')
            api_version = doc.get('apiVersion', 'Unknown')
            
            kind_counts[kind] = kind_counts.get(kind, 0) + 1
            api_versions.add(api_version)
        
        summary = {
            'total_documents': len(documents),
            'kind_counts': kind_counts,
            'api_versions': sorted(list(api_versions)),
            'has_csv': 'ClusterServiceVersion' in kind_counts,
            'has_crds': 'CustomResourceDefinition' in kind_counts
        }
        
        self.logger.debug(f"Bundle manifest summary: {summary}")
        return summary
    
    def _execute_opm_render(self, bundle_image_url: str) -> Dict[str, Any]:
        """
        Execute the OPM render command and parse output.
        
        Args:
            bundle_image_url: Bundle image URL to render
            
        Returns:
            Parsed bundle data
            
        Raises:
            subprocess.CalledProcessError: If OPM command fails
            subprocess.TimeoutExpired: If command times out
            BundleProcessorError: If output parsing fails
        """
        # Build OPM command
        cmd = ['opm', 'render', bundle_image_url]
        if self.insecure:
            cmd.extend(['--use-http'])
        
        self.logger.debug(f"Executing: {' '.join(cmd)}")
        
        # Set up environment for registry authentication
        env = os.environ.copy()
        if self.registry_token:
            # For registry authentication, OPM uses the container runtime (podman/docker)
            self.logger.debug("Setting up registry authentication for OPM")
            
            if self.registry_token == "discovered":
                # Credentials were discovered from standard locations
                # Let the container runtime (podman/docker) use them automatically
                self.logger.debug("Using discovered registry credentials via container runtime")
            else:
                # Explicit token provided - set up environment for OPM
                registry_host = self._extract_registry_host(bundle_image_url)
                if registry_host:
                    # Set up podman/docker credentials via environment
                    # This may need adjustment based on the registry authentication method
                    env['REGISTRY_AUTH'] = self.registry_token
                    self.logger.debug(f"Configured registry authentication for {registry_host}")
        
        # Execute with timeout
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=120,  # 2 minute timeout for bundle rendering
            check=True,
            env=env
        )
        
        # Parse the output
        try:
            bundle_data = self._parse_opm_output(result.stdout)
            documents_count = len(bundle_data.documents) if hasattr(bundle_data, 'documents') else len(bundle_data.get('documents', []) if isinstance(bundle_data, dict) else [])
            self.logger.debug(f"Successfully parsed {documents_count} manifest(s)")
            return bundle_data
        except Exception as e:
            raise BundleProcessorError(f"Failed to parse OPM output: {e}")
    
    def _extract_registry_host(self, image_url: str) -> str:
        """
        Extract registry hostname from image URL.
        
        Args:
            image_url: Container image URL
            
        Returns:
            Registry hostname or empty string if not found
        """
        try:
            # Handle various image URL formats:
            # registry.redhat.io/ubi8/cert-manager-bundle:v1.0.0
            # quay.io/prometheus-operator/prometheus-operator-bundle:v0.47.0  
            # private.registry.com/my-operator:latest
            # bundle@sha256:abcd1234...
            
            if '://' in image_url:
                # Remove protocol if present
                image_url = image_url.split('://', 1)[1]
            
            if '/' not in image_url:
                # No registry specified, likely using default (docker.io)
                return "docker.io"
            
            # Get the first part before the first slash
            registry_host = image_url.split('/')[0]
            
            # If it contains a dot or colon, it's likely a registry hostname
            if '.' in registry_host or ':' in registry_host:
                return registry_host
            
            # Otherwise, it's likely a Docker Hub username, so use docker.io
            return "docker.io"
            
        except Exception as e:
            self.logger.warning(f"Failed to extract registry host from {image_url}: {e}")
            return ""
    
    def _parse_opm_output(self, opm_output: str) -> Dict[str, Any]:
        """
        Parse OPM render output into structured data.
        
        OPM render outputs JSON with base64-encoded manifests in olm.bundle.object entries.
        Following the pattern from README.md:
        opm render [bundle] | jq -r '.properties[] | select(.type == "olm.bundle.object") | .value.data' | base64 -d
        
        Args:
            opm_output: Raw output from OPM render command
            
        Returns:
            Dictionary with parsed documents
        """
        if not opm_output.strip():
            raise BundleProcessorError("OPM output is empty")

        import base64
        documents = []
        
        try:
            # Parse the main JSON output from OPM render
            main_json = json.loads(opm_output)
            
            # Look for properties array containing olm.bundle.object entries
            if 'properties' not in main_json:
                raise BundleProcessorError("No 'properties' array found in OPM output")
            
            self.logger.debug(f"Found {len(main_json['properties'])} properties in OPM output")
            
            # Process each property looking for olm.bundle.object entries
            for i, prop in enumerate(main_json['properties']):
                if prop.get('type') == 'olm.bundle.object':
                    self.logger.debug(f"Processing olm.bundle.object property {i + 1}")
                    
                    # Extract base64-encoded data
                    if 'value' not in prop or 'data' not in prop['value']:
                        self.logger.warning(f"Property {i + 1}: Missing value.data field")
                        continue
                    
                    try:
                        # Decode base64 data
                        decoded_data = base64.b64decode(prop['value']['data']).decode('utf-8')
                        
                        # Parse the decoded YAML/JSON manifest
                        manifest = yaml.safe_load(decoded_data)
                        if manifest and isinstance(manifest, dict):
                            kind = manifest.get('kind', 'unknown')
                            api_version = manifest.get('apiVersion', 'unknown')
                            self.logger.debug(f"Decoded manifest: kind={kind}, apiVersion={api_version}")
                            documents.append(manifest)
                        else:
                            self.logger.warning(f"Property {i + 1}: Decoded data is not a valid manifest")
                            
                    except (base64.binascii.Error, UnicodeDecodeError) as e:
                        self.logger.warning(f"Property {i + 1}: Failed to decode base64 data: {e}")
                        continue
                    except yaml.YAMLError as e:
                        self.logger.warning(f"Property {i + 1}: Failed to parse YAML: {e}")
                        continue
                else:
                    self.logger.debug(f"Skipping property {i + 1} with type: {prop.get('type', 'unknown')}")
            
        except json.JSONDecodeError as e:
            raise BundleProcessorError(f"Failed to parse OPM JSON output: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error parsing OPM output: {e}")
            raise BundleProcessorError(f"Failed to parse OPM output: {e}")
        
        if not documents:
            raise BundleProcessorError("No valid manifests found in OPM output")
        
        self.logger.info(f"Successfully parsed {len(documents)} manifests from OPM output")
        return {'documents': documents}
    
    def _validate_bundle_url(self, bundle_url: str) -> None:
        """
        Validate bundle image URL format.
        
        Args:
            bundle_url: Bundle image URL to validate
            
        Raises:
            BundleProcessorError: If URL format is invalid
        """
        if not bundle_url or not isinstance(bundle_url, str):
            raise BundleProcessorError(f"Invalid bundle URL: {bundle_url}")
        
        bundle_url = bundle_url.strip()
        
        # Basic format validation
        if not ('/' in bundle_url and len(bundle_url.split('/')) >= 2):
            raise BundleProcessorError(f"Invalid bundle URL format: {bundle_url}")
    
    def _extract_service_account_name(self, deployments: List[Dict[str, Any]]) -> Optional[str]:
        """
        Extract service account name from deployment specifications.
        
        Args:
            deployments: List of deployment specifications from CSV
            
        Returns:
            Service account name if found, None otherwise
        """
        for deployment in deployments:
            try:
                container_spec = deployment.get('spec', {}).get('template', {}).get('spec', {})
                sa_name = container_spec.get('serviceAccountName')
                if sa_name:
                    self.logger.debug(f"Found service account: {sa_name}")
                    return sa_name
            except (TypeError, AttributeError) as e:
                self.logger.debug(f"Error parsing deployment spec: {e}")
                continue
        
        self.logger.debug("No service account name found in deployments")
        return None
    
    def _get_cache_key(self, bundle_image_url: str) -> str:
        """
        Generate cache key for bundle image URL.
        
        Args:
            bundle_image_url: Bundle image URL
            
        Returns:
            Safe filename for caching
        """
        import hashlib
        # Create a hash of the URL for safe filename
        url_hash = hashlib.sha256(bundle_image_url.encode()).hexdigest()[:16]
        # Include URL parts for readability
        safe_url = bundle_image_url.replace('/', '_').replace(':', '_').replace('@', '_')[:50]
        return f"{safe_url}_{url_hash}"
    
    def _load_from_persistent_cache(self, bundle_image_url: str) -> Optional[Dict[str, Any]]:
        """
        Load bundle data from persistent cache.
        
        Args:
            bundle_image_url: Bundle image URL
            
        Returns:
            Cached bundle data if available and fresh, None otherwise
        """
        if not self.cache_dir:
            return None
        
        cache_key = self._get_cache_key(bundle_image_url)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        if not cache_file.exists():
            return None
        
        try:
            # Check cache age (24 hours)
            cache_age = time.time() - cache_file.stat().st_mtime
            if cache_age > 86400:  # 24 hours in seconds
                self.logger.debug(f"Cache expired for {bundle_image_url}")
                return None
            
            # Load cached data
            with open(cache_file, 'r') as f:
                cached_data = json.load(f)
            
            self.logger.debug(f"Loaded bundle data from cache: {cache_file}")
            return cached_data
            
        except (json.JSONDecodeError, OSError) as e:
            self.logger.warning(f"Failed to load cache for {bundle_image_url}: {e}")
            return None
    
    def _save_to_persistent_cache(self, bundle_image_url: str, bundle_data: Dict[str, Any]) -> None:
        """
        Save bundle data to persistent cache.
        
        Args:
            bundle_image_url: Bundle image URL
            bundle_data: Bundle data to cache
        """
        if not self.cache_dir:
            return
        
        cache_key = self._get_cache_key(bundle_image_url)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        try:
            with open(cache_file, 'w') as f:
                json.dump(bundle_data, f, indent=2)
            
            self.logger.debug(f"Saved bundle data to cache: {cache_file}")
            
        except OSError as e:
            self.logger.warning(f"Failed to save cache for {bundle_image_url}: {e}")
