"""
OPM Client

Handles low-level OPM binary operations and bundle extraction.
"""

import base64
import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional, List

from ..core.exceptions import OPMError, BundleProcessingError
from ..core.utils import validate_image_url
from ..core.constants import OPMConstants, ErrorMessages, NetworkConstants, KubernetesConstants

logger = logging.getLogger(__name__)


class OPMClient:
    """Low-level client for OPM binary operations"""
    
    def __init__(self, skip_tls: bool = False, debug: bool = False):
        """
        Initialize OPM client
        
        Args:
            skip_tls: Whether to skip TLS verification
            debug: Enable debug logging
        """
        self.skip_tls = skip_tls
        self.debug = debug
        self.logger = logger
        self._opm_binary = None
    
    def _find_opm_binary(self) -> str:
        """
        Find OPM binary in system PATH
        
        Returns:
            str: Path to OPM binary
            
        Raises:
            OPMError: If OPM binary not found
        """
        if self._opm_binary:
            return self._opm_binary
        
        try:
            # Try to find opm in PATH
            result = subprocess.run(['which', 'opm'], capture_output=True, text=True)
            if result.returncode == 0:
                self._opm_binary = result.stdout.strip()
                logger.debug(f"Found OPM binary at: {self._opm_binary}")
                return self._opm_binary
        except Exception:
            pass
        
        # Try common locations
        common_paths = [
            '/usr/local/bin/opm',
            '/usr/bin/opm',
            './opm',
            'opm'
        ]
        
        for path in common_paths:
            try:
                result = subprocess.run([path, 'version'], capture_output=True, text=True)
                if result.returncode == 0:
                    self._opm_binary = path
                    logger.debug(f"Found OPM binary at: {self._opm_binary}")
                    return self._opm_binary
            except Exception:
                continue
        
        raise OPMError(ErrorMessages.OPM_BINARY_NOT_FOUND)
    
    def validate_image(self, image: str) -> bool:
        """
        Validate if image is accessible and is a valid bundle/index
        
        Args:
            image: Container image URL
            
        Returns:
            bool: True if image is valid
            
        Raises:
            BundleProcessingError: If image validation fails
        """
        try:
            validate_image_url(image)
            
            opm_binary = self._find_opm_binary()
            
            # For bundle images, use 'opm render' to validate
            cmd = [opm_binary, 'render', image]
            
            if self.skip_tls:
                cmd.extend(['--skip-tls-verify'])
            
            logger.debug(f"Validating bundle image with command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=NetworkConstants.PORT_FORWARD_TIMEOUT
            )
            
            if result.returncode == 0:
                # Check if we got valid JSON output
                if not result.stdout.strip():
                    raise BundleProcessingError(f"No output from opm render for image: {image}")
                logger.debug(f"Bundle image validation successful: {image}")
                return True
            else:
                logger.debug(f"Bundle image validation failed: {result.stderr}")
                raise BundleProcessingError(f"Image validation failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            raise BundleProcessingError(f"Image validation timed out for: {image}")
        except Exception as e:
            raise BundleProcessingError(f"Failed to validate image {image}: {e}")
    
    def is_index_image(self, image: str) -> bool:
        """
        Check if image is an index image (contains multiple bundles)
        
        Args:
            image: Container image URL
            
        Returns:
            bool: True if image is an index image
        """
        try:
            opm_binary = self._find_opm_binary()
            
            # List bundles in the image
            cmd = [opm_binary, 'alpha', 'list', 'bundles', image]
            
            if self.skip_tls:
                cmd.extend(['--use-http'])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Count number of bundles
                bundles = result.stdout.strip().split('\n')
                bundle_count = len([b for b in bundles if b.strip()])
                
                logger.debug(f"Found {bundle_count} bundles in image")
                return bundle_count > 1
            
            return False
            
        except Exception as e:
            logger.debug(f"Failed to check if image is index: {e}")
            return False
    
    def extract_bundle_metadata(self, image: str, registry_token: str = None) -> Dict[str, Any]:
        """
        Extract bundle metadata from container image using OPM render
        
        Args:
            image: Container image URL
            registry_token: Registry authentication token (optional)
            
        Returns:
            Dict containing bundle metadata with decoded manifests
            
        Raises:
            BundleProcessingError: If extraction fails
        """
        try:
            validate_image_url(image)
            opm_binary = self._find_opm_binary()
            
            # Use opm render to get JSON output
            cmd = [opm_binary, 'render', image]
            
            if self.skip_tls:
                cmd.extend(['--skip-tls-verify'])
            
            # Set up environment for registry authentication
            env = {}
            if registry_token:
                with tempfile.TemporaryDirectory() as temp_dir:
                    env['REGISTRY_AUTH_FILE'] = self._create_auth_file(registry_token, Path(temp_dir))
            
            logger.debug(f"Rendering bundle with command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=NetworkConstants.BUNDLE_EXTRACTION_TIMEOUT,
                env={**subprocess.os.environ, **env} if env else None
            )
            
            if result.returncode != 0:
                raise BundleProcessingError(f"Failed to render bundle: {result.stderr}")
            
            # Parse the JSON output (multiple JSON objects, one per line)
            metadata = self._parse_opm_render_output(result.stdout)
            metadata['image'] = image
            
            logger.info(f"Successfully extracted bundle metadata from: {image}")
            return metadata
                
        except subprocess.TimeoutExpired:
            raise BundleProcessingError(f"Bundle extraction timed out for: {image}")
        except Exception as e:
            if isinstance(e, BundleProcessingError):
                raise
            raise BundleProcessingError(f"Failed to extract bundle metadata: {e}")
    
    def _create_auth_file(self, registry_token: str, temp_path: Path) -> str:
        """
        Create registry authentication file
        
        Args:
            registry_token: Registry authentication token
            temp_path: Temporary directory path
            
        Returns:
            str: Path to auth file
        """
        auth_file = temp_path / "auth.json"
        
        # Create basic auth file structure
        auth_data = {
            "auths": {
                "registry.redhat.io": {
                    "auth": registry_token
                },
                "quay.io": {
                    "auth": registry_token
                }
            }
        }
        
        with open(auth_file, 'w') as f:
            json.dump(auth_data, f)
        
        return str(auth_file)
    
    def _parse_opm_render_output(self, output: str) -> Dict[str, Any]:
        """
        Parse opm render output (NDJSON format) and decode base64 manifests
        
        Args:
            output: Raw output from opm render command
            
        Returns:
            Dict containing parsed bundle metadata with decoded manifests
            
        Raises:
            BundleProcessingError: If parsing fails
        """
        try:
            bundle_metadata = {
                'name': None,
                'version': None,
                'package': None,
                'manifests': {},
                OPMConstants.BUNDLE_PERMISSIONS_KEY: [],
                OPMConstants.BUNDLE_CLUSTER_PERMISSIONS_KEY: [],
                'csv_metadata': {},
                'csv_crds': [],
                'api_groups': [],
                '_raw_bundle_data': []
            }
            
                # Parse the single JSON object from opm render output
            try:
                obj = json.loads(output.strip())
                logger.debug(f"Successfully parsed JSON object from opm render output")
                
                # Store raw bundle data for bundle object extraction
                bundle_metadata['_raw_bundle_data'] = [obj]
                
                schema = obj.get('schema')
                
                if schema == OPMConstants.OLM_BUNDLE_SCHEMA:
                    # Extract basic bundle information
                    bundle_metadata['name'] = obj.get('name')
                    bundle_metadata['package'] = obj.get('package')
                    bundle_metadata['image'] = obj.get('image')
                    
                    # Process properties to extract manifests and API groups
                    properties = obj.get('properties', [])
                    for prop in properties:
                        if prop.get('type') == OPMConstants.OLM_GVK_PROPERTY:
                            # Extract API group information
                            gvk_data = prop.get('value', {})
                            api_group = gvk_data.get('group')
                            if api_group and api_group not in bundle_metadata['api_groups']:
                                bundle_metadata['api_groups'].append(api_group)
                        
                        elif prop.get('type') == OPMConstants.OLM_BUNDLE_OBJECT_PROPERTY:
                            # Decode base64 data to get the actual Kubernetes manifest
                            encoded_data = prop.get('value', {}).get('data', '')
                            if encoded_data:
                                try:
                                    decoded_data = base64.b64decode(encoded_data).decode('utf-8')
                                    manifest = json.loads(decoded_data)
                                    
                                    # Store manifest by kind
                                    kind = manifest.get('kind')
                                    if kind:
                                        bundle_metadata['manifests'][kind] = manifest
                                        
                                        # Extract specific data based on manifest type
                                        if kind == OPMConstants.CLUSTER_SERVICE_VERSION_KIND:
                                            self._extract_csv_data(manifest, bundle_metadata)
                                        elif kind == OPMConstants.CUSTOM_RESOURCE_DEFINITION_KIND:
                                            # CRD manifests are now handled via CSV spec.customresourcedefinitions.owned
                                            pass
                                            
                                except (base64.binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as e:
                                    logger.warning(f"Failed to decode manifest data: {e}")
                                    continue
                        
                        elif prop.get('type') == OPMConstants.OLM_PACKAGE_PROPERTY:
                            # Extract package metadata
                            package_data = prop.get('value', {})
                            bundle_metadata['package'] = package_data.get('packageName')
                            bundle_metadata['package_name'] = package_data.get('packageName')  # For consistency
                            bundle_metadata['version'] = package_data.get('version')
                            
            except json.JSONDecodeError as e:
                raise BundleProcessingError(f"Failed to parse JSON from opm render output: {e}")
            
            # Validate that we got essential data
            if not bundle_metadata.get('name'):
                raise BundleProcessingError("No bundle name found in opm render output")
            
            if not bundle_metadata.get('manifests'):
                raise BundleProcessingError("No manifests found in bundle")
            
            logger.debug(f"Successfully parsed bundle: {bundle_metadata.get('name')}")
            return bundle_metadata
            
        except Exception as e:
            raise BundleProcessingError(f"Failed to parse opm render output: {e}")
    
    def _extract_csv_data(self, csv_manifest: Dict[str, Any], bundle_metadata: Dict[str, Any]) -> None:
        """
        Extract data from ClusterServiceVersion manifest
        
        Args:
            csv_manifest: The CSV manifest dictionary
            bundle_metadata: Bundle metadata dictionary to update
        """
        try:
            spec = csv_manifest.get(OPMConstants.CSV_SPEC_SECTION, {})
            metadata = csv_manifest.get(OPMConstants.CSV_METADATA_SECTION, {})
            
            # Extract CSV metadata
            bundle_metadata['csv_metadata'] = {
                'name': metadata.get('name'),
                'display_name': spec.get('displayName'),
                'description': spec.get('description'),
                'version': spec.get('version'),
                'provider': spec.get('provider', {}).get('name'),
                'maintainers': spec.get('maintainers', []),
                'keywords': spec.get('keywords', []),
                'links': spec.get('links', []),
                'maturity': spec.get('maturity'),
                'install_modes': spec.get('installModes', [])
            }
            
            # Extract install section data
            install_section = spec.get(OPMConstants.CSV_INSTALL_SECTION, {})
            install_spec = install_section.get(OPMConstants.CSV_SPEC_SECTION, {})
            
            # Extract deployment information for installer permissions
            deployments = install_spec.get(OPMConstants.CSV_DEPLOYMENTS_SECTION, [])
            bundle_metadata[OPMConstants.CSV_DEPLOYMENTS_SECTION] = deployments
            
            # Bundle objects will be processed by the processor layer
            
            # Extract RBAC permissions
            
            # Namespace-scoped permissions
            permissions = install_spec.get(OPMConstants.CSV_PERMISSIONS_SECTION, [])
            for perm in permissions:
                bundle_metadata[OPMConstants.BUNDLE_PERMISSIONS_KEY].append({
                    'service_account': perm.get('serviceAccountName', KubernetesConstants.DEFAULT_NAMESPACE),
                    'rules': perm.get('rules', [])
                })
            
            # Cluster-scoped permissions
            cluster_permissions = install_spec.get(OPMConstants.CSV_CLUSTER_PERMISSIONS_SECTION, [])
            for perm in cluster_permissions:
                bundle_metadata[OPMConstants.BUNDLE_CLUSTER_PERMISSIONS_KEY].append({
                    'service_account': perm.get('serviceAccountName', KubernetesConstants.DEFAULT_NAMESPACE),
                    'rules': perm.get('rules', [])
                })
            
            # Extract CRDs from CSV spec
            crd_definitions = spec.get(OPMConstants.CSV_CRD_SECTION, {})
            owned_crds = crd_definitions.get(OPMConstants.CSV_OWNED_CRDS_SECTION, [])
            for crd in owned_crds:
                crd_name = crd.get('name')
                if crd_name:
                    bundle_metadata['csv_crds'].append({
                        'name': crd_name,
                        'kind': crd.get('kind'),
                        'version': crd.get('version'),
                        'description': crd.get('description', ''),
                        'displayName': crd.get('displayName', '')
                    })
                
        except Exception as e:
            logger.warning(f"Failed to extract CSV data: {e}")
