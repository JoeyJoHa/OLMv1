"""
OPM Client

Handles low-level OPM binary operations and bundle extraction.
"""

import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional

from ..core.exceptions import OPMError, BundleProcessingError
from ..core.utils import validate_image_url

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
        
        raise OPMError(
            "OPM binary not found. Please install the OPM CLI tool and ensure it's in your PATH. "
            "Visit: https://github.com/operator-framework/operator-registry/releases"
        )
    
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
            
            # Try to inspect the image
            cmd = [opm_binary, 'alpha', 'list', 'bundles', image]
            
            if self.skip_tls:
                cmd.extend(['--use-http'])
            
            logger.debug(f"Validating image with command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                logger.debug(f"Image validation successful: {image}")
                return True
            else:
                logger.debug(f"Image validation failed: {result.stderr}")
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
        Extract bundle metadata from container image using OPM
        
        Args:
            image: Container image URL
            registry_token: Registry authentication token (optional)
            
        Returns:
            Dict containing bundle metadata
            
        Raises:
            BundleProcessingError: If extraction fails
        """
        try:
            validate_image_url(image)
            opm_binary = self._find_opm_binary()
            
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Extract bundle to temporary directory
                cmd = [opm_binary, 'alpha', 'bundle', 'extract', image, '--output', str(temp_path)]
                
                if self.skip_tls:
                    cmd.extend(['--use-http'])
                
                # Set up environment for registry authentication
                env = {}
                if registry_token:
                    env['REGISTRY_AUTH_FILE'] = self._create_auth_file(registry_token, temp_path)
                
                logger.debug(f"Extracting bundle with command: {' '.join(cmd)}")
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    env={**subprocess.os.environ, **env} if env else None
                )
                
                if result.returncode != 0:
                    raise BundleProcessingError(f"Failed to extract bundle: {result.stderr}")
                
                # Parse extracted metadata
                metadata = self._parse_extracted_bundle(temp_path)
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
    
    def _parse_extracted_bundle(self, bundle_path: Path) -> Dict[str, Any]:
        """
        Parse extracted bundle directory for metadata
        
        Args:
            bundle_path: Path to extracted bundle directory
            
        Returns:
            Dict containing parsed metadata
            
        Raises:
            BundleProcessingError: If parsing fails
        """
        try:
            metadata = {
                'manifests': [],
                'permissions': [],
                'cluster_permissions': [],
                'service_account': None,
                'install_modes': {},
                'has_webhooks': False
            }
            
            # Look for manifests directory
            manifests_dir = bundle_path / 'manifests'
            if not manifests_dir.exists():
                raise BundleProcessingError("No manifests directory found in extracted bundle")
            
            # Parse YAML files in manifests directory
            for yaml_file in manifests_dir.glob('*.yaml'):
                try:
                    import yaml
                    with open(yaml_file, 'r') as f:
                        docs = list(yaml.safe_load_all(f))
                    
                    for doc in docs:
                        if not doc:
                            continue
                        
                        kind = doc.get('kind')
                        if kind == 'ClusterServiceVersion':
                            metadata.update(self._parse_csv(doc))
                        elif kind in ['Role', 'ClusterRole']:
                            metadata['manifests'].append(doc)
                        elif kind in ['RoleBinding', 'ClusterRoleBinding']:
                            metadata['manifests'].append(doc)
                        elif kind == 'ServiceAccount':
                            metadata['manifests'].append(doc)
                        else:
                            metadata['manifests'].append(doc)
                            
                except Exception as e:
                    logger.warning(f"Failed to parse {yaml_file}: {e}")
                    continue
            
            return metadata
            
        except Exception as e:
            raise BundleProcessingError(f"Failed to parse extracted bundle: {e}")
    
    def _parse_csv(self, csv_doc: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse ClusterServiceVersion document for RBAC and metadata
        
        Args:
            csv_doc: ClusterServiceVersion document
            
        Returns:
            Dict containing parsed CSV metadata
        """
        metadata = {}
        
        spec = csv_doc.get('spec', {})
        
        # Extract install modes
        install_modes = {}
        for mode in spec.get('installModes', []):
            install_modes[mode.get('type')] = mode.get('supported', False)
        metadata['install_modes'] = install_modes
        
        # Check for webhooks
        webhooks = spec.get('webhookdefinitions', [])
        metadata['has_webhooks'] = len(webhooks) > 0
        
        # Extract permissions
        permissions = []
        cluster_permissions = []
        
        # Get permissions from install strategy
        install_strategy = spec.get('install', {}).get('spec', {})
        
        for permission in install_strategy.get('permissions', []):
            permissions.append(permission)
        
        for cluster_permission in install_strategy.get('clusterPermissions', []):
            cluster_permissions.append(cluster_permission)
        
        metadata['permissions'] = permissions
        metadata['cluster_permissions'] = cluster_permissions
        
        # Extract service account name
        if permissions:
            metadata['service_account'] = permissions[0].get('serviceAccountName', 'default')
        elif cluster_permissions:
            metadata['service_account'] = cluster_permissions[0].get('serviceAccountName', 'default')
        
        return metadata
