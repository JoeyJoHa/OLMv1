"""
Bundle Processor

Handles extraction and processing of operator bundle metadata using opm binary.
"""

import logging
import subprocess
import tempfile
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class BundleProcessor:
    """Processes operator bundle images and extracts metadata"""
    
    def __init__(self, skip_tls: bool = False, debug: bool = False):
        self.skip_tls = skip_tls
        self.debug = debug
        
        if debug:
            logging.getLogger().setLevel(logging.DEBUG)
            logger.debug("Debug mode enabled")
    
    def check_opm_binary(self) -> bool:
        """Check if opm binary is available"""
        try:
            result = subprocess.run(['opm', 'version'], capture_output=True, text=True)
            if result.returncode == 0:
                logger.debug(f"OPM version: {result.stdout.strip()}")
                return True
            return False
        except FileNotFoundError:
            return False
    
    def extract_bundle_metadata(self, image: str, registry_token: str = None) -> Dict[str, Any]:
        """Extract metadata from operator bundle image using opm"""
        if not self.check_opm_binary():
            raise Exception("opm binary not found. Please install opm CLI tool.")
        
        # Check if image is index or bundle
        if self.is_index_image(image):
            raise Exception(
                f"Image {image} appears to be an index image. "
                "Please create a ClusterCatalog and query it with catalogd command instead."
            )
        
        logger.info(f"Extracting bundle metadata from image: {image}")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Set up authentication if registry token provided
            if registry_token:
                self.setup_registry_auth(registry_token)
            
            # Extract bundle
            cmd = ['opm', 'alpha', 'bundle', 'extract', '-i', image, '-o', temp_dir]
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                logger.debug(f"Bundle extracted to: {temp_dir}")
                
                # Parse bundle metadata
                metadata = self.parse_bundle_directory(temp_dir)
                return metadata
                
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to extract bundle: {e.stderr}")
                raise
    
    def is_index_image(self, image: str) -> bool:
        """Check if image is an index image by trying to list packages"""
        try:
            cmd = ['opm', 'alpha', 'list', 'packages', image]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return False
    
    def setup_registry_auth(self, registry_token: str):
        """Setup registry authentication"""
        # This is a simplified version - in practice, you might need more sophisticated auth
        logger.debug("Setting up registry authentication")
        # Implementation would depend on the specific registry and auth method
        pass
    
    def parse_bundle_directory(self, bundle_dir: str) -> Dict[str, Any]:
        """Parse extracted bundle directory and extract metadata"""
        bundle_path = Path(bundle_dir)
        metadata = {
            'manifests': [],
            'metadata': {},
            'rbac_rules': []
        }
        
        # Parse manifests
        manifests_dir = bundle_path / 'manifests'
        if manifests_dir.exists():
            for manifest_file in manifests_dir.glob('*.yaml'):
                with open(manifest_file, 'r') as f:
                    try:
                        docs = list(yaml.safe_load_all(f))
                        for doc in docs:
                            if doc:
                                metadata['manifests'].append(doc)
                                
                                # Extract RBAC rules
                                if doc.get('kind') == 'ClusterServiceVersion':
                                    self.extract_rbac_from_csv(doc, metadata)
                                    
                    except yaml.YAMLError as e:
                        logger.warning(f"Failed to parse {manifest_file}: {e}")
        
        # Parse metadata
        metadata_dir = bundle_path / 'metadata'
        if metadata_dir.exists():
            annotations_file = metadata_dir / 'annotations.yaml'
            if annotations_file.exists():
                with open(annotations_file, 'r') as f:
                    try:
                        annotations = yaml.safe_load(f)
                        metadata['metadata'] = annotations
                    except yaml.YAMLError as e:
                        logger.warning(f"Failed to parse annotations: {e}")
        
        return metadata
    
    def extract_rbac_from_csv(self, csv_doc: Dict[str, Any], metadata: Dict[str, Any]):
        """Extract RBAC rules from ClusterServiceVersion"""
        spec = csv_doc.get('spec', {})
        
        # Extract install modes and permissions
        install_modes = spec.get('installModes', [])
        permissions = spec.get('install', {}).get('spec', {}).get('permissions', [])
        cluster_permissions = spec.get('install', {}).get('spec', {}).get('clusterPermissions', [])
        
        # Store operator metadata
        metadata['operator_name'] = csv_doc.get('metadata', {}).get('name', '')
        metadata['operator_version'] = spec.get('version', '')
        metadata['install_modes'] = install_modes
        
        # Combine all permissions
        all_rules = []
        
        for perm in permissions:
            rules = perm.get('rules', [])
            all_rules.extend(rules)
        
        for cluster_perm in cluster_permissions:
            rules = cluster_perm.get('rules', [])
            all_rules.extend(rules)
        
        metadata['rbac_rules'] = all_rules
