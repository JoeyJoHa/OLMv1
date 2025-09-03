"""
OPM Query Library.

This module provides OPM-based catalog querying functionality with caching
and improved error handling.
"""

import logging
import os
import subprocess
import yaml
from typing import Dict, List, Optional

# Import shared RBAC utilities
from . import rbac_utils

# Set up logger
logger = logging.getLogger(__name__)


class OPMQueryLib:
    """Library class for OPM-based catalog queries."""
    
    def __init__(self, insecure: bool = False):
        """
        Initialize OPM query library.
        
        Args:
            insecure: Skip TLS verification
        """
        self.insecure = insecure
        # Cache for storing rendered catalog data to avoid repeated OPM calls
        self._catalog_cache: Dict[str, List[Dict]] = {}
    
    def _run_opm_command(self, cmd: List[str]) -> str:
        """Run OPM command with error handling."""
        try:
            # Handle global flags like --skip-tls (must come before subcommand)
            if self.insecure and 'render' in cmd:
                # Find the position of 'opm' and insert --skip-tls after it
                opm_index = cmd.index('opm')
                cmd.insert(opm_index + 1, '--skip-tls')
            
            # Set environment variables that might help with certificate issues
            env = os.environ.copy()
            if self.insecure:
                # Environment variables that might help with TLS/certificate issues
                env.update({
                    'GODEBUG': 'x509ignoreCN=0',
                    'SSL_VERIFY': 'false',
                    'PYTHONHTTPSVERIFY': '0'
                })
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                env=env
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"OPM command failed: {' '.join(cmd)} - {e.stderr}")
            
            # Provide helpful error message for certificate issues
            if "x509: certificate signed by unknown authority" in str(e.stderr):
                registry_host = ""
                if len(cmd) > 2:
                    # Extract registry host from image reference
                    image_ref = cmd[-1]  # Last argument is usually the image
                    if '/' in image_ref:
                        registry_host = image_ref.split('/')[0]
                
                error_msg = (
                    f"🔒 TLS certificate verification failed for the container registry.\n\n"
                    f"This usually means:\n"
                    f"1. The registry uses a self-signed certificate\n" 
                    f"2. The registry certificate is not trusted by the system\n"
                    f"3. You need to configure your container runtime for insecure registries\n\n"
                    f"💡 Try these solutions:\n"
                )
                
                if registry_host:
                    error_msg += (
                        f"- Configure podman for insecure registry:\n"
                        f"  podman login --tls-verify=false {registry_host}\n\n"
                        f"- Or add to /etc/containers/registries.conf:\n"
                        f"  [[registry]]\n"
                        f"  location = \"{registry_host}\"\n"
                        f"  insecure = true\n\n"
                    )
                else:
                    error_msg += (
                        f"- Configure your container runtime for insecure registries\n"
                        f"- Check /etc/containers/registries.conf configuration\n\n"
                    )
                    
                error_msg += f"Original error: {e.stderr}"
                raise Exception(error_msg)
            
            raise Exception(f"OPM command failed: {' '.join(cmd)}\nError: {e.stderr}")
        except FileNotFoundError:
            logger.error("OPM command not found")
            raise Exception("'opm' command not found. Please install OPM tool from: https://github.com/operator-framework/operator-registry/releases")
    
    def render_catalog(self, image_ref: str) -> List[Dict]:
        """
        Render catalog from image reference with caching support.
        
        Args:
            image_ref: Container image reference
            
        Returns:
            List of catalog entries
        """
        # Check cache first
        if image_ref in self._catalog_cache:
            logger.debug(f"Using cached data for image: {image_ref}")
            return self._catalog_cache[image_ref]
        
        logger.info(f"Rendering catalog from image: {image_ref}")
        
        cmd = ['opm', 'render', image_ref]
        output = self._run_opm_command(cmd)
        
        # Parse YAML documents
        entries = []
        for doc in yaml.safe_load_all(output):
            if doc:
                entries.append(doc)
        
        # Cache the results for future use
        self._catalog_cache[image_ref] = entries
        
        logger.info(f"Loaded and cached {len(entries)} catalog entries")
        return entries
    
    def clear_cache(self, image_ref: Optional[str] = None) -> None:
        """
        Clear cached catalog data.
        
        Args:
            image_ref: Specific image to clear, or None to clear all
        """
        if image_ref:
            self._catalog_cache.pop(image_ref, None)
            logger.debug(f"Cleared cache for image: {image_ref}")
        else:
            self._catalog_cache.clear()
            logger.debug("Cleared all catalog cache")
    
    def list_packages(self, image_ref: str) -> List[str]:
        """
        List all packages in catalog.
        
        Args:
            image_ref: Container image reference
            
        Returns:
            List of package names
        """
        entries = self.render_catalog(image_ref)
        
        packages = []
        for entry in entries:
            if entry.get('schema') == 'olm.package':
                packages.append(entry['name'])
        
        packages.sort()
        return packages
    
    def get_package_bundles(self, image_ref: str, package_name: str) -> List[Dict]:
        """
        Get all bundles for a specific package.
        
        Args:
            image_ref: Container image reference
            package_name: Name of the package
            
        Returns:
            List of bundle entries
        """
        entries = self.render_catalog(image_ref)
        
        bundles = []
        for entry in entries:
            if (entry.get('schema') == 'olm.bundle' and 
                entry.get('package') == package_name):
                bundles.append(entry)
        
        return bundles
    
    def extract_rbac_resources(self, image_ref: str, package_name: str) -> Optional[Dict]:
        """
        Extract RBAC resources for a specific package as Kubernetes YAML structures.
        
        Args:
            image_ref: Container image reference
            package_name: Name of the package
            
        Returns:
            Dict with clusterRoles, roles, and serviceAccount, or None if not found
        """
        bundles = self.get_package_bundles(image_ref, package_name)
        return rbac_utils.extract_rbac_from_bundles(bundles, package_name)

