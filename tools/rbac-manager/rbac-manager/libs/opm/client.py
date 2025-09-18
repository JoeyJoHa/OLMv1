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
import platform

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
    
    def _build_render_command(self, image: str) -> List[str]:
        """
        Build the opm render command with common options
        
        Args:
            image: Container image URL
            
        Returns:
            List of command arguments for opm render
            
        Raises:
            OPMError: If OPM binary not found
        """
        opm_binary = self._find_opm_binary()
        cmd = [opm_binary, 'render', image]
        
        if self.skip_tls:
            cmd.extend(['--skip-tls-verify'])
        
        return cmd
    
    def _run_opm_command(self, image: str, registry_token: str = None) -> subprocess.CompletedProcess:
        """
        Centralized helper method to run opm commands with robust two-attempt authentication
        
        Args:
            image: Container image URL
            registry_token: Registry authentication token (optional)
            
        Returns:
            subprocess.CompletedProcess: Result of the command execution
            
        Raises:
            BundleProcessingError: If command execution fails
        """
        try:
            validate_image_url(image)
            
            # Build render command using centralized helper
            cmd = self._build_render_command(image)
            
            # Enhanced registry authentication handling
            if registry_token:
                # Two-attempt authentication strategy for robust token handling
                return self._run_with_two_attempt_auth(cmd, image, registry_token)
            else:
                # Auto-discover authentication from standard locations
                discovered_auth = self._discover_registry_auth(image)
                if discovered_auth:
                    with tempfile.TemporaryDirectory() as temp_dir:
                        auth_file_path = self._create_auth_file_from_discovered(discovered_auth, image, Path(temp_dir))
                        env = {'REGISTRY_AUTH_FILE': auth_file_path}
                        logger.info(f"Using discovered registry authentication for {self._extract_registry_from_image(image)}")
                        
                        logger.debug(f"Running opm command with discovered auth: {' '.join(cmd)}")
                        logger.debug(f"Using authentication file: {auth_file_path}")
                        
                        result = subprocess.run(
                            cmd,
                            capture_output=True,
                            text=True,
                            timeout=NetworkConstants.BUNDLE_EXTRACTION_TIMEOUT,
                            env={**os.environ, **env}
                        )
                        return result
                else:
                    # No authentication needed/available
                    logger.debug(f"Running opm command without authentication: {' '.join(cmd)}")
                    
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=NetworkConstants.BUNDLE_EXTRACTION_TIMEOUT
                    )
                    return result
                    
        except subprocess.TimeoutExpired:
            raise BundleProcessingError(f"OPM command timed out for image: {image}")
        except Exception as e:
            if isinstance(e, BundleProcessingError):
                raise
            raise BundleProcessingError(f"Failed to run opm command: {e}")
    
    def _run_with_two_attempt_auth(self, cmd: List[str], image: str, registry_token: str) -> subprocess.CompletedProcess:
        """
        Robust two-attempt authentication strategy with Docker config fallback
        
        Args:
            cmd: OPM command to execute
            image: Container image URL
            registry_token: Registry authentication token
            
        Returns:
            subprocess.CompletedProcess: Result of successful command execution
            
        Raises:
            BundleProcessingError: If both authentication attempts fail
        """
        # First Attempt: Use REGISTRY_AUTH_FILE environment variable
        logger.debug("Attempting authentication via REGISTRY_AUTH_FILE environment variable")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            auth_file_path = self._create_auth_file_from_token(registry_token, image, Path(temp_dir))
            env = {'REGISTRY_AUTH_FILE': auth_file_path}
            
            logger.debug(f"First attempt - Running opm command with auth file: {' '.join(cmd)}")
            logger.debug(f"Using authentication file: {auth_file_path}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=NetworkConstants.BUNDLE_EXTRACTION_TIMEOUT,
                env={**os.environ, **env}
            )
            
            # Check if first attempt succeeded
            if result.returncode == 0:
                logger.debug("First attempt succeeded with REGISTRY_AUTH_FILE")
                return result
            
            # Check if failure is due to authentication (unauthorized error)
            if "unauthorized" not in result.stderr.lower():
                logger.debug("First attempt failed, but not due to authentication - returning result")
                return result
            
            logger.warning("First attempt failed with unauthorized error, trying Docker config fallback")
            
            # Second Attempt: Fallback to Docker config file manipulation
            return self._run_with_docker_config_fallback(cmd, image, registry_token)
    
    def _run_with_docker_config_fallback(self, cmd: List[str], image: str, registry_token: str) -> subprocess.CompletedProcess:
        """
        Fallback authentication method using Docker config file manipulation
        
        Args:
            cmd: OPM command to execute
            image: Container image URL
            registry_token: Registry authentication token
            
        Returns:
            subprocess.CompletedProcess: Result of command execution
            
        Raises:
            BundleProcessingError: If fallback authentication fails
        """
        # Define Docker config file paths
        docker_config_dir = Path.home() / '.docker'
        docker_config_file = docker_config_dir / 'config.json'
        backup_config_file = docker_config_dir / 'config.json.bak'
        
        # Track if we created a backup for proper cleanup
        backup_created = False
        original_existed = docker_config_file.exists()
        
        try:
            # Ensure .docker directory exists
            docker_config_dir.mkdir(exist_ok=True)
            
            # Safely back up original config.json if it exists
            if original_existed:
                logger.debug(f"Backing up original Docker config: {docker_config_file} -> {backup_config_file}")
                docker_config_file.rename(backup_config_file)
                backup_created = True
            
            # Create new config.json with authentication token
            registry_host = self._extract_registry_from_image(image) or 'registry.redhat.io'
            auth_token = self._process_auth_token(registry_token)
            
            auth_data = {
                "auths": {
                    registry_host: {
                        "auth": auth_token
                    }
                }
            }
            
            # Add common registry fallbacks for better compatibility
            if registry_host not in ['quay.io', 'registry.redhat.io', 'docker.io']:
                auth_data["auths"]["registry.redhat.io"] = {"auth": auth_token}
                auth_data["auths"]["quay.io"] = {"auth": auth_token}
            
            # Write new Docker config
            with open(docker_config_file, 'w') as f:
                json.dump(auth_data, f, indent=2)
            
            logger.debug(f"Created temporary Docker config for registry: {registry_host}")
            
            # Run OPM command without REGISTRY_AUTH_FILE (forces use of default Docker config)
            logger.debug(f"Second attempt - Running opm command with Docker config fallback: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=NetworkConstants.BUNDLE_EXTRACTION_TIMEOUT
                # No env override - let opm use default Docker config location
            )
            
            if result.returncode == 0:
                logger.info("Docker config fallback authentication succeeded")
            else:
                logger.warning("Docker config fallback authentication also failed")
            
            return result
            
        except Exception as e:
            logger.error(f"Error during Docker config fallback: {e}")
            raise BundleProcessingError(f"Docker config fallback failed: {e}")
            
        finally:
            # GUARANTEE: Always restore original config, regardless of success/failure
            try:
                # Remove our temporary config file
                if docker_config_file.exists():
                    docker_config_file.unlink()
                    logger.debug("Removed temporary Docker config file")
                
                # Restore original config if we backed it up
                if backup_created and backup_config_file.exists():
                    backup_config_file.rename(docker_config_file)
                    logger.debug("Restored original Docker config from backup")
                elif not original_existed and docker_config_dir.exists():
                    # If original didn't exist and directory is empty, clean up
                    try:
                        if not any(docker_config_dir.iterdir()):
                            docker_config_dir.rmdir()
                            logger.debug("Cleaned up empty .docker directory")
                    except OSError:
                        # Directory not empty or other issue, ignore
                        pass
                        
            except Exception as cleanup_error:
                logger.error(f"Error during Docker config cleanup: {cleanup_error}")
                # Don't raise here - we want to return the original command result
    
    def validate_image(self, image: str, registry_token: str = None) -> bool:
        """
        Validate if image is accessible and is a valid bundle/index
        
        Args:
            image: Container image URL
            registry_token: Registry authentication token (optional)
            
        Returns:
            bool: True if image is valid
            
        Raises:
            BundleProcessingError: If image validation fails
        """
        try:
            # Use centralized helper method (DRY principle)
            result = self._run_opm_command(image, registry_token)
            
            if result.returncode == 0:
                # Check if we got valid JSON output
                if not result.stdout.strip():
                    raise BundleProcessingError(f"No output from opm render for image: {image}")
                logger.debug(f"Bundle image validation successful: {image}")
                return True
            else:
                logger.debug(f"Bundle image validation failed: {result.stderr}")
                raise BundleProcessingError(f"Image validation failed: {result.stderr}")
                
        except Exception as e:
            if isinstance(e, BundleProcessingError):
                raise
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
            # Use centralized helper method (DRY principle)
            result = self._run_opm_command(image, registry_token)
            
            if result.returncode != 0:
                raise BundleProcessingError(f"Failed to render bundle: {result.stderr}")
            
            # Parse the JSON output (multiple JSON objects, one per line)
            metadata = self._parse_opm_render_output(result.stdout)
            metadata['image'] = image
            
            logger.info(f"Successfully extracted bundle metadata from: {image}")
            return metadata
                
        except Exception as e:
            if isinstance(e, BundleProcessingError):
                raise
            raise BundleProcessingError(f"Failed to extract bundle metadata: {e}")
    
    def _discover_registry_auth(self, image: str) -> Optional[Dict[str, Any]]:
        """
        Auto-discover registry authentication from standard Docker/Podman locations
        
        Args:
            image: Container image URL to determine target registry
            
        Returns:
            Dict containing authentication data if found, None otherwise
        """
        registry_host = self._extract_registry_from_image(image)
        if not registry_host:
            return None
        
        # Standard locations for authentication files
        auth_locations = self._get_auth_file_locations()
        
        logger.debug(f"Searching for authentication for registry: {registry_host}")
        logger.debug(f"Checking locations: {auth_locations}")
        
        for auth_path in auth_locations:
            try:
                if auth_path.exists():
                    logger.debug(f"Found auth file: {auth_path}")
                    with open(auth_path, 'r') as f:
                        auth_data = json.load(f)
                    
                    # Look for matching registry in auths
                    auths = auth_data.get('auths', {})
                    
                    # Try exact match first
                    if registry_host in auths:
                        auth_entry = auths[registry_host]
                        if auth_entry.get('auth'):
                            logger.debug(f"Found exact match for {registry_host}")
                            return {
                                'registry': registry_host,
                                'auth_data': auth_entry,
                                'source_file': str(auth_path)
                            }
                    
                    # Try partial matches for common registries
                    for auth_registry, auth_entry in auths.items():
                        if self._is_registry_match(registry_host, auth_registry) and auth_entry.get('auth'):
                            logger.debug(f"Found partial match: {auth_registry} for {registry_host}")
                            return {
                                'registry': registry_host,
                                'auth_data': auth_entry,
                                'source_file': str(auth_path)
                            }
                            
            except (json.JSONDecodeError, IOError, PermissionError) as e:
                logger.debug(f"Could not read auth file {auth_path}: {e}")
                continue
        
        logger.debug(f"No authentication found for registry: {registry_host}")
        return None
    
    def _get_auth_file_locations(self) -> List[Path]:
        """
        Get standard locations for Docker/Podman authentication files
        
        Returns:
            List of Path objects to check for auth files
        """
        home = Path.home()
        locations = []
        
        # Docker locations
        locations.extend([
            home / '.docker' / 'config.json',
            home / '.dockercfg',
        ])
        
        # Podman locations
        if platform.system() == 'Darwin':  # macOS
            locations.extend([
                home / '.config' / 'containers' / 'auth.json',
                home / 'Library' / 'Containers' / 'com.docker.docker' / 'Data' / 'vms' / '0' / 'tty' / 'root' / '.docker' / 'config.json'
            ])
        else:  # Linux
            locations.extend([
                home / '.config' / 'containers' / 'auth.json',
                Path('/etc/containers/auth.json'),
                Path('/run/containers/0/auth.json'),
            ])
        
        # XDG locations
        xdg_runtime_dir = os.getenv('XDG_RUNTIME_DIR')
        if xdg_runtime_dir:
            locations.append(Path(xdg_runtime_dir) / 'containers' / 'auth.json')
        
        # Environment variable override
        registry_auth_file = os.getenv('REGISTRY_AUTH_FILE')
        if registry_auth_file:
            locations.insert(0, Path(registry_auth_file))  # Highest priority
        
        return locations
    
    def _extract_registry_from_image(self, image: str) -> Optional[str]:
        """
        Extract registry hostname from container image URL
        
        Args:
            image: Container image URL
            
        Returns:
            Registry hostname or None if cannot be determined
        """
        try:
            # Handle various image formats:
            # registry.redhat.io/ubi8/ubi:latest
            # quay.io/operator-framework/opm:latest
            # docker.io/library/ubuntu:latest
            # ubuntu:latest (implies docker.io)
            
            if '/' not in image:
                # Just a simple image name, assume docker.io
                return 'docker.io'
            
            parts = image.split('/')
            
            # If first part contains a dot or colon, it's likely a registry
            first_part = parts[0]
            if '.' in first_part or ':' in first_part:
                return first_part
            
            # Otherwise, it's likely docker.io (e.g., "ubuntu/something")
            return 'docker.io'
            
        except Exception as e:
            logger.debug(f"Could not extract registry from image {image}: {e}")
            return None
    
    def _is_registry_match(self, target_registry: str, auth_registry: str) -> bool:
        """
        Check if two registry hostnames match (with fuzzy matching for common cases)
        
        Args:
            target_registry: The registry we're looking for auth
            auth_registry: The registry in the auth file
            
        Returns:
            bool: True if they match
        """
        if target_registry == auth_registry:
            return True
        
        # Common registry aliases
        registry_aliases = {
            'docker.io': ['index.docker.io', 'registry-1.docker.io'],
            'registry.redhat.io': ['registry.access.redhat.com'],
            'quay.io': ['quay.io'],
        }
        
        # Check if target matches any aliases of auth_registry
        for canonical, aliases in registry_aliases.items():
            if auth_registry == canonical and target_registry in aliases:
                return True
            if target_registry == canonical and auth_registry in aliases:
                return True
        
        return False
    
    def _create_auth_file_from_token(self, registry_token: str, image: str, temp_path: Path) -> str:
        """
        Create registry authentication file from provided token
        
        Args:
            registry_token: Registry authentication token (can be base64 or username:password)
            image: Container image URL to determine target registry
            temp_path: Temporary directory path
            
        Returns:
            str: Path to auth file
        """
        auth_file = temp_path / "auth.json"
        registry_host = self._extract_registry_from_image(image) or 'registry.redhat.io'
        
        # Handle different token formats
        auth_token = self._process_auth_token(registry_token)
        
        # Create auth file structure
        auth_data = {
            "auths": {
                registry_host: {
                    "auth": auth_token
                }
            }
        }
        
        # Add common registry fallbacks
        if registry_host not in ['quay.io', 'registry.redhat.io']:
            auth_data["auths"]["registry.redhat.io"] = {"auth": auth_token}
            auth_data["auths"]["quay.io"] = {"auth": auth_token}
        
        with open(auth_file, 'w') as f:
            json.dump(auth_data, f, indent=2)
        
        logger.debug(f"Created auth file for registry: {registry_host}")
        return str(auth_file)
    
    def _create_auth_file_from_discovered(self, discovered_auth: Dict[str, Any], image: str, temp_path: Path) -> str:
        """
        Create registry authentication file from discovered credentials
        
        Args:
            discovered_auth: Discovered authentication data
            image: Container image URL
            temp_path: Temporary directory path
            
        Returns:
            str: Path to auth file
        """
        auth_file = temp_path / "auth.json"
        registry_host = discovered_auth['registry']
        auth_entry = discovered_auth['auth_data']
        
        # Create minimal auth file with just the needed registry
        auth_data = {
            "auths": {
                registry_host: auth_entry
            }
        }
        
        with open(auth_file, 'w') as f:
            json.dump(auth_data, f, indent=2)
        
        logger.debug(f"Created auth file from discovered credentials for: {registry_host}")
        logger.debug(f"Source: {discovered_auth['source_file']}")
        return str(auth_file)
    
    def _process_auth_token(self, token: str) -> str:
        """
        Process authentication token, handling different formats
        
        Args:
            token: Authentication token (base64 encoded or username:password)
            
        Returns:
            str: Base64 encoded authentication token
        """
        try:
            # If it's already base64 encoded, validate it
            if self._is_base64_encoded(token):
                # Try to decode to verify it's valid base64
                decoded = base64.b64decode(token).decode('utf-8')
                if ':' in decoded:  # Valid username:password format
                    logger.debug("Using provided base64-encoded token")
                    return token
            
            # If it contains ':', assume it's username:password and encode it
            if ':' in token:
                encoded_token = base64.b64encode(token.encode('utf-8')).decode('utf-8')
                logger.debug("Encoded username:password to base64")
                return encoded_token
            
            # Otherwise, assume it's already a token and use as-is
            logger.debug("Using token as-is")
            return token
            
        except Exception as e:
            logger.debug(f"Error processing auth token: {e}")
            # Fallback: use as-is
            return token
    
    def _is_base64_encoded(self, s: str) -> bool:
        """
        Check if string is base64 encoded
        
        Args:
            s: String to check
            
        Returns:
            bool: True if appears to be base64 encoded
        """
        try:
            if len(s) % 4 != 0:
                return False
            base64.b64decode(s, validate=True)
            return True
        except Exception:
            return False
    
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
                
                if schema == str(OPMConstants.BundleSchema.BUNDLE):
                    # Extract basic bundle information
                    bundle_metadata['name'] = obj.get('name')
                    bundle_metadata['package'] = obj.get('package')
                    bundle_metadata['image'] = obj.get('image')
                    
                    # Process properties to extract manifests and API groups
                    properties = obj.get('properties', [])
                    for prop in properties:
                        if prop.get('type') == str(OPMConstants.PropertyType.GVK):
                            # Extract API group information
                            gvk_data = prop.get('value', {})
                            api_group = gvk_data.get('group')
                            if api_group and api_group not in bundle_metadata['api_groups']:
                                bundle_metadata['api_groups'].append(api_group)
                        
                        elif prop.get('type') == str(OPMConstants.PropertyType.BUNDLE_OBJECT):
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
                                        if kind == str(OPMConstants.ManifestKind.CLUSTER_SERVICE_VERSION):
                                            self._extract_csv_data(manifest, bundle_metadata)
                                        elif kind == str(OPMConstants.ManifestKind.CUSTOM_RESOURCE_DEFINITION):
                                            # CRD manifests are now handled via CSV spec.customresourcedefinitions.owned
                                            pass
                                            
                                except (base64.binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as e:
                                    logger.warning(f"Failed to decode manifest data: {e}")
                                    continue
                        
                        elif prop.get('type') == str(OPMConstants.PropertyType.PACKAGE):
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
            spec = csv_manifest.get(str(OPMConstants.CSVSection.SPEC), {})
            metadata = csv_manifest.get(str(OPMConstants.CSVSection.METADATA), {})
            
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
            install_section = spec.get(str(OPMConstants.CSVSection.INSTALL), {})
            install_spec = install_section.get(str(OPMConstants.CSVSection.SPEC), {})
            
            # Extract deployment information for installer permissions
            deployments = install_spec.get(str(OPMConstants.CSVSection.DEPLOYMENTS), [])
            bundle_metadata[str(OPMConstants.CSVSection.DEPLOYMENTS)] = deployments
            
            # Bundle objects will be processed by the processor layer
            
            # Extract RBAC permissions
            
            # Namespace-scoped permissions
            permissions = install_spec.get(str(OPMConstants.CSVSection.PERMISSIONS), [])
            for perm in permissions:
                bundle_metadata[OPMConstants.BUNDLE_PERMISSIONS_KEY].append({
                    'service_account': perm.get('serviceAccountName', KubernetesConstants.DEFAULT_NAMESPACE),
                    'rules': perm.get('rules', [])
                })
            
            # Cluster-scoped permissions
            cluster_permissions = install_spec.get(str(OPMConstants.CSVSection.CLUSTER_PERMISSIONS), [])
            for perm in cluster_permissions:
                bundle_metadata[OPMConstants.BUNDLE_CLUSTER_PERMISSIONS_KEY].append({
                    'service_account': perm.get('serviceAccountName', KubernetesConstants.DEFAULT_NAMESPACE),
                    'rules': perm.get('rules', [])
                })
            
            # Extract CRDs from CSV spec
            crd_definitions = spec.get(str(OPMConstants.CSVSection.CRD), {})
            owned_crds = crd_definitions.get(str(OPMConstants.CSVSection.OWNED_CRDS), [])
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
