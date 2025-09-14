"""
Catalog Manager

Handles operations related to OpenShift catalogs and catalogd service.
"""

import json
import logging
import subprocess
import sys
import time
from typing import Dict, List, Optional, Any, Tuple

import requests
from kubernetes import client, config
from kubernetes.client.rest import ApiException
import urllib3

logger = logging.getLogger(__name__)


class CatalogManager:
    """Manages catalog operations and catalogd service interactions"""
    
    def __init__(self, skip_tls: bool = False, debug: bool = False):
        self.skip_tls = skip_tls
        self.debug = debug
        
        if debug:
            logging.getLogger().setLevel(logging.DEBUG)
            logger.debug("Debug mode enabled")
        
        # Disable SSL warnings when --skip-tls is used
        if skip_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Initialize Kubernetes client
        try:
            config.load_kube_config()
            
            # Configure SSL verification based on skip_tls flag
            configuration = client.Configuration.get_default_copy()
            if skip_tls:
                configuration.verify_ssl = False
                configuration.ssl_ca_cert = None
            else:
                # Ensure SSL verification is enabled
                configuration.verify_ssl = True
            
            self.k8s_client = client.ApiClient(configuration)
            self.custom_api = client.CustomObjectsApi(self.k8s_client)
            self.core_api = client.CoreV1Api(self.k8s_client)
            logger.debug("Kubernetes client initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize Kubernetes client: {e}")
            self.k8s_client = None
    
    def is_output_piped(self) -> bool:
        """
        Check if output is being piped (not connected to terminal).
        
        Returns:
            bool: True if output is connected to terminal, False if piped
        """
        return not sys.stdout.isatty()
    
    def _fetch_clustercatalogs(self) -> List[Dict[str, Any]]:
        """
        Internal method to fetch ClusterCatalogs from Kubernetes API.
        
        Returns:
            List[Dict[str, Any]]: Raw ClusterCatalog data from Kubernetes API
        """
        if not self.k8s_client:
            raise Exception("Kubernetes client not available. Please ensure kubeconfig is properly configured.")
        
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
                raise Exception(
                    "SSL certificate verification failed. This cluster appears to use self-signed certificates. "
                    "Please use the --skip-tls flag to bypass certificate verification."
                )
            logger.error(f"Failed to list ClusterCatalogs: {e}")
            raise
        except Exception as e:
            error_msg = str(e).lower()
            if any(keyword in error_msg for keyword in ["certificate verify failed", "ssl", "certificate", "tls", "handshake", "verify failed"]):
                raise Exception(
                    "SSL certificate verification failed. This cluster appears to use self-signed certificates. "
                    "Please use the --skip-tls flag to bypass certificate verification."
                )
            logger.error(f"Failed to list ClusterCatalogs: {e}")
            raise
    
    def _format_age(self, creation_time: str) -> str:
        """Format age from creation timestamp."""
        if creation_time == 'unknown':
            return 'unknown'
        
        try:
            from datetime import datetime
            import dateutil.parser
            created = dateutil.parser.parse(creation_time)
            now = datetime.now(created.tzinfo)
            age_delta = now - created
            
            if age_delta.days > 0:
                return f"{age_delta.days}d"
            elif age_delta.seconds > 3600:
                return f"{age_delta.seconds // 3600}h"
            elif age_delta.seconds > 60:
                return f"{age_delta.seconds // 60}m"
            else:
                return f"{age_delta.seconds}s"
        except:
            return creation_time
    
    def _parse_serving_status(self, status: Dict[str, Any]) -> bool:
        """Parse serving status from conditions array."""
        conditions = status.get('conditions', [])
        for condition in conditions:
            if condition.get('type') == 'Serving' and condition.get('status') == 'True':
                return True
        return False
    
    def list_catalogs(self) -> List[Dict[str, Any]]:
        """
        List all available ClusterCatalogs in the cluster with enhanced information.
        
        Returns:
            List[Dict[str, Any]]: List of enhanced catalog information
        """
        try:
            raw_catalogs = self._fetch_clustercatalogs()
            
            catalog_list = []
            for catalog in raw_catalogs:
                metadata = catalog.get('metadata', {})
                status = catalog.get('status', {})
                spec = catalog.get('spec', {})
                
                catalog_info = {
                    'name': metadata.get('name', 'unknown'),
                    'source': spec.get('source', {}),
                    'status': status.get('phase', 'Unknown'),
                    'serving': self._parse_serving_status(status),
                    'lastUnpacked': status.get('lastUnpacked', 'never'),
                    'age': self._format_age(metadata.get('creationTimestamp', 'unknown'))
                }
                catalog_list.append(catalog_info)
            
            return catalog_list
            
        except Exception as e:
            logger.error(f"Failed to list ClusterCatalogs: {e}")
            raise
    
    def display_catalogs_enhanced(self) -> int:
        """
        Display ClusterCatalogs with enhanced output format.
        
        Returns:
            int: Exit code (0 for success, non-zero for error)
        """
        try:
            catalogs = self.list_catalogs()
            
            if not catalogs:
                print("No ClusterCatalogs found in this cluster.")
                return 1
            
            print(f"\nAvailable ClusterCatalogs:")
            print("-" * 80)
            print(f"{'Name':<40} {'Serving':<8} {'Last Unpacked':<25} {'Age':<7}")
            print("-" * 80)
            
            for catalog in catalogs:
                serving_status = "True" if catalog['serving'] else "False"
                last_unpacked = catalog['lastUnpacked'] if catalog['lastUnpacked'] != 'never' else 'Never'
                print(f"{catalog['name']:<40} {serving_status:<8} {last_unpacked:<25} {catalog['age']:<7}")
            
            print("-" * 80)
            print(f"\nTotal: {len(catalogs)} ClusterCatalogs")
            print("Note: Only serving catalogs can be reliably queried for packages.")
            
            return 0
            
        except Exception as e:
            if "certificate verify failed" in str(e) or "SSL" in str(e) or "certificate" in str(e).lower():
                print("Error: SSL certificate verification failed. This cluster appears to use self-signed certificates.")
                print("Please use the --skip-tls flag to bypass certificate verification.")
                return 1
            logger.error(f"Failed to display ClusterCatalogs: {e}")
            print(f"Error listing ClusterCatalogs: {e}")
            return 1
    
    def _discover_catalogd_service(self) -> Tuple[str, int, bool]:
        """Discover catalogd service name and preferred port.

        Returns:
            Tuple[str, int, bool]: (target resource string, service port, is_https)
        """
        try:
            svc_list = self.core_api.list_namespaced_service(namespace="openshift-catalogd")
            candidates: List[Tuple[str, int, bool]] = []
            for svc in svc_list.items:
                name = svc.metadata.name or ""
                if "catalogd" not in name:
                    continue
                for port in (svc.spec.ports or []):
                    port_num = int(port.port)
                    name_lower = (port.name or "").lower()
                    is_https = port_num == 443 or "https" in name_lower
                    # prefer https then http
                    pref = 0
                    if is_https:
                        pref = 2
                    elif port_num == 80 or "http" in name_lower:
                        pref = 1
                    candidates.append((f"service/{name}", port_num, is_https, pref))
            if candidates:
                # sort by preference desc then by name for stability
                candidates.sort(key=lambda x: (x[3], x[0]), reverse=True)
                target, svc_port, is_https = candidates[0][0], candidates[0][1], candidates[0][2]
                return target, svc_port, is_https
        except Exception as e:
            logger.debug(f"Service discovery failed: {e}")
        # Fallback to common defaults
        return "service/catalogd-service", 443, True

    def port_forward_catalogd(self) -> Tuple[subprocess.Popen, int, bool]:
        """Port-forward the catalogd service and return the process, local port and https flag"""
        logger.info("Setting up port-forward to catalogd service...")
        
        # Find an available port
        import socket
        sock = socket.socket()
        sock.bind(('', 0))
        port = sock.getsockname()[1]
        sock.close()
        
        # Discover target service/port
        target, target_port, is_https = self._discover_catalogd_service()
        last_error: Optional[str] = None
        
        cmd = [
            'kubectl', 'port-forward',
            '-n', 'openshift-catalogd',
            target,
            f'{port}:{target_port}'
        ]
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            # Give it a moment to establish
            time.sleep(2)
            if process.poll() is None:
                logger.info(f"Port-forward established to {target} ({target_port}) on local port {port}")
                return process, port, is_https
            # If it exited, capture stderr
            stdout, stderr = process.communicate()
            last_error = stderr or stdout
        except Exception as e:
            last_error = str(e)
        
        error_message = last_error or "Unknown error establishing port-forward to catalogd"
        logger.error(f"Failed to establish port-forward: {error_message}")
        raise Exception(f"Port-forward failed: {error_message}")
    
    def make_catalogd_request(self, url: str, openshift_url: str = None, 
                            openshift_token: str = None) -> Dict[str, Any]:
        """Make API request to catalogd service"""
        headers = {}
        
        if openshift_token:
            headers['Authorization'] = f'Bearer {openshift_token}'
        
        verify_ssl = not self.skip_tls
        
        try:
            if openshift_url:
                # Direct API call to OpenShift
                full_url = f"{openshift_url.rstrip('/')}/{url.lstrip('/')}"
            else:
                # Use port-forward
                full_url = url
            
            logger.debug(f"Making request to: {full_url}")
            response = requests.get(full_url, headers=headers, verify=verify_ssl, timeout=30)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            raise

        # Parse body robustly (JSON array/object, concatenated JSON, or NDJSON)
        content_type = (response.headers.get('Content-Type') or '').lower()
        text_body = response.text
        import json as _json

        # First attempt: standard JSON parse
        try:
            return _json.loads(text_body)
        except Exception:
            pass

        # If body looks like concatenated JSON objects, split and parse lines
        lines = [ln for ln in text_body.splitlines() if ln.strip()]
        if len(lines) > 1:
            items = []
            all_lines_json = True
            for ln in lines:
                try:
                    items.append(_json.loads(ln))
                except Exception:
                    all_lines_json = False
                    break
            if all_lines_json:
                return items

        # Last resort: raise with snippet for diagnostics
        snippet = text_body[:400].replace('\n', ' ')
        raise Exception(f"Failed to parse catalogd response as JSON. Content-Type={content_type}. Snippet: {snippet}")
    
    def interactive_catalog_selection(self, catalogs: List[Dict[str, Any]]) -> str:
        """Interactive prompt for catalog selection"""
        print("\nAvailable ClusterCatalogs:")
        print("-" * 50)
        
        for i, catalog in enumerate(catalogs, 1):
            source_type = catalog['source'].get('type', 'Unknown')
            source_image = catalog['source'].get('image', {}).get('ref', 'N/A')
            print(f"{i}. {catalog['name']}")
            print(f"   Source: {source_type}")
            print(f"   Image: {source_image}")
            print(f"   Status: {catalog['status']}")
            print()
        
        while True:
            try:
                choice = input(f"Select a catalog (1-{len(catalogs)}): ").strip()
                index = int(choice) - 1
                
                if 0 <= index < len(catalogs):
                    selected = catalogs[index]['name']
                    print(f"Selected catalog: {selected}")
                    return selected
                else:
                    print(f"Please enter a number between 1 and {len(catalogs)}")
                    
            except (ValueError, KeyboardInterrupt):
                print("\nOperation cancelled.")
                import sys
                sys.exit(1)
    
    def _fetch_catalog_metadata(self, catalog_name: str, port: int = None, 
                               openshift_url: str = None, openshift_token: str = None) -> List[Dict[str, Any]]:
        """Fetch raw catalog metadata from catalogd API"""
        if port:
            url = f"http://localhost:{port}/catalogs/{catalog_name}/api/v1/all"
        else:
            url = f"/catalogs/{catalog_name}/api/v1/all"
        
        logger.debug(f"Making request to: {url}")
        return self.make_catalogd_request(url, openshift_url, openshift_token)
    
    def fetch_catalog_packages(self, catalog_name: str, port: int = None, 
                             openshift_url: str = None, openshift_token: str = None) -> List[Dict[str, Any]]:
        """Fetch all packages from a catalog"""
        logger.info(f"Fetching packages from catalog: {catalog_name}")
        data = self._fetch_catalog_metadata(catalog_name, port, openshift_url, openshift_token)
        
        # Parse the JSON output to extract packages
        packages = self._parse_catalog_data(data, 'packages')
        logger.info(f"Found {len(packages)} packages in catalog {catalog_name}")
        
        return packages
    
    def fetch_package_channels(self, catalog_name: str, package_name: str, port: int = None,
                             openshift_url: str = None, openshift_token: str = None) -> List[Dict[str, Any]]:
        """Fetch all channels for a package"""
        logger.info(f"Fetching channels for package: {package_name}")
        data = self._fetch_catalog_metadata(catalog_name, port, openshift_url, openshift_token)
        
        # Parse the JSON output to extract channels for the specific package
        channels = self._parse_catalog_data(data, 'channels', package_name)
        logger.info(f"Found {len(channels)} channels for package {package_name}")
        
        return channels
    
    def fetch_channel_versions(self, catalog_name: str, package_name: str, channel_name: str, 
                             port: int = None, openshift_url: str = None, openshift_token: str = None) -> List[Dict[str, Any]]:
        """Fetch all versions for a channel"""
        logger.info(f"Fetching versions for channel: {channel_name}")
        data = self._fetch_catalog_metadata(catalog_name, port, openshift_url, openshift_token)
        
        # Parse the JSON output to extract versions for the specific channel
        versions = self._parse_catalog_data(data, 'versions', package_name, channel_name)
        logger.info(f"Found {len(versions)} versions for channel {channel_name}")
        
        return versions
    
    def fetch_version_metadata(self, catalog_name: str, package_name: str, channel_name: str, 
                             version: str, port: int = None, openshift_url: str = None, 
                             openshift_token: str = None) -> Dict[str, Any]:
        """Fetch metadata for a specific version"""
        logger.info(f"Fetching metadata for version: {version}")
        data = self._fetch_catalog_metadata(catalog_name, port, openshift_url, openshift_token)
        
        # Parse the JSON output to extract metadata for the specific version
        metadata = self._parse_catalog_data(data, 'metadata', package_name, channel_name, version)
        
        return metadata
    
    def _parse_catalog_data(self, data: List[Dict[str, Any]], data_type: str, 
                           package_name: str = None, channel_name: str = None, 
                           version: str = None) -> Any:
        """Parse catalog data from the /api/v1/all endpoint"""
        if not isinstance(data, list):
            logger.warning("Expected list data from catalogd API")
            return []
        
        if data_type == 'packages':
            # Extract unique package names
            packages = set()
            for item in data:
                if item.get('schema') == 'olm.package':
                    package_name = item.get('name', '')
                    if package_name:
                        packages.add(package_name)
            return sorted(list(packages))
        
        elif data_type == 'channels':
            # Extract channels for a specific package
            if not package_name:
                return []
            
            channels = set()
            for item in data:
                if (item.get('schema') == 'olm.channel' and 
                    item.get('package') == package_name):
                    channel_name = item.get('name', '')
                    if channel_name:
                        channels.add(channel_name)
            return sorted(list(channels))
        
        elif data_type == 'versions':
            # Extract versions for a specific channel
            if not package_name or not channel_name:
                return []
            
            versions = set()
            
            # First, find the channel schema item to get the version mapping
            channel_entries = []
            for item in data:
                if (item.get('schema') == 'olm.channel' and 
                    item.get('package') == package_name and 
                    item.get('name') == channel_name):
                    channel_entries = item.get('entries', [])
                    logger.debug(f"Found channel {channel_name} with {len(channel_entries)} entries")
                    break
            
            # Extract versions from channel entries
            for entry in channel_entries:
                version = entry.get('name', '')
                if version:
                    # Remove bundle name prefix if present (e.g., "quay-operator.v3.10.0" -> "v3.10.0")
                    if '.' in version and version.startswith(package_name):
                        version = version.split('.', 1)[1] if '.' in version else version
                    versions.add(version)
                    logger.debug(f"Added version {version} for channel {channel_name}")
            
            logger.debug(f"Found {len(versions)} versions for channel {channel_name}: {list(versions)}")
            return sorted(list(versions), reverse=True)  # Most recent first
        
        elif data_type == 'metadata':
            # Extract metadata for a specific version
            if not package_name or not channel_name or not version:
                return {}
            
            # Find the bundle that matches the version
            # The bundle name typically follows the pattern: package-name.version
            expected_bundle_name = f"{package_name}.{version}"
            
            for item in data:
                if (item.get('schema') == 'olm.bundle' and 
                    item.get('package') == package_name):
                    bundle_name = item.get('name', '')
                    
                    # Check if bundle name matches expected pattern
                    if bundle_name == expected_bundle_name:
                        logger.debug(f"Found matching bundle: {bundle_name}")
                        return self._extract_essential_metadata(item)
                    
                    # Also check if the version matches in the olm.package property
                    for prop in item.get('properties', []):
                        if (prop.get('type') == 'olm.package' and 
                            prop.get('value', {}).get('version') == version.lstrip('v')):
                            logger.debug(f"Found bundle by version property: {bundle_name}")
                            return self._extract_essential_metadata(item)
            
            logger.debug(f"No bundle found for version {version}")
            return {}
        
        return []
    
    def _extract_essential_metadata(self, bundle_item: Dict[str, Any]) -> Dict[str, Any]:
        """Extract essential metadata for OLMv1 compatibility assessment"""
        essential_data = {
            'image': bundle_item.get('image', ''),
            'package': bundle_item.get('package', ''),
            'name': bundle_item.get('name', ''),
            'olmv1_compatible': False,
            'install_modes': {},
            'has_webhooks': False
        }
        
        # Parse properties to extract install modes and webhook information
        properties = bundle_item.get('properties', [])
        
        for prop in properties:
            if prop.get('type') == 'olm.csv.metadata':
                csv_metadata = prop.get('value', {})
                
                # Extract install modes
                install_modes = csv_metadata.get('installModes', [])
                for mode in install_modes:
                    mode_type = mode.get('type', '')
                    supported = mode.get('supported', False)
                    essential_data['install_modes'][mode_type] = supported
                
                # Check for AllNamespaces support (OLMv1 compatibility indicator)
                essential_data['olmv1_compatible'] = essential_data['install_modes'].get('AllNamespaces', False)
                
                # Check for webhooks
                webhook_definitions = csv_metadata.get('webhookdefinitions', [])
                api_service_definitions = csv_metadata.get('apiServiceDefinitions', {})
                
                # Check if there are any webhooks or API service definitions
                has_webhook_defs = len(webhook_definitions) > 0
                has_api_services = len(api_service_definitions.get('owned', [])) > 0 or len(api_service_definitions.get('required', [])) > 0
                
                essential_data['has_webhooks'] = has_webhook_defs or has_api_services
                
                break
        
        return essential_data
