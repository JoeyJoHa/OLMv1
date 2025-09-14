"""
Catalog Manager

Handles operations related to OpenShift catalogs and catalogd service.
"""

import json
import logging
import socket
import sys
import time
from typing import Dict, List, Optional, Any, Tuple

import requests
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes.stream import portforward
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
    
    def _discover_catalogd_service(self) -> Tuple[str, int, int, bool]:
        """Discover catalogd service name and preferred port.

        Returns:
            Tuple[str, int, int, bool]: (service name, service port, target port, is_https)
        """
        try:
            svc_list = self.core_api.list_namespaced_service(namespace="openshift-catalogd")
            candidates: List[Tuple[str, int, int, bool]] = []
            for svc in svc_list.items:
                name = svc.metadata.name or ""
                if "catalogd" not in name:
                    continue
                for port in (svc.spec.ports or []):
                    port_num = int(port.port)
                    target_port = int(port.target_port) if port.target_port else port_num
                    name_lower = (port.name or "").lower()
                    is_https = port_num == 443 or "https" in name_lower
                    # prefer https then http
                    pref = 0
                    if is_https:
                        pref = 2
                    elif port_num == 80 or "http" in name_lower:
                        pref = 1
                    candidates.append((name, port_num, target_port, is_https, pref))
            if candidates:
                # sort by preference desc then by name for stability
                candidates.sort(key=lambda x: (x[4], x[0]), reverse=True)
                service_name, svc_port, target_port, is_https = candidates[0][0], candidates[0][1], candidates[0][2], candidates[0][3]
                return service_name, svc_port, target_port, is_https
        except Exception as e:
            logger.debug(f"Service discovery failed: {e}")
        # Fallback to common defaults
        return "catalogd-service", 443, 8443, True

    def port_forward_catalogd(self) -> Tuple['PortForwardManager', int, bool]:
        """Port-forward the catalogd service using native Python Kubernetes client"""
        logger.info("Setting up port-forward to catalogd service...")
        
        # Find an available port
        sock = socket.socket()
        sock.bind(('', 0))
        local_port = sock.getsockname()[1]
        sock.close()
        
        # Discover target service/port
        service_name, service_port, target_port, is_https = self._discover_catalogd_service()
        
        try:
            # Create port-forward connection
            pf_manager = PortForwardManager(
                self.core_api,
                service_name,
                "openshift-catalogd",
                target_port,
                local_port
            )
            
            # Establish the port-forward
            pf_manager.start()
            
            logger.info(f"Port-forward established to service/{service_name} ({service_port}->{target_port}) on local port {local_port}")
            return pf_manager, local_port, is_https
            
        except Exception as e:
            error_message = f"Failed to establish port-forward: {e}"
            logger.error(error_message)
            raise Exception(error_message)
    
    def make_catalogd_request(self, url: str, openshift_url: str = None, 
                            openshift_token: str = None, port_forward_manager: 'PortForwardManager' = None) -> Dict[str, Any]:
        """Make API request to catalogd service"""
        headers = {}
        
        if openshift_token:
            headers['Authorization'] = f'Bearer {openshift_token}'
        
        try:
            if openshift_url:
                # Direct API call to OpenShift
                full_url = f"{openshift_url.rstrip('/')}/{url.lstrip('/')}"
                logger.debug(f"Making request to: {full_url}")
                
                verify_ssl = not self.skip_tls
                response = requests.get(full_url, headers=headers, verify=verify_ssl, timeout=30)
                response.raise_for_status()
                text_body = response.text
                
            elif port_forward_manager:
                # Use native port-forward socket
                logger.debug(f"Making request through native port-forward: {url}")
                text_body = port_forward_manager.make_http_request(url, headers)
                
            else:
                raise Exception("Either openshift_url or port_forward_manager must be provided")
                
        except Exception as e:
            logger.error(f"Request failed: {e}")
            raise

        # Parse body as NDJSON (newline-delimited JSON) efficiently
        return self._parse_ndjson_stream(text_body)
    
    def _parse_ndjson_stream(self, text_body: str) -> List[Dict[str, Any]]:
        """Parse NDJSON (newline-delimited JSON) stream efficiently"""
        import json as _json
        
        logger.debug(f"Parsing NDJSON response ({len(text_body)} bytes)")
        logger.debug(f"First 500 chars: {text_body[:500]}")
        logger.debug(f"Last 500 chars: {text_body[-500:]}")
        
        # Parse line by line (NDJSON format)
        items = []
        lines = text_body.strip().split('\n')
        logger.debug(f"Split into {len(lines)} lines")
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
                
            try:
                obj = _json.loads(line)
                items.append(obj)
            except _json.JSONDecodeError as e:
                logger.debug(f"Failed to parse JSON line {line_num}: {e}")
                logger.debug(f"Problematic line: {line[:200]}...")
                # Continue parsing other lines
                continue
        
        logger.info(f"Successfully parsed {len(items)} JSON objects from NDJSON stream")
        return items
    
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
    
    def _fetch_catalog_metadata(self, catalog_name: str, port_forward_manager: 'PortForwardManager' = None, 
                               openshift_url: str = None, openshift_token: str = None) -> List[Dict[str, Any]]:
        """Fetch raw catalog metadata from catalogd API"""
        url = f"/catalogs/{catalog_name}/api/v1/all"
        
        logger.debug(f"Making request to: {url}")
        return self.make_catalogd_request(url, openshift_url, openshift_token, port_forward_manager)
    
    def fetch_catalog_packages(self, catalog_name: str, port_forward_manager: 'PortForwardManager' = None, 
                             openshift_url: str = None, openshift_token: str = None) -> List[Dict[str, Any]]:
        """Fetch all packages from a catalog"""
        logger.info(f"Fetching packages from catalog: {catalog_name}")
        data = self._fetch_catalog_metadata(catalog_name, port_forward_manager, openshift_url, openshift_token)
        
        # Parse the JSON output to extract packages
        packages = self._parse_catalog_data(data, 'packages')
        logger.info(f"Found {len(packages)} packages in catalog {catalog_name}")
        
        return packages
    
    def fetch_package_channels(self, catalog_name: str, package_name: str, port_forward_manager: 'PortForwardManager' = None,
                             openshift_url: str = None, openshift_token: str = None) -> List[Dict[str, Any]]:
        """Fetch all channels for a package"""
        logger.info(f"Fetching channels for package: {package_name}")
        data = self._fetch_catalog_metadata(catalog_name, port_forward_manager, openshift_url, openshift_token)
        
        # Parse the JSON output to extract channels for the specific package
        channels = self._parse_catalog_data(data, 'channels', package_name)
        logger.info(f"Found {len(channels)} channels for package {package_name}")
        
        return channels
    
    def fetch_channel_versions(self, catalog_name: str, package_name: str, channel_name: str, 
                             port_forward_manager: 'PortForwardManager' = None, openshift_url: str = None, openshift_token: str = None) -> List[Dict[str, Any]]:
        """Fetch all versions for a channel"""
        logger.info(f"Fetching versions for channel: {channel_name}")
        data = self._fetch_catalog_metadata(catalog_name, port_forward_manager, openshift_url, openshift_token)
        
        # Parse the JSON output to extract versions for the specific channel
        versions = self._parse_catalog_data(data, 'versions', package_name, channel_name)
        logger.info(f"Found {len(versions)} versions for channel {channel_name}")
        
        return versions
    
    def fetch_version_metadata(self, catalog_name: str, package_name: str, channel_name: str, 
                             version: str, port_forward_manager: 'PortForwardManager' = None, openshift_url: str = None, 
                             openshift_token: str = None) -> Dict[str, Any]:
        """Fetch metadata for a specific version"""
        logger.info(f"Fetching metadata for version: {version}")
        data = self._fetch_catalog_metadata(catalog_name, port_forward_manager, openshift_url, openshift_token)
        
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


class PortForwardManager:
    """Manages native Python Kubernetes port-forwarding using direct socket communication"""
    
    def __init__(self, core_api: client.CoreV1Api, service_name: str, namespace: str, 
                 target_port: int, local_port: int):
        self.core_api = core_api
        self.service_name = service_name
        self.namespace = namespace
        self.target_port = target_port
        self.local_port = local_port
        self.pf = None
        self._socket = None
        self._pod_name = None
        
    def _find_service_pod(self) -> str:
        """Find a pod that backs the service"""
        try:
            # Get the service to find its selector
            service = self.core_api.read_namespaced_service(
                name=self.service_name, 
                namespace=self.namespace
            )
            
            if not service.spec.selector:
                raise Exception(f"Service {self.service_name} has no selector")
            
            # Build label selector from service selector
            label_selector = []
            for key, value in service.spec.selector.items():
                label_selector.append(f"{key}={value}")
            
            # Find pods matching the selector
            pods = self.core_api.list_namespaced_pod(
                namespace=self.namespace,
                label_selector=",".join(label_selector)
            )
            
            if not pods.items:
                raise Exception(f"No pods found for service {self.service_name}")
            
            # Use the first running pod
            for pod in pods.items:
                if pod.status.phase == 'Running':
                    return pod.metadata.name
            
            # If no running pods, use the first available
            return pods.items[0].metadata.name
            
        except Exception as e:
            logger.error(f"Failed to find pod for service {self.service_name}: {e}")
            raise
        
    def start(self):
        """Start the native port-forward connection"""
        try:
            # Find a pod that backs the service
            self._pod_name = self._find_service_pod()
            logger.debug(f"Using pod {self._pod_name} for port-forward to service {self.service_name}")
            
            # Create port-forward connection to the pod
            self.pf = portforward(
                self.core_api.connect_get_namespaced_pod_portforward,
                name=self._pod_name,
                namespace=self.namespace,
                ports=str(self.target_port)
            )
            
            # Get the socket for the target port
            self._socket = self.pf.socket(self.target_port)
            if not self._socket:
                raise Exception(f"Failed to create socket for port {self.target_port}")
                
            logger.debug(f"Native port-forward socket created for pod {self._pod_name}:{self.target_port}")
            
        except Exception as e:
            logger.error(f"Failed to start native port-forward: {e}")
            raise
    
    def make_http_request(self, path: str, headers: Dict[str, str] = None) -> str:
        """Make HTTPS request through the port-forward socket"""
        if not self._socket:
            raise Exception("Port-forward not established")
        
        headers = headers or {}
        
        # Wrap socket with SSL for HTTPS
        import ssl
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Skip certificate verification for port-forward
        
        try:
            # Wrap the socket with SSL
            ssl_socket = context.wrap_socket(self._socket, server_hostname=f"{self.service_name}.{self.namespace}.svc.cluster.local")
            
            # Build HTTPS request
            request_lines = [
                f"GET {path} HTTP/1.1",
                f"Host: {self.service_name}.{self.namespace}.svc.cluster.local",
                "Connection: close"
            ]
            
            for key, value in headers.items():
                request_lines.append(f"{key}: {value}")
            
            request_lines.append("")  # Empty line to end headers
            request_lines.append("")  # Empty line to end request
            
            request_data = "\r\n".join(request_lines).encode('utf-8')
            
            # Send HTTPS request through the SSL socket
            ssl_socket.sendall(request_data)
            
            # Read response
            response_data = b""
            headers_complete = False
            content_length = None
            body_start = 0
            
            while True:
                try:
                    chunk = ssl_socket.recv(8192)  # Increased buffer size
                    if not chunk:
                        break
                    response_data += chunk
                    
                    # Parse headers if not done yet
                    if not headers_complete and b"\r\n\r\n" in response_data:
                        header_end = response_data.find(b"\r\n\r\n")
                        headers_part = response_data[:header_end].decode('utf-8')
                        body_start = header_end + 4
                        headers_complete = True
                        
                        # Parse Content-Length
                        for line in headers_part.split('\r\n'):
                            if line.lower().startswith('content-length:'):
                                content_length = int(line.split(':')[1].strip())
                                logger.debug(f"Content-Length: {content_length}")
                                break
                    
                    # Check if we have all the data
                    if headers_complete:
                        body_length = len(response_data) - body_start
                        if content_length is not None:
                            if body_length >= content_length:
                                logger.debug(f"Received complete response: {body_length}/{content_length} bytes")
                                break
                        else:
                            # For responses without Content-Length, continue until connection closes
                            continue
                            
                except ssl.SSLWantReadError:
                    continue
                except Exception as e:
                    logger.debug(f"SSL read error: {e}")
                    break
            
            # Parse HTTP response (handle chunked transfer and compression)
            if not headers_complete:
                raise Exception("Invalid HTTPS response received - no headers")

            headers_raw = response_data[:body_start - 4].decode('utf-8')
            body_bytes = response_data[body_start:]

            # Status line and headers
            status_line = headers_raw.split("\r\n", 1)[0]
            try:
                status_code = int(status_line.split(" ")[1])
            except Exception:
                status_code = 0
            if status_code < 200 or status_code >= 300:
                raise Exception(f"HTTPS request failed: {status_line}")

            headers_map: Dict[str, str] = {}
            for line in headers_raw.split("\r\n")[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers_map[k.strip().lower()] = v.strip()

            # Handle chunked transfer-encoding
            if 'transfer-encoding' in headers_map and 'chunked' in headers_map['transfer-encoding'].lower():
                body_bytes = self._decode_chunked(body_bytes)

            # Handle compression
            content_encoding = headers_map.get('content-encoding', '').lower()
            if 'gzip' in content_encoding:
                import gzip
                body_bytes = gzip.decompress(body_bytes)
            elif 'deflate' in content_encoding:
                import zlib
                body_bytes = zlib.decompress(body_bytes)

            # Decode to text
            text_body = body_bytes.decode('utf-8', errors='replace')
            return text_body
                
        except Exception as e:
            logger.error(f"HTTPS request through socket failed: {e}")
            raise
        finally:
            try:
                ssl_socket.close()
            except:
                pass

    def _decode_chunked(self, data: bytes) -> bytes:
        """Decode HTTP/1.1 chunked transfer-encoding payload"""
        i = 0
        out = bytearray()
        length = len(data)
        while True:
            j = data.find(b"\r\n", i)
            if j == -1:
                break
            size_line = data[i:j].decode('ascii', errors='ignore').strip()
            if ';' in size_line:
                size_line = size_line.split(';', 1)[0]
            try:
                size = int(size_line, 16)
            except Exception:
                break
            i = j + 2
            if size == 0:
                # optional trailers end with CRLF; we're done
                break
            if i + size > length:
                # incomplete buffer
                out += data[i:]
                break
            out += data[i:i + size]
            i += size
            # skip CRLF after chunk
            if data[i:i + 2] == b"\r\n":
                i += 2
        return bytes(out)
    
    def stop(self):
        """Stop the port-forward connection"""
        try:
            if self._socket:
                self._socket.close()
                self._socket = None
            if self.pf:
                # Check for any errors
                error = self.pf.error(self.target_port)
                if error:
                    logger.warning(f"Port-forward error on port {self.target_port}: {error}")
                self.pf = None
            logger.debug("Port-forward connection closed")
        except Exception as e:
            logger.warning(f"Error closing port-forward: {e}")
    
    def poll(self) -> Optional[int]:
        """Check if the port-forward is still active"""
        return None if self._socket else 1
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.stop()
