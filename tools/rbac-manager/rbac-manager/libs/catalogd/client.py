"""
Catalogd Client

Handles low-level communication with catalogd service including port-forwarding and HTTP requests.
"""

import json
import logging
import socket
import ssl
import time
from typing import Dict, Any, Tuple, Optional

from kubernetes import client
from kubernetes.client.rest import ApiException
from kubernetes.stream import portforward

from ..core.exceptions import CatalogdError, NetworkError
from ..core.utils import format_bytes

logger = logging.getLogger(__name__)


class PortForwardManager:
    """Manages native Kubernetes port-forwarding to catalogd service"""
    
    def __init__(self, core_api: client.CoreV1Api, service_name: str, 
                 namespace: str, target_port: int, local_port: int):
        """
        Initialize port-forward manager
        
        Args:
            core_api: Kubernetes CoreV1Api client
            service_name: Name of the service to port-forward to
            namespace: Namespace of the service
            target_port: Target port inside the pod
            local_port: Local port to bind to
        """
        self.core_api = core_api
        self.service_name = service_name
        self.namespace = namespace
        self.target_port = target_port
        self.local_port = local_port
        self._socket = None
        self._pf = None
    
    def _find_service_pod(self) -> str:
        """
        Find a running pod that backs the target service
        
        Returns:
            str: Name of the pod to use for port-forwarding
            
        Raises:
            CatalogdError: If no suitable pod is found
        """
        try:
            # Get service to find selector
            service = self.core_api.read_namespaced_service(
                name=self.service_name,
                namespace=self.namespace
            )
            
            selector = service.spec.selector
            if not selector:
                raise CatalogdError(f"Service {self.service_name} has no selector")
            
            # Convert selector dict to label selector string
            label_selector = ','.join([f"{k}={v}" for k, v in selector.items()])
            
            # Find pods matching the selector
            pods = self.core_api.list_namespaced_pod(
                namespace=self.namespace,
                label_selector=label_selector
            )
            
            # Find a running pod
            for pod in pods.items:
                if pod.status.phase == 'Running':
                    logger.debug(f"Using pod {pod.metadata.name} for port-forward to service {self.service_name}")
                    return pod.metadata.name
            
            raise CatalogdError(f"No running pods found for service {self.service_name}")
            
        except ApiException as e:
            raise CatalogdError(f"Failed to find pod for service {self.service_name}: {e}")
        except Exception as e:
            raise CatalogdError(f"Failed to find pod for service {self.service_name}: {e}")
    
    def start(self) -> None:
        """
        Start the port-forward connection
        
        Raises:
            CatalogdError: If port-forward cannot be established
        """
        try:
            pod_name = self._find_service_pod()
            
            # Create port-forward connection using the correct API
            self._pf = portforward(
                self.core_api.connect_get_namespaced_pod_portforward,
                pod_name,
                self.namespace,
                ports=str(self.target_port)
            )
            
            # Get the socket from port-forward
            self._socket = self._pf.socket(self.target_port)
            
            logger.debug(f"Native port-forward socket created for pod {pod_name}:{self.target_port}")
            
        except Exception as e:
            raise CatalogdError(f"Failed to start native port-forward: {e}")
    
    def make_http_request(self, path: str, headers: Dict[str, str] = None) -> str:
        """
        Make HTTPS request through the port-forward socket
        
        Args:
            path: API endpoint path
            headers: Additional HTTP headers
            
        Returns:
            str: Response body
            
        Raises:
            NetworkError: If HTTP request fails
        """
        if not self._socket:
            raise NetworkError("Port-forward not established")

        headers = headers or {}

        # Wrap socket with SSL for HTTPS
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Skip certificate verification for port-forward

        try:
            # Wrap the socket with SSL
            ssl_socket = context.wrap_socket(
                self._socket, 
                server_hostname=f"{self.service_name}.{self.namespace}.svc.cluster.local"
            )

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
                raise NetworkError("Invalid HTTPS response received - no headers")

            headers_raw = response_data[:body_start - 4].decode('utf-8')
            body_bytes = response_data[body_start:]

            # Status line and headers
            status_line = headers_raw.split("\r\n", 1)[0]
            status_code = int(status_line.split(" ")[1])
            if status_code != 200:
                raise NetworkError(f"HTTPS request failed with status {status_code}: {status_line}")

            # Handle Content-Encoding (gzip/deflate)
            content_encoding = None
            for line in headers_raw.split('\r\n'):
                if line.lower().startswith('content-encoding:'):
                    content_encoding = line.split(':')[1].strip().lower()
                    break

            if content_encoding == 'gzip':
                import gzip
                body_bytes = gzip.decompress(body_bytes)
            elif content_encoding == 'deflate':
                import zlib
                body_bytes = zlib.decompress(body_bytes)

            return body_bytes.decode('utf-8')

        except Exception as e:
            raise NetworkError(f"HTTPS request through socket failed: {e}")
        finally:
            try:
                ssl_socket.close()
            except:
                pass
    
    def stop(self) -> None:
        """Stop the port-forward connection"""
        try:
            if self._socket:
                self._socket.close()
                self._socket = None
            if self._pf:
                self._pf = None
            logger.debug("Port-forward connection closed")
        except Exception as e:
            logger.warning(f"Error closing port-forward: {e}")
    
    def poll(self) -> Optional[int]:
        """Check if port-forward is still active (compatibility method)"""
        return None if self._socket else 1
    
    def __enter__(self):
        """Context manager entry"""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.stop()


class CatalogdClient:
    """Low-level client for communicating with catalogd service"""
    
    def __init__(self, core_api: client.CoreV1Api, skip_tls: bool = False):
        """
        Initialize catalogd client
        
        Args:
            core_api: Kubernetes CoreV1Api client
            skip_tls: Whether to skip TLS verification
        """
        self.core_api = core_api
        self.skip_tls = skip_tls
    
    def discover_catalogd_service(self) -> Tuple[str, int, int, bool]:
        """
        Discover catalogd service details
        
        Returns:
            Tuple of (service_name, service_port, target_port, is_https)
            
        Raises:
            CatalogdError: If service discovery fails
        """
        try:
            # List services in openshift-catalogd namespace
            services = self.core_api.list_namespaced_service(namespace="openshift-catalogd")
            
            for service in services.items:
                if "catalogd" in service.metadata.name.lower():
                    # Found catalogd service
                    service_name = service.metadata.name
                    
                    # Find HTTPS port (usually 443 -> 8443)
                    service_port = None
                    target_port = None
                    is_https = False
                    
                    for port in service.spec.ports:
                        if port.name and "https" in port.name.lower():
                            service_port = port.port
                            target_port = port.target_port
                            is_https = True
                            break
                    
                    if service_port is None:
                        # Fallback to first port
                        first_port = service.spec.ports[0]
                        service_port = first_port.port
                        target_port = first_port.target_port
                        is_https = service_port == 443
                    
                    logger.debug(f"Discovered catalogd service: {service_name} ({service_port}->{target_port})")
                    return service_name, service_port, target_port, is_https
            
            raise CatalogdError("No catalogd service found in openshift-catalogd namespace")
            
        except ApiException as e:
            logger.debug(f"Service discovery failed: {e}")
            raise CatalogdError(f"Failed to discover catalogd service: {e}")
        except Exception as e:
            raise CatalogdError(f"Failed to discover catalogd service: {e}")
    
    def create_port_forward(self) -> Tuple[PortForwardManager, int, bool]:
        """
        Create port-forward to catalogd service
        
        Returns:
            Tuple of (port_forward_manager, local_port, is_https)
            
        Raises:
            CatalogdError: If port-forward creation fails
        """
        try:
            if not self.core_api:
                raise CatalogdError("Kubernetes client not initialized. Provide a valid kubeconfig or use --openshift-url/--openshift-token to query without port-forwarding.")
            
            logger.info("Setting up port-forward to catalogd service...")
            
            # Find an available port
            sock = socket.socket()
            sock.bind(('', 0))
            local_port = sock.getsockname()[1]
            sock.close()
            
            # Discover target service/port
            service_name, service_port, target_port, is_https = self.discover_catalogd_service()
            
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
            raise CatalogdError(error_message)
    
    def make_catalogd_request(self, url: str, port_forward_manager: PortForwardManager, 
                             auth_headers: Dict[str, str] = None) -> str:
        """
        Make API request to catalogd service via port-forward
        
        Args:
            url: API endpoint path
            port_forward_manager: Port-forward manager instance
            auth_headers: Authentication headers
            
        Returns:
            str: Raw response body
            
        Raises:
            CatalogdError: If request fails
        """
        if not port_forward_manager:
            raise CatalogdError("Port-forward is required for catalogd queries. Ensure port-forward is established and retry.")
        
        headers = auth_headers or {}
        
        try:
            logger.debug(f"Making request through native port-forward: {url}")
            text_body = port_forward_manager.make_http_request(url, headers)
            return text_body
        except Exception as e:
            logger.error(f"Request failed: {e}")
            raise CatalogdError(f"Request failed: {e}")
