"""
Catalogd Client

Handles low-level communication with catalogd service including port-forwarding and HTTP requests.
"""

import json
import logging
import socket
import time
from typing import Dict, Any, Tuple, Optional

from kubernetes import client
from kubernetes.client.rest import ApiException
from kubernetes.stream import portforward

from ..core.exceptions import CatalogdError, NetworkError
from ..core.utils import format_bytes, handle_ssl_error
from ..core.constants import KubernetesConstants, NetworkConstants, ErrorMessages
from .cache import CatalogdCache
from .session import CatalogdSession

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
    
    def __init__(self, core_api: client.CoreV1Api, skip_tls: bool = False, 
                 enable_cache: bool = True, cache_ttl: int = 300):
        """
        Initialize catalogd client
        
        Args:
            core_api: Kubernetes CoreV1Api client
            skip_tls: Whether to skip TLS verification
            enable_cache: Whether to enable response caching
            cache_ttl: Cache time-to-live in seconds
        """
        self.core_api = core_api
        self.skip_tls = skip_tls
        
        # Performance enhancements
        self.cache = CatalogdCache(ttl=cache_ttl) if enable_cache else None
        self._session = None
        self._current_catalog = None
    
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
            services = self.core_api.list_namespaced_service(namespace=KubernetesConstants.OPENSHIFT_CATALOGD_NAMESPACE)
            
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
                        is_https = service_port == NetworkConstants.HTTPS_PORT
                    
                    logger.debug(f"Discovered catalogd service: {service_name} ({service_port}->{target_port})")
                    return service_name, service_port, target_port, is_https
            
            raise CatalogdError(ErrorMessages.CATALOGD_SERVICE_NOT_FOUND)
            
        except ApiException as e:
            logger.debug(f"Service discovery failed: {e}")
            raise CatalogdError(f"Failed to discover catalogd service: {e}")
        except Exception as e:
            # Use centralized SSL error handler
            handle_ssl_error(e, CatalogdError)
    
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
            
            # Discover target service/port
            service_name, service_port, target_port, is_https = self.discover_catalogd_service()
            
            # Find an available local port
            import socket
            sock = socket.socket()
            sock.bind(('', 0))
            local_port = sock.getsockname()[1]
            sock.close()
            
            # Create port-forward connection
            pf_manager = PortForwardManager(
                self.core_api,
                service_name,
                KubernetesConstants.OPENSHIFT_CATALOGD_NAMESPACE,
                target_port,
                local_port
            )
            
            # Establish the port-forward
            pf_manager.start()
            
            # Initialize session manager for performance
            self._session = CatalogdSession(service_name, KubernetesConstants.OPENSHIFT_CATALOGD_NAMESPACE, target_port)
            self._session.set_port_forward(pf_manager._pf, pf_manager._socket)
            
            logger.info(f"Port-forward established to service/{service_name} ({service_port}->{target_port}) on local port {local_port}")
            return pf_manager, local_port, is_https
            
        except Exception as e:
            error_message = f"Failed to establish port-forward: {e}"
            logger.error(error_message)
            raise CatalogdError(error_message)
    
    def make_catalogd_request(self, url: str, port_forward_manager: PortForwardManager, 
                             auth_headers: Dict[str, str] = None, catalog_name: str = None) -> str:
        """
        Make API request to catalogd service with caching and session management
        
        Args:
            url: API endpoint path
            port_forward_manager: Port-forward manager instance
            auth_headers: Authentication headers
            catalog_name: Catalog name for cache key generation
            
        Returns:
            str: Raw response body
            
        Raises:
            CatalogdError: If request fails
        """
        if not port_forward_manager:
            raise CatalogdError("Port-forward is required for catalogd queries. Ensure port-forward is established and retry.")
        
        # Check cache first
        if self.cache and catalog_name:
            cached_response = self.cache.get(catalog_name, url)
            if cached_response:
                logger.debug(f"Cache hit for {catalog_name}{url}")
                return cached_response
        
        headers = auth_headers or {}
        
        try:
            # Use session manager for all requests
            if not self._session:
                raise CatalogdError("Session manager not initialized. Ensure port-forward is established.")
            
            logger.debug(f"Making request through session manager: {url}")
            text_body = self._session.make_request(url, headers)
            
            # Cache the response
            if self.cache and catalog_name and text_body:
                self.cache.put(catalog_name, url, text_body)
            
            return text_body
            
        except NetworkError as e:
            # Handle network-specific errors with enhanced messages
            error_str = str(e)
            if "404" in error_str or "Not Found" in error_str:
                available_catalogs = self._get_available_catalogs_hint()
                raise CatalogdError(
                    f"Catalog '{catalog_name}' not found on the cluster.\n"
                    f"This could mean:\n"
                    f"  • The catalog name is misspelled\n"
                    f"  • The catalog is not installed on this cluster\n"
                    f"  • The catalog is not in 'Serving' state\n\n"
                    f"Available catalogs: {available_catalogs}\n\n"
                    f"To list all available catalogs, run:\n"
                    f"  python3 rbac-manager.py --list-catalogs"
                )
            elif "timeout" in error_str.lower() or "connection" in error_str.lower():
                raise CatalogdError(
                    f"Connection timeout or network error occurred.\n"
                    f"This could mean:\n"
                    f"  • The catalogd service is not responding\n"
                    f"  • Network connectivity issues to the cluster\n"
                    f"  • The port-forward connection was interrupted\n\n"
                    f"Try:\n"
                    f"  • Checking cluster connectivity: kubectl get pods -n openshift-catalogd\n"
                    f"  • Retrying the command\n"
                    f"  • Using --debug flag for more detailed logs\n\n"
                    f"Original error: {e}"
                )
            elif "unauthorized" in error_str.lower() or "403" in error_str:
                raise CatalogdError(
                    f"Authentication or authorization error.\n"
                    f"This could mean:\n"
                    f"  • Your token has expired or is invalid\n"
                    f"  • Insufficient permissions to access catalogd service\n"
                    f"  • RBAC restrictions on the openshift-catalogd namespace\n\n"
                    f"Try:\n"
                    f"  • Refreshing your authentication token\n"
                    f"  • Checking cluster access: oc whoami\n"
                    f"  • Verifying permissions: oc auth can-i get pods -n openshift-catalogd\n\n"
                    f"Original error: {e}"
                )
            else:
                raise CatalogdError(f"Network error: {e}")
        except Exception as e:
            logger.error(f"Request failed: {e}")
            # Check for common error patterns
            error_str = str(e)
            if "connection refused" in error_str.lower():
                raise CatalogdError(
                    f"Connection refused to catalogd service.\n"
                    f"This usually means:\n"
                    f"  • The catalogd service is not running\n"
                    f"  • Port-forward failed to establish\n"
                    f"  • Firewall or network policy blocking connection\n\n"
                    f"Try:\n"
                    f"  • Checking catalogd status: kubectl get pods -n openshift-catalogd\n"
                    f"  • Verifying service: kubectl get svc -n openshift-catalogd\n"
                    f"  • Retrying with --debug for detailed logs"
                )
            elif "ssl" in error_str.lower() and "certificate" in error_str.lower():
                raise CatalogdError(
                    f"SSL certificate error occurred.\n"
                    f"If using self-signed certificates, add --skip-tls flag.\n"
                    f"Original error: {e}"
                )
            else:
                raise CatalogdError(f"Request failed: {e}")
    
    def _get_available_catalogs_hint(self) -> str:
        """Get a hint about available catalogs for error messages"""
        try:
            if self.core_api:
                # Try to get a quick list of common catalog names
                services = self.core_api.list_namespaced_service(namespace=KubernetesConstants.OPENSHIFT_CATALOGD_NAMESPACE)
                if services.items:
                    return "Use --list-catalogs to see all available catalogs"
                else:
                    return "No catalogd services found (catalogd may not be installed)"
        except Exception:
            pass
        return "Use --list-catalogs to see available catalogs"
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """
        Get performance statistics for the client
        
        Returns:
            Dict with performance statistics
        """
        stats = {
            'cache_enabled': self.cache is not None,
            'session_active': self._session is not None
        }
        
        if self.cache:
            stats['cache_stats'] = self.cache.get_cache_stats()
        
        if self._session:
            stats['session_stats'] = self._session.get_session_stats()
        
        return stats
    
    def close(self) -> None:
        """Close client and clean up resources"""
        if self._session:
            self._session.close()
            self._session = None
