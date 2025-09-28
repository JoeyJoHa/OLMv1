"""
Catalogd Session Manager

Manages persistent connections and sessions for improved performance using httpx.
Requires httpx library for HTTP client functionality.
"""

import logging
import socket
import time
from typing import Dict, Any, Optional

try:
    import httpx
except ImportError:
    raise ImportError("httpx is required for CatalogdSession. Install with: pip install httpx")

from ..core.exceptions import NetworkError
from ..core.constants import NetworkConstants
from ..core.utils import format_bytes

logger = logging.getLogger(__name__)


class SocketTransport(httpx.HTTPTransport):
    """Custom httpx transport that operates over a pre-existing socket"""
    
    def __init__(self, socket_obj: socket.socket, service_name: str, namespace: str, **kwargs):
        """
        Initialize transport with existing socket
        
        Args:
            socket_obj: Pre-existing socket object from port-forward
            service_name: Name of the catalogd service
            namespace: Namespace of the service
            **kwargs: Additional arguments for HTTPTransport
        """
        # Remove verify from kwargs as we handle it ourselves
        kwargs.pop('verify', None)
        super().__init__(**kwargs)
        self._socket = socket_obj
        self.service_name = service_name
        self.namespace = namespace
        self.host = f"{service_name}.{namespace}.svc.cluster.local"
    
    def handle_request(self, request: httpx.Request) -> httpx.Response:
        """
        Handle HTTP request using the pre-existing socket
        
        Args:
            request: httpx Request object
            
        Returns:
            httpx.Response: Response from the server
        """
        import ssl
        import http.client
        from urllib.parse import urlparse
        
        # Parse the request URL
        parsed = urlparse(str(request.url))
        path = parsed.path
        if parsed.query:
            path += f"?{parsed.query}"
        
        try:
            # Wrap the socket with SSL
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            ssl_socket = context.wrap_socket(self._socket, server_hostname=self.host)
            
            # Create HTTP connection using the SSL socket
            conn = http.client.HTTPSConnection(self.host)
            conn.sock = ssl_socket
            
            # Prepare headers
            headers = dict(request.headers)
            
            # Make the request
            conn.request(request.method, path, body=request.content, headers=headers)
            response = conn.getresponse()
            
            # Read response data
            content = response.read()
            
            # Convert headers to the format httpx expects
            headers_dict = {}
            for header, value in response.headers.items():
                headers_dict[header] = value
            
            # Create httpx Response object
            return httpx.Response(
                status_code=response.status,
                headers=headers_dict,
                content=content,
                request=request
            )
            
        except Exception as e:
            raise httpx.RequestError(f"Socket transport failed: {e}", request=request)


class CatalogdSession:
    """Manages persistent connection sessions to catalogd service using httpx"""
    
    def __init__(self, service_name: str, namespace: str, target_port: int):
        """
        Initialize catalogd session manager
        
        Args:
            service_name: Name of the catalogd service
            namespace: Namespace of the service
            target_port: Target port for connections
        """
        self.service_name = service_name
        self.namespace = namespace
        self.target_port = target_port
        self.local_port = None  # Will be set when port-forward is established
        
        # Connection management
        self._socket = None
        self._port_forward = None
        self._connection_time = None
        self._request_count = 0
        
        # Performance tracking
        self._total_request_time = 0.0
        self._total_bytes_received = 0
        
        # httpx client (will be initialized when socket is available)
        self.client: Optional[httpx.Client] = None
    
    def set_port_forward(self, port_forward, socket_obj, local_port: int = None) -> None:
        """
        Set the port-forward connection and socket, initialize httpx client
        
        Args:
            port_forward: Port-forward object
            socket_obj: Raw socket object
            local_port: Local port for the port-forward (optional)
        """
        self._port_forward = port_forward
        self._socket = socket_obj
        self.local_port = local_port
        self._connection_time = time.time()
        self._request_count = 0
        
        # Initialize httpx client with custom transport for the port-forward socket
        transport = SocketTransport(
            socket_obj, 
            self.service_name, 
            self.namespace,
            verify=False  # Skip SSL verification for port-forward connections
        )
        
        self.client = httpx.Client(
            transport=transport,
            timeout=httpx.Timeout(30.0),
            headers={
                "User-Agent": NetworkConstants.USER_AGENT,
                "Accept-Encoding": "gzip",
                "Connection": "keep-alive"
            }
        )
        
        logger.debug(f"Session initialized with port-forward to {self.service_name}:{self.target_port}")
    
    
    def make_request(self, path: str, headers: Dict[str, str] = None) -> str:
        """
        Make an HTTPS request using httpx client (simplified high-level interface)
        
        Args:
            path: API endpoint path
            headers: Additional HTTP headers
            
        Returns:
            str: Response body
            
        Raises:
            NetworkError: If request fails
        """
        if not self.client:
            raise NetworkError("httpx client not initialized. Call set_port_forward first.")
        
        start_time = time.time()
        
        try:
            # Merge additional headers with defaults
            request_headers = {}
            if headers:
                request_headers.update(headers)
            
            # Make the request using httpx with custom transport (port-forward socket)
            # The SocketTransport will handle routing through the port-forward socket
            url = f"https://{self.service_name}.{self.namespace}.svc.cluster.local{path}"
            
            response = self.client.get(url, headers=request_headers)
            
            # Check response status
            response.raise_for_status()
            
            # Update statistics
            self._request_count += 1
            request_time = time.time() - start_time
            self._total_request_time += request_time
            response_text = response.text
            self._total_bytes_received += len(response_text.encode('utf-8'))
            
            logger.debug(f"Request completed in {request_time:.2f}s ({len(response_text)} chars)")
            
            return response_text
            
        except httpx.HTTPStatusError as e:
            raise NetworkError(f"HTTP {e.response.status_code}: {e.response.reason_phrase}")
        except httpx.RequestError as e:
            raise NetworkError(f"Request failed: {e}")
        except Exception as e:
            raise NetworkError(f"Session request failed: {e}")
    
    def get_session_stats(self) -> Dict[str, Any]:
        """
        Get session performance statistics
        
        Returns:
            Dict with session statistics
        """
        connection_age = time.time() - self._connection_time if self._connection_time else 0
        avg_request_time = self._total_request_time / self._request_count if self._request_count > 0 else 0
        
        return {
            'connection_age_seconds': connection_age,
            'total_requests': self._request_count,
            'total_request_time': self._total_request_time,
            'average_request_time': avg_request_time,
            'total_bytes_received': self._total_bytes_received,
            'connection_reused': self._request_count > 1,
            'httpx_client_active': self.client is not None,
            'transport_type': 'httpx'
        }
    
    def close(self) -> None:
        """Close the session and clean up resources"""
        # Close httpx client
        if self.client:
            try:
                self.client.close()
            except Exception as e:
                logger.debug(f"Error closing httpx client: {e}")
            finally:
                self.client = None
        
        # Close raw socket
        if self._socket:
            try:
                self._socket.close()
            except Exception as e:
                logger.debug(f"Error closing raw socket: {e}")
            finally:
                self._socket = None
        
        # Log session statistics
        if self._request_count > 0:
            stats = self.get_session_stats()
            logger.info(f"Session closed: {self._request_count} requests, "
                       f"{stats['average_request_time']:.2f}s avg, "
                       f"{format_bytes(self._total_bytes_received)} transferred")
    
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
