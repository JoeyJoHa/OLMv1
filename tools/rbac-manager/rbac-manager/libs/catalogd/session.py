"""
Catalogd Session Manager

Manages persistent connections and sessions for improved performance.
"""

import logging
import socket
import ssl
import time
from typing import Dict, Any, Optional, Tuple

from ..core.exceptions import NetworkError
from ..core.constants import NetworkConstants
from ..core.utils import format_bytes

logger = logging.getLogger(__name__)


class CatalogdSession:
    """Manages persistent connection sessions to catalogd service"""
    
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
        
        # Connection management
        self._socket = None
        self._ssl_socket = None
        self._port_forward = None
        self._connection_time = None
        self._request_count = 0
        
        # Performance tracking
        self._total_request_time = 0.0
        self._total_bytes_received = 0
        
        # Connection settings
        self.connection_timeout = 30
        self.read_timeout = 120
        self.max_requests_per_connection = 10
        self.connection_reuse_timeout = 300  # 5 minutes
    
    def set_port_forward(self, port_forward, socket_obj) -> None:
        """
        Set the port-forward connection and socket
        
        Args:
            port_forward: Port-forward object
            socket_obj: Raw socket object
        """
        self._port_forward = port_forward
        self._socket = socket_obj
        self._connection_time = time.time()
        self._request_count = 0
        
        logger.debug(f"Session initialized with port-forward to {self.service_name}:{self.target_port}")
    
    def _create_ssl_socket(self) -> ssl.SSLSocket:
        """
        Create SSL-wrapped socket for HTTPS communication
        
        Returns:
            ssl.SSLSocket: SSL-wrapped socket
            
        Raises:
            NetworkError: If SSL socket creation fails
        """
        if not self._socket:
            raise NetworkError("No raw socket available for SSL wrapping")
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Configure for better performance
            context.set_ciphers('HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA')
            
            # Wrap socket with SSL
            ssl_socket = context.wrap_socket(
                self._socket,
                server_hostname=f"{self.service_name}.{self.namespace}.svc.cluster.local"
            )
            
            # Configure socket options for performance
            ssl_socket.settimeout(self.read_timeout)
            
            return ssl_socket
            
        except Exception as e:
            raise NetworkError(f"Failed to create SSL socket: {e}")
    
    def _should_reuse_connection(self) -> bool:
        """
        Check if the current connection should be reused
        
        Returns:
            bool: True if connection can be reused
        """
        if not self._ssl_socket or not self._connection_time:
            return False
        
        # Check connection age
        connection_age = time.time() - self._connection_time
        if connection_age > self.connection_reuse_timeout:
            logger.debug(f"Connection too old ({connection_age:.1f}s), creating new one")
            return False
        
        # Check request count
        if self._request_count >= self.max_requests_per_connection:
            logger.debug(f"Max requests per connection reached ({self._request_count}), creating new one")
            return False
        
        return True
    
    def _close_ssl_socket(self) -> None:
        """Close the SSL socket if open"""
        if self._ssl_socket:
            try:
                self._ssl_socket.close()
            except Exception as e:
                logger.debug(f"Error closing SSL socket: {e}")
            finally:
                self._ssl_socket = None
    
    def make_request(self, path: str, headers: Dict[str, str] = None) -> str:
        """
        Make an HTTPS request using session management
        
        Args:
            path: API endpoint path
            headers: Additional HTTP headers
            
        Returns:
            str: Response body
            
        Raises:
            NetworkError: If request fails
        """
        start_time = time.time()
        
        try:
            # Create new SSL socket if needed
            if not self._should_reuse_connection():
                self._close_ssl_socket()
                self._ssl_socket = self._create_ssl_socket()
                logger.debug("Created new SSL socket for request")
            
            headers = headers or {}
            
            # Build HTTP request
            request_lines = [
                f"GET {path} HTTP/1.1",
                f"Host: {self.service_name}.{self.namespace}.svc.cluster.local",
                "Connection: keep-alive",  # Enable connection reuse
                "Accept-Encoding: identity",  # Disable compression for now
                f"User-Agent: {NetworkConstants.USER_AGENT}"
            ]
            
            for key, value in headers.items():
                request_lines.append(f"{key}: {value}")
            
            request_lines.append("")  # Empty line to end headers
            request_lines.append("")  # Empty line to end request
            
            request_data = "\r\n".join(request_lines).encode('utf-8')
            
            # Send request
            logger.debug(f"Sending request: {path} (connection reused: {self._request_count > 0})")
            self._ssl_socket.sendall(request_data)
            
            # Read response with streaming
            response_data = self._read_response_streaming()
            
            # Update statistics
            self._request_count += 1
            request_time = time.time() - start_time
            self._total_request_time += request_time
            self._total_bytes_received += len(response_data)
            
            logger.debug(f"Request completed in {request_time:.2f}s ({len(response_data)} bytes)")
            
            return response_data
            
        except Exception as e:
            # Close connection on error to ensure clean state
            self._close_ssl_socket()
            raise NetworkError(f"Session request failed: {e}")
    
    def _read_response_streaming(self) -> str:
        """
        Read HTTP response with streaming for better performance
        
        Returns:
            str: Response body
            
        Raises:
            NetworkError: If response reading fails
        """
        response_data = b""
        headers_complete = False
        content_length = None
        body_start = 0
        chunk_size = 16384  # 16KB chunks for better performance
        
        try:
            while True:
                chunk = self._ssl_socket.recv(chunk_size)
                if not chunk:
                    break
                
                response_data += chunk
                
                # Parse headers if not done yet
                if not headers_complete and b"\r\n\r\n" in response_data:
                    header_end = response_data.find(b"\r\n\r\n")
                    headers_part = response_data[:header_end].decode('utf-8')
                    body_start = header_end + 4
                    headers_complete = True
                    
                    # Parse headers for optimization
                    content_length, is_chunked, is_compressed = self._parse_response_headers(headers_part)
                    
                    # Validate status code and provide detailed error messages
                    status_line = headers_part.split('\r\n')[0]
                    status_code = int(status_line.split(' ')[1])
                    if status_code != 200:
                        if status_code == 404:
                            raise NetworkError(f"HTTP 404 Not Found: {status_line}")
                        elif status_code == 401:
                            raise NetworkError(f"HTTP 401 Unauthorized: {status_line}")
                        elif status_code == 403:
                            raise NetworkError(f"HTTP 403 Forbidden: {status_line}")
                        elif status_code == 500:
                            raise NetworkError(f"HTTP 500 Internal Server Error: {status_line}")
                        elif status_code == 503:
                            raise NetworkError(f"HTTP 503 Service Unavailable: {status_line}")
                        else:
                            raise NetworkError(f"HTTP request failed with status {status_code}: {status_line}")
                
                # Check if we have complete response
                if headers_complete:
                    body_length = len(response_data) - body_start
                    if content_length is not None and body_length >= content_length:
                        logger.debug(f"Received complete response: {body_length}/{content_length} bytes")
                        break
            
            if not headers_complete:
                raise NetworkError("Invalid HTTP response - no headers found")
            
            # Extract and decompress body
            body_bytes = response_data[body_start:]
            
            # Handle compression
            if is_compressed:
                try:
                    body_bytes = self._decompress_response(body_bytes, is_compressed)
                except Exception as e:
                    logger.debug(f"Decompression failed, using raw data: {e}")
                    # Continue with raw data if decompression fails
            
            return body_bytes.decode('utf-8')
            
        except ssl.SSLWantReadError:
            # Handle SSL read timeouts gracefully
            raise NetworkError(
                "SSL read timeout - connection may be unstable.\n"
                "This could indicate:\n"
                "  • Network connectivity issues\n"
                "  • Catalogd service overload\n"
                "  • Firewall or proxy interference\n\n"
                "Try retrying the request or checking network connectivity."
            )
        except ssl.SSLError as e:
            raise NetworkError(
                f"SSL connection error: {e}\n"
                "This could mean:\n"
                "  • Certificate validation issues\n"
                "  • TLS version mismatch\n"
                "  • Connection interrupted during SSL handshake\n\n"
                "Try adding --skip-tls flag if using self-signed certificates."
            )
        except socket.timeout as e:
            raise NetworkError(
                f"Socket timeout occurred: {e}\n"
                "This usually means:\n"
                "  • The catalogd service is not responding\n"
                "  • Network latency is too high\n"
                "  • The request is taking longer than expected\n\n"
                "Try retrying the request or checking service health."
            )
        except ConnectionResetError as e:
            raise NetworkError(
                f"Connection was reset by the server: {e}\n"
                "This could indicate:\n"
                "  • Catalogd service restarted during request\n"
                "  • Network infrastructure reset the connection\n"
                "  • Load balancer or proxy issues\n\n"
                "Try retrying the request."
            )
        except Exception as e:
            # Check for common error patterns in the exception message
            error_str = str(e)
            if "broken pipe" in error_str.lower():
                raise NetworkError(
                    f"Connection broken during data transfer: {e}\n"
                    "This usually means the connection was interrupted.\n"
                    "Try retrying the request."
                )
            elif "connection aborted" in error_str.lower():
                raise NetworkError(
                    f"Connection aborted: {e}\n"
                    "The connection was terminated unexpectedly.\n"
                    "Try retrying the request."
                )
            else:
                raise NetworkError(f"Failed to read response: {e}")
    
    def _parse_response_headers(self, headers_raw: str) -> Tuple[Optional[int], bool, Optional[str]]:
        """
        Parse HTTP response headers for optimization hints
        
        Args:
            headers_raw: Raw header string
            
        Returns:
            Tuple of (content_length, is_chunked, compression_type)
        """
        content_length = None
        is_chunked = False
        compression_type = None
        
        for line in headers_raw.split('\r\n'):
            line_lower = line.lower()
            if line_lower.startswith('content-length:'):
                content_length = int(line.split(':')[1].strip())
            elif line_lower.startswith('transfer-encoding:') and 'chunked' in line_lower:
                is_chunked = True
            elif line_lower.startswith('content-encoding:'):
                compression_type = line.split(':')[1].strip().lower()
        
        return content_length, is_chunked, compression_type
    
    def _decompress_response(self, data: bytes, compression_type: str) -> bytes:
        """
        Decompress response data
        
        Args:
            data: Compressed data
            compression_type: Type of compression (gzip, deflate)
            
        Returns:
            bytes: Decompressed data
        """
        if compression_type == 'gzip':
            import gzip
            # Check if data is actually gzipped
            if data.startswith(b'\x1f\x8b'):
                return gzip.decompress(data)
            else:
                logger.debug("Data not gzipped despite Content-Encoding header")
                return data
        elif compression_type == 'deflate':
            import zlib
            try:
                return zlib.decompress(data)
            except zlib.error:
                # Try with -15 window bits (raw deflate)
                return zlib.decompress(data, -15)
        else:
            return data
    
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
            'ssl_socket_active': self._ssl_socket is not None
        }
    
    def close(self) -> None:
        """Close the session and clean up resources"""
        self._close_ssl_socket()
        
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
