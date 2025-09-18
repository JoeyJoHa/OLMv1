"""
Catalogd Session Manager

Manages persistent connections and sessions for improved performance.
"""

import gzip
import logging
import socket
import ssl
import time
import zlib
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
                "Accept-Encoding: gzip",  # Enable compression for better performance
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
    
    def _read_headers_and_status(self) -> Tuple[Dict[str, Any], int, bytes]:
        """
        Read and parse HTTP response headers, validate status code
        
        Returns:
            Tuple of (parsed_headers_dict, body_start_position, initial_response_data)
            
        Raises:
            NetworkError: If headers are invalid or status code is not 200
        """
        response_data = b""
        chunk_size = 16384  # 16KB chunks for better performance
        
        # Read until we have complete headers
        while b"\r\n\r\n" not in response_data:
            chunk = self._ssl_socket.recv(chunk_size)
            if not chunk:
                raise NetworkError("Connection closed while reading headers")
            response_data += chunk
        
        # Find where headers end and body begins
        header_end = response_data.find(b"\r\n\r\n")
        headers_part = response_data[:header_end].decode('utf-8')
        body_start = header_end + 4
        
        # Validate status code and provide detailed error messages
        status_line = headers_part.split('\r\n')[0]
        status_code = int(status_line.split(' ')[1])
        if status_code != NetworkConstants.HTTPStatus.OK:
            if status_code == NetworkConstants.HTTPStatus.NOT_FOUND:
                raise NetworkError(f"HTTP 404 Not Found: {status_line}")
            elif status_code == NetworkConstants.HTTPStatus.UNAUTHORIZED:
                raise NetworkError(f"HTTP 401 Unauthorized: {status_line}")
            elif status_code == NetworkConstants.HTTPStatus.FORBIDDEN:
                raise NetworkError(f"HTTP 403 Forbidden: {status_line}")
            elif status_code == NetworkConstants.HTTPStatus.INTERNAL_SERVER_ERROR:
                raise NetworkError(f"HTTP 500 Internal Server Error: {status_line}")
            elif status_code == NetworkConstants.HTTPStatus.SERVICE_UNAVAILABLE:
                raise NetworkError(f"HTTP 503 Service Unavailable: {status_line}")
            else:
                raise NetworkError(f"HTTP request failed with status {status_code}: {status_line}")
        
        # Parse headers for optimization
        content_length, is_chunked, is_compressed = self._parse_response_headers(headers_part)
        
        # Return parsed headers as dictionary for easier access
        headers_dict = {
            'content_length': content_length,
            'is_chunked': is_chunked,
            'is_compressed': is_compressed,
            'status_code': status_code,
            'raw_headers': headers_part
        }
        
        return headers_dict, body_start, response_data
    
    def _read_body(self, headers_dict: Dict[str, Any], body_start: int, initial_data: bytes) -> bytes:
        """
        Read the complete HTTP response body based on headers
        
        Args:
            headers_dict: Parsed headers dictionary from _read_headers_and_status
            body_start: Position where body starts in initial_data
            initial_data: Initial response data containing headers and partial body
            
        Returns:
            bytes: Complete response body
            
        Raises:
            NetworkError: If body reading fails
        """
        content_length = headers_dict['content_length']
        is_compressed = headers_dict['is_compressed']
        chunk_size = 16384  # 16KB chunks for better performance
        
        # Start with any body data we already have
        response_data = initial_data
        
        # Continue reading until we have the complete body
        while True:
            body_length = len(response_data) - body_start
            if content_length is not None and body_length >= content_length:
                logger.debug(f"Received complete response: {body_length}/{content_length} bytes")
                break
            
            # Read more data
            chunk = self._ssl_socket.recv(chunk_size)
            if not chunk:
                break
            response_data += chunk
        
        # Extract body bytes
        body_bytes = response_data[body_start:]
        if content_length is not None:
            body_bytes = body_bytes[:content_length]
        
        # Handle chunked transfer encoding
        if headers_dict['is_chunked']:
            body_bytes = self._decode_chunked_data(body_bytes)
        
        # Handle compression - check both header and data signature
        is_compressed = headers_dict['is_compressed']
        
        if is_compressed or body_bytes.startswith(b'\x1f\x8b'):  # gzip magic bytes
            try:
                if body_bytes.startswith(b'\x1f\x8b'):
                    # Data is gzip compressed regardless of header
                    body_bytes = self._decompress_response(body_bytes, 'gzip')
                elif is_compressed:
                    # Use header-specified compression
                    body_bytes = self._decompress_response(body_bytes, is_compressed)
            except Exception as e:
                logger.debug(f"Decompression failed, using raw data: {e}")
                # Continue with raw data if decompression fails
        
        return body_bytes
    
    def _read_response_streaming(self) -> str:
        """
        Read HTTP response with streaming for better performance
        
        Returns:
            str: Response body
            
        Raises:
            NetworkError: If response reading fails
        """
        try:
            # Step 1: Read and validate headers
            headers_dict, body_start, initial_data = self._read_headers_and_status()
            
            # Step 2: Read complete body
            body_bytes = self._read_body(headers_dict, body_start, initial_data)
            
            # Step 3: Convert to string and return
            return body_bytes.decode('utf-8')
            
        except ssl.SSLWantReadError as e:
            raise NetworkError(f"SSL read timeout: {e}")
        except ssl.SSLError as e:
            raise NetworkError(f"SSL connection error: {e}")
        except socket.timeout as e:
            raise NetworkError(f"Socket timeout: {e}")
        except ConnectionResetError as e:
            raise NetworkError(f"Connection reset by server: {e}")
        except Exception as e:
            # Check for common error patterns in the exception message
            error_str = str(e).lower()
            if "broken pipe" in error_str:
                raise NetworkError(f"Connection broken during data transfer: {e}")
            elif "connection aborted" in error_str:
                raise NetworkError(f"Connection aborted: {e}")
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
    
    def _decode_chunked_data(self, chunked_data: bytes) -> bytes:
        """
        Decode HTTP chunked transfer encoding
        
        Args:
            chunked_data: Raw chunked data
            
        Returns:
            bytes: Decoded data without chunk headers
        """
        decoded_data = b""
        offset = 0
        
        while offset < len(chunked_data):
            # Find the end of the chunk size line
            chunk_size_end = chunked_data.find(b'\r\n', offset)
            if chunk_size_end == -1:
                break
            
            # Parse chunk size (hexadecimal)
            try:
                chunk_size_str = chunked_data[offset:chunk_size_end].decode('ascii')
                chunk_size = int(chunk_size_str, 16)
            except (ValueError, UnicodeDecodeError):
                logger.debug(f"Failed to parse chunk size: {chunked_data[offset:chunk_size_end]}")
                break
            
            # If chunk size is 0, we've reached the end
            if chunk_size == 0:
                break
            
            # Extract the chunk data
            chunk_data_start = chunk_size_end + 2  # Skip \r\n
            chunk_data_end = chunk_data_start + chunk_size
            
            if chunk_data_end <= len(chunked_data):
                decoded_data += chunked_data[chunk_data_start:chunk_data_end]
            
            # Move to the next chunk (skip trailing \r\n)
            offset = chunk_data_end + 2
        
        logger.debug(f"Decoded chunked data: {len(chunked_data)} bytes -> {len(decoded_data)} bytes")
        return decoded_data
    
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
            # Check if data is actually gzipped
            if data.startswith(b'\x1f\x8b'):
                return gzip.decompress(data)
            else:
                logger.debug("Data not gzipped despite Content-Encoding header")
                return data
        elif compression_type == 'deflate':
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
