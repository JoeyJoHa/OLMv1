"""
Core Utilities

Common utility functions used across the RBAC Manager tool.
"""

import logging
import re
import sys
import urllib3
from typing import Type
from .exceptions import ConfigurationError, RBACManagerError, AuthenticationError, CatalogdError, NetworkError
from .constants import ErrorMessages


def setup_logging(debug: bool = False) -> None:
    """
    Set up logging configuration for the application.
    
    Args:
        debug: Enable debug logging level
    """
    level = logging.DEBUG if debug else logging.INFO
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Remove existing handlers to avoid duplicates
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(formatter)
    
    # Add handler to root logger
    root_logger.addHandler(console_handler)
    
    if debug:
        logger = logging.getLogger(__name__)
        logger.debug("Debug mode enabled")


def disable_ssl_warnings() -> None:
    """Disable SSL warnings when --skip-tls is used"""
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def is_output_piped() -> bool:
    """
    Check if output is being piped (not connected to terminal).
    
    Returns:
        bool: True if output is piped, False if connected to terminal
    """
    return not sys.stdout.isatty()


def mask_sensitive_info(text: str, url: str = None, token: str = None) -> str:
    """
    Mask sensitive information in text for logging and debug output.
    
    Args:
        text: Text to mask
        url: URL to mask (optional)
        token: Token to mask (optional)
        
    Returns:
        Text with sensitive information masked
    """
    if not text:
        return text
        
    masked_text = text
    
    # Mask token if provided
    if token and token in masked_text:
        # Extract the token prefix (e.g., "sha256~") and mask the rest
        if '~' in token:
            prefix = token.split('~')[0] + '~'
            masked_token = prefix + "***MASKED***"
        else:
            masked_token = "***MASKED***"
        masked_text = masked_text.replace(token, masked_token)
    
    # Mask URL if provided
    if url and url in masked_text:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.hostname:
                # Extract domain parts and mask the hostname
                hostname_parts = parsed.hostname.split('.')
                if len(hostname_parts) >= 3:
                    # For api.opslab-joe.rh-igc.com -> api.****.com
                    first_part = hostname_parts[0][:3] if len(hostname_parts[0]) > 3 else hostname_parts[0]
                    last_part = hostname_parts[-1]  # .com, .org, etc.
                    masked_hostname = f"{first_part}.****.{last_part}"
                elif len(hostname_parts) == 2:
                    # For domain.com -> ****.com
                    masked_hostname = f"****.{hostname_parts[-1]}"
                else:
                    masked_hostname = "****"
                
                # Mask the port as well
                masked_url = f"{parsed.scheme}://{masked_hostname}:***"
                masked_text = masked_text.replace(url, masked_url)
            else:
                masked_text = masked_text.replace(url, "https://****:***")
        except Exception:
            masked_text = masked_text.replace(url, "https://****:***")
    
    # Generic patterns for common sensitive information
    # Mask bearer tokens
    masked_text = re.sub(r'Bearer [A-Za-z0-9+/=_-]+', 'Bearer ***MASKED***', masked_text)
    
    # Mask basic auth tokens
    masked_text = re.sub(r'Basic [A-Za-z0-9+/=]+', 'Basic ***MASKED***', masked_text)
    
    # Mask OpenShift tokens (sha256~ prefix)
    masked_text = re.sub(r'sha256~[A-Za-z0-9_-]+', 'sha256~***MASKED***', masked_text)
    
    return masked_text


def validate_image_url(image: str) -> bool:
    """
    Validate if the provided string is a valid container image URL.
    
    Args:
        image: Container image URL to validate
        
    Returns:
        bool: True if valid image URL
        
    Raises:
        ConfigurationError: If image URL is invalid
    """
    if not image or not isinstance(image, str):
        raise ConfigurationError("Image URL cannot be empty")
    
    # Basic validation for container image format
    # registry.com/namespace/image:tag or registry.com/namespace/image@sha256:hash
    image_pattern = r'^([a-zA-Z0-9.-]+(?:\:[0-9]+)?\/)?[a-zA-Z0-9._-]+\/[a-zA-Z0-9._-]+(?:\:[a-zA-Z0-9._-]+|@sha256\:[a-fA-F0-9]{64})?$'
    
    if not re.match(image_pattern, image):
        raise ConfigurationError(f"Invalid container image URL format: {image}")
    
    return True


def validate_namespace(namespace: str) -> bool:
    """
    Validate if the provided string is a valid Kubernetes namespace.
    
    Args:
        namespace: Kubernetes namespace to validate
        
    Returns:
        bool: True if valid namespace
        
    Raises:
        ConfigurationError: If namespace is invalid
    """
    if not namespace or not isinstance(namespace, str):
        raise ConfigurationError("Namespace cannot be empty")
    
    # Kubernetes namespace validation
    # Must be lowercase alphanumeric with hyphens, max 63 chars
    if not re.match(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$', namespace):
        raise ConfigurationError(f"Invalid Kubernetes namespace format: {namespace}")
    
    if len(namespace) > 63:
        raise ConfigurationError(f"Namespace too long (max 63 chars): {namespace}")
    
    return True


def validate_openshift_url(url: str) -> bool:
    """
    Validate if the provided string is a valid OpenShift API URL.
    
    Args:
        url: OpenShift API URL to validate
        
    Returns:
        bool: True if valid URL
        
    Raises:
        ConfigurationError: If URL is invalid
    """
    if not url or not isinstance(url, str):
        raise ConfigurationError("OpenShift URL cannot be empty")
    
    # Basic URL validation for OpenShift API
    url_pattern = r'^https?:\/\/[a-zA-Z0-9.-]+(?:\:[0-9]+)?(?:\/.*)?$'
    
    if not re.match(url_pattern, url):
        raise ConfigurationError(f"Invalid OpenShift URL format: {url}")
    
    return True


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename by removing or replacing invalid characters.
    
    Args:
        filename: Original filename
        
    Returns:
        str: Sanitized filename safe for filesystem use
    """
    # Replace invalid characters with underscores
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Remove leading/trailing dots and spaces
    sanitized = sanitized.strip('. ')
    
    # Ensure filename is not empty
    if not sanitized:
        sanitized = "unnamed"
    
    return sanitized


def format_bytes(bytes_count: int) -> str:
    """
    Format byte count into human-readable string.
    
    Args:
        bytes_count: Number of bytes
        
    Returns:
        str: Human-readable byte count (e.g., "1.5 MB")
    """
    if bytes_count == 0:
        return "0 B"
    
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    unit_index = 0
    size = float(bytes_count)
    
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    
    return f"{size:.1f} {units[unit_index]}"


def truncate_string(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    Truncate a string to a maximum length with optional suffix.
    
    Args:
        text: String to truncate
        max_length: Maximum length including suffix
        suffix: Suffix to add when truncating
        
    Returns:
        str: Truncated string
    """
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix


def handle_ssl_error(error: Exception, exception_class: Type[RBACManagerError] = AuthenticationError) -> None:
    """
    Centralized SSL error handling with user-friendly messages
    
    Args:
        error: The caught exception
        exception_class: The specific exception class to raise
        
    Raises:
        RBACManagerError: Appropriate error type with user-friendly message
    """
    error_str = str(error)
    
    if "certificate verify failed" in error_str or "CERTIFICATE_VERIFY_FAILED" in error_str:
        raise exception_class(ErrorMessages.SSL_CERT_VERIFICATION_FAILED)
    elif "SSLError" in error_str or "SSL:" in error_str:
        raise exception_class(ErrorMessages.SSL_CONNECTION_ERROR.format(error=error))
    else:
        # Re-raise original error if not SSL-related
        raise exception_class(f"Connection error: {error}")


def handle_network_error(error: Exception, context: str = "", exception_class: Type[RBACManagerError] = NetworkError) -> None:
    """
    Centralized network error handling with context-specific messages
    
    Args:
        error: The caught exception
        context: Context information for better error messages
        exception_class: The specific exception class to raise
        
    Raises:
        RBACManagerError: Appropriate error type with user-friendly message
    """
    error_str = str(error).lower()
    
    if "timeout" in error_str or "connection" in error_str:
        raise exception_class(f"{context}\n{ErrorMessages.CONNECTION_TIMEOUT}")
    elif "connection refused" in error_str:
        raise exception_class(f"{context}\n{ErrorMessages.CONNECTION_REFUSED}")
    elif "ssl" in error_str and "certificate" in error_str:
        handle_ssl_error(error, exception_class)
    else:
        raise exception_class(f"{context}: {error}")


def handle_api_error(error: Exception, exception_class: Type[RBACManagerError] = None) -> None:
    """
    Centralized API error handling for Kubernetes API exceptions
    
    Args:
        error: The caught exception (ApiException or other)
        exception_class: The specific exception class to raise (defaults to CatalogdError)
        
    Raises:
        RBACManagerError: Appropriate error type with user-friendly message
    """
    if exception_class is None:
        exception_class = CatalogdError
    
    error_str = str(error).lower()
    
    # Check for authentication/authorization errors
    if "unauthorized" in error_str or "401" in error_str:
        raise exception_class(
            "Unauthorized (401). Verify that your token is valid and has permissions. "
            "If passing via shell, ensure correct syntax (zsh/bash: $TOKEN, PowerShell: $env:TOKEN)."
        )
    
    # Check for forbidden errors
    if "forbidden" in error_str or "403" in error_str:
        raise exception_class(
            "Forbidden (403). Your credentials are valid but lack necessary permissions. "
            "Contact your cluster administrator to grant appropriate RBAC permissions."
        )
    
    # Check for SSL/TLS related errors
    if any(ssl_indicator in error_str for ssl_indicator in ["ssl", "certificate", "tls"]):
        handle_ssl_error(error, exception_class)
    
    # Check for connection-related errors
    if any(conn_indicator in error_str for conn_indicator in ["connection", "timeout", "refused"]):
        handle_network_error(error, "API connection failed", exception_class)
    
    # For other errors, re-raise with the original message
    raise exception_class(f"API error: {error}")


def create_user_friendly_error(error_type: str, details: str, suggestions: list = None) -> str:
    """
    Create a user-friendly error message with suggestions
    
    Args:
        error_type: Type of error (e.g., "Authentication Error")
        details: Detailed error description
        suggestions: List of suggested solutions
        
    Returns:
        str: Formatted error message
    """
    message = f"{error_type}: {details}"
    
    if suggestions:
        message += "\n\nSuggested solutions:"
        for i, suggestion in enumerate(suggestions, 1):
            message += f"\n  {i}. {suggestion}"
    
    return message
