"""
Core Utilities

Common utility functions used across the RBAC Manager tool.
"""

import logging
import re
import sys
from typing import Type, Optional
from urllib.parse import urlparse
from .exceptions import ConfigurationError, RBACManagerError, AuthenticationError, CatalogdError, NetworkError
from .constants import ErrorMessages


def setup_logging(debug: bool = False) -> None:
    """
    Set up logging configuration for the application.
    Separates WARNING/INFO to stdout and ERROR to stderr.
    
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
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Create stdout handler for INFO, WARNING, DEBUG
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(level)
    stdout_handler.setFormatter(formatter)
    # Filter to only handle INFO, WARNING, DEBUG (not ERROR)
    stdout_handler.addFilter(lambda record: record.levelno < logging.ERROR)
    
    # Create stderr handler for ERROR and CRITICAL only
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.ERROR)
    stderr_handler.setFormatter(formatter)
    
    # Add handlers to root logger
    root_logger.addHandler(stdout_handler)
    root_logger.addHandler(stderr_handler)
    
    if debug:
        logger = logging.getLogger(__name__)
        logger.debug("Debug mode enabled")


def is_output_piped() -> bool:
    """
    Check if output is being piped (not connected to terminal).
    
    Returns:
        bool: True if output is piped, False if connected to terminal
    """
    return not sys.stdout.isatty()


def mask_sensitive_info(text: str, url: Optional[str] = None, token: Optional[str] = None) -> str:
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


class ValidationConfig:
    """
    Configuration-driven validation patterns.
    
    Centralizes validation patterns, error messages, and constraints
    to eliminate code duplication across validation functions.
    """
    
    IMAGE_URL = {
        'pattern': r'^([a-zA-Z0-9.-]+(?:\:[0-9]+)?\/)?[a-zA-Z0-9._-]+(?:\/[a-zA-Z0-9._-]+)?(?:\:[a-zA-Z0-9._-]+|@sha256\:[a-fA-F0-9]{64})?$',
        'error': ErrorMessages.ConfigError.INVALID_IMAGE_URL,
        'name': 'Image',
        'description': 'Container image URL (registry.com/namespace/image:tag or @sha256:hash)'
    }
    
    NAMESPACE = {
        'pattern': r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$',
        'error': ErrorMessages.ConfigError.INVALID_NAMESPACE,
        'name': 'Namespace',
        'max_length': 63,
        'description': 'Kubernetes namespace (lowercase alphanumeric with hyphens)'
    }
    
    OPENSHIFT_URL = {
        'pattern': r'^https?:\/\/[a-zA-Z0-9.-]+(?:\:[0-9]+)?(?:\/.*)?$',
        'error': ErrorMessages.ConfigError.INVALID_OPENSHIFT_URL,
        'name': 'URL',
        'description': 'OpenShift API URL (https://api.cluster.com:6443)'
    }


def _validate_with_config(value: str, config: dict) -> bool:
    """
    Generic validation using configuration-driven approach.
    
    Uses a single validation function
    with configuration objects instead of multiple similar functions.
    
    Args:
        value: The string to validate
        config: Validation configuration dictionary
        
    Returns:
        bool: True if validation passes
        
    Raises:
        ConfigurationError: If validation fails
    """
    # Use the existing helper for pattern validation
    _validate_input(value, config['pattern'], str(config['error']), config['name'])
    
    # Handle additional constraints (e.g., max_length)
    if 'max_length' in config and len(value) > config['max_length']:
        raise ConfigurationError(
            f"{config['name']} too long (max {config['max_length']} chars): {value}"
        )
    
    return True


def _validate_input(value: str, pattern: str, error_template: str, name: str) -> bool:
    """
    Private helper function to validate input against a regex pattern.
    
    Args:
        value: The string to validate
        pattern: The regex pattern to match against
        error_template: Error message template from ErrorMessages enum
        name: The name of the field being validated (for error messages)
        
    Returns:
        bool: True if validation passes
        
    Raises:
        ConfigurationError: If validation fails
    """
    if not value or not isinstance(value, str):
        raise ConfigurationError(f"{name} cannot be empty")
    
    if not re.match(pattern, value):
        raise ConfigurationError(error_template.format(**{name.lower(): value}))
    
    return True


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
    return _validate_with_config(image, ValidationConfig.IMAGE_URL)


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
    return _validate_with_config(namespace, ValidationConfig.NAMESPACE)


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
    return _validate_with_config(url, ValidationConfig.OPENSHIFT_URL)


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


def handle_api_error(
    error: Exception, 
    context: str = "", 
    exception_class: Optional[Type[RBACManagerError]] = None
) -> None:
    """
    Unified error handling function that inspects exceptions and raises appropriate custom exceptions
    
    This function consolidates SSL, network, and API error handling into a single, comprehensive
    error handler that can determine the appropriate exception type and user-friendly message
    based on the error characteristics.
    
    Args:
        error: The caught exception to analyze and handle
        context: Optional context information for better error messages
        exception_class: The specific exception class to raise (defaults based on error type)
        
    Raises:
        RBACManagerError: Appropriate error type with user-friendly message from ErrorMessages constants
    """
    error_str = str(error).lower()
    
    # Determine default exception class based on error type if not provided
    if exception_class is None:
        if any(auth_indicator in error_str for auth_indicator in ["unauthorized", "401", "forbidden", "403"]):
            exception_class = AuthenticationError
        elif any(net_indicator in error_str for net_indicator in ["connection", "timeout", "refused", "ssl", "certificate"]):
            exception_class = NetworkError
        else:
            exception_class = CatalogdError
    
    # Handle SSL/TLS related errors
    if any(ssl_indicator in error_str for ssl_indicator in ["ssl", "certificate", "tls"]):
        if "certificate verify failed" in error_str or "certificate_verify_failed" in error_str:
            raise exception_class(str(ErrorMessages.SSLError.CERT_VERIFICATION_FAILED))
        else:
            raise exception_class(str(ErrorMessages.SSLError.CONNECTION_ERROR).format(error=error))
    
    # Handle authentication/authorization errors
    if "unauthorized" in error_str or "401" in error_str:
        raise exception_class(str(ErrorMessages.AuthError.TOKEN_EXPIRED))
    
    if "forbidden" in error_str or "403" in error_str:
        raise exception_class(str(ErrorMessages.AuthError.INSUFFICIENT_PERMISSIONS))
    
    # Handle network connection errors
    if "timeout" in error_str:
        context_msg = f"{context}\n" if context else ""
        raise exception_class(f"{context_msg}{str(ErrorMessages.NetworkError.CONNECTION_TIMEOUT)}")
    
    if "connection refused" in error_str:
        context_msg = f"{context}\n" if context else ""
        raise exception_class(f"{context_msg}{str(ErrorMessages.NetworkError.CONNECTION_REFUSED)}")
    
    # Handle general connection errors
    if "connection" in error_str:
        context_msg = f"{context}: " if context else ""
        raise exception_class(f"{context_msg}Connection error: {error}")
    
    # For other errors, re-raise with context and original message
    context_msg = f"{context}: " if context else ""
    raise exception_class(f"{context_msg}{error}")




def create_user_friendly_error(error_type: str, details: str, suggestions: Optional[list] = None) -> str:
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
