"""
Logging Utilities Module.

This module provides logging configuration and setup utilities for the RBAC Manager.
"""

import logging


def setup_logging(verbose: bool = False) -> None:
    """
    Configure logging for the application.
    
    Args:
        verbose: Enable debug-level logging if True
    """
    level = logging.DEBUG if verbose else logging.INFO
    
    # Configure root logger
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Reduce noise from urllib3 when using insecure connections
    logging.getLogger('urllib3').setLevel(logging.WARNING)
