"""
Core Utilities Module.

This module provides essential utilities used throughout the RBAC Manager application,
including logging setup, port-forwarding, and other common functionality.
Consolidates small utility modules to reduce file fragmentation.
"""

import logging
import os
import signal
import subprocess
import sys
import time
from typing import Optional


# ============================================================================
# LOGGING UTILITIES
# ============================================================================

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


# ============================================================================
# PORT FORWARD UTILITIES
# ============================================================================

class PortForwardManager:
    """
    Context manager for handling OpenShift service port-forwarding.
    
    This class manages the lifecycle of oc port-forward processes,
    ensuring proper cleanup and resource management.
    """
    
    def __init__(self, namespace: str, service: str, local_port: int = 8080, remote_port: int = 443):
        """
        Initialize port-forward manager.
        
        Args:
            namespace: Kubernetes namespace containing the service
            service: Service name to port-forward to
            local_port: Local port to bind to
            remote_port: Remote port on the service
        """
        self.namespace = namespace
        self.service = service
        self.local_port = local_port
        self.remote_port = remote_port
        self.process: Optional[subprocess.Popen] = None
        
        # Use HTTPS for catalogd service since it expects HTTPS connections
        if remote_port == 443 or service == 'catalogd-service':
            self.api_url = f"https://localhost:{local_port}"
        else:
            self.api_url = f"http://localhost:{local_port}"
        
        self.logger = logging.getLogger(__name__)
    
    def __enter__(self) -> str:
        """
        Start port-forward and return the local API URL.
        
        Returns:
            Local API URL for accessing the service
            
        Raises:
            Exception: If port-forward fails to start
        """
        return self.start_port_forward()
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Stop the port-forward process."""
        self.stop_port_forward()
    
    def start_port_forward(self) -> str:
        """
        Start the port-forward process.
        
        Returns:
            Local API URL for accessing the service
            
        Raises:
            Exception: If port-forward fails to start
        """
        if not self._check_oc_available():
            raise Exception(
                "'oc' command not found. Please install OpenShift CLI from: "
                "https://docs.openshift.com/container-platform/latest/cli_reference/openshift_cli/getting-started-cli.html"
            )
        
        cmd = [
            "oc", "port-forward", 
            f"-n", self.namespace,
            f"service/{self.service}",
            f"{self.local_port}:{self.remote_port}"
        ]
        
        self.logger.info(f"Starting port-forward: {' '.join(cmd)}")
        
        try:
            # Start port-forward process
            self.process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid  # Create new process group
            )
            
            # Wait for port-forward to be ready
            if self._wait_for_port_forward():
                self.logger.info(f"Port-forward ready: {self.api_url}")
                return self.api_url
            else:
                # Port-forward failed, get error details
                if self.process and self.process.poll() is not None:
                    _, stderr = self.process.communicate()
                    error_msg = stderr.decode().strip()
                else:
                    error_msg = "Port-forward timeout"
                
                self.stop_port_forward()
                raise Exception(f"Port-forward failed: {error_msg}")
                
        except Exception as e:
            self.stop_port_forward()
            raise Exception(f"Failed to start port-forward: {e}")
    
    def stop_port_forward(self) -> None:
        """Stop the port-forward process."""
        if self.process:
            try:
                # Send SIGTERM to the process group
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                
                # Wait for process to terminate gracefully
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate gracefully
                    os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                    self.process.wait()
                
                self.logger.info("Port-forward process terminated")
                
            except (OSError, ProcessLookupError):
                # Process already terminated
                pass
            finally:
                self.process = None
    
    def _check_oc_available(self) -> bool:
        """Check if oc command is available."""
        try:
            subprocess.run(['oc', 'version', '--client'], 
                          capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def _wait_for_port_forward(self, timeout: int = 10) -> bool:
        """
        Wait for port-forward to be ready.
        
        Args:
            timeout: Maximum time to wait in seconds
            
        Returns:
            True if port-forward is ready, False otherwise
        """
        import socket
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.process and self.process.poll() is not None:
                # Process has terminated
                return False
            
            # Check if port is listening
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    result = sock.connect_ex(('localhost', self.local_port))
                    if result == 0:
                        # Port is open
                        time.sleep(1)  # Give it a moment to fully initialize
                        return True
            except Exception:
                pass
            
            time.sleep(0.5)
        
        return False


# ============================================================================
# COMMON UTILITIES
# ============================================================================

def check_terminal_output() -> bool:
    """
    Check if output is being piped (not connected to terminal).
    
    Returns:
        True if output is connected to terminal, False if piped
    """
    return sys.stdout.isatty()


def display_pipe_error_message(command_context: str) -> None:
    """
    Display error message when piping output without required parameters.
    
    Args:
        command_context: Context string for providing appropriate examples
    """
    print("ERROR: When piping output, you must specify --catalog-name parameter.")
    
    # Provide context-specific example
    if "list-packages" in command_context:
        print("Example: python3 rbac_manager.py --catalogd --catalog-name openshift-community-operators --list-packages --insecure | grep cert-manager")
    elif "all-namespaces" in command_context:
        print("Example: python3 rbac_manager.py --catalogd --catalog-name openshift-community-operators --all-namespaces-packages --insecure | grep cert-manager")
    else:  # package extraction
        print("Example: python3 rbac_manager.py --catalogd --catalog-name openshift-community-operators --package cert-manager --insecure")
    
    print("\nAvailable catalogs can be listed with: python3 rbac_manager.py --catalogd --list-catalogs --insecure")
