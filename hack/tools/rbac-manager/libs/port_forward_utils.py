"""
Port-forward utilities for OpenShift/Kubernetes services.

This module provides utilities for managing oc port-forward processes
to access internal cluster services securely.
"""

import logging
import os
import signal
import socket
import subprocess
import time
from typing import Optional

logger = logging.getLogger(__name__)


class PortForwardManager:
    """Manage oc port-forward processes for accessing cluster services."""
    
    def __init__(self, namespace: str = "openshift-catalogd", 
                 service: str = "catalogd-service", 
                 local_port: int = 8080, remote_port: int = 443):
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
        self.api_url = f"http://localhost:{local_port}"
    
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
        for _ in range(timeout):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('localhost', self.local_port))
                sock.close()
                
                if result == 0:
                    return True
            except Exception:
                pass
            
            time.sleep(1)
        
        return False
    
    def start_port_forward(self) -> str:
        """
        Start port-forward in background.
        
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
        
        logger.info(f"Starting port-forward: {' '.join(cmd)}")
        
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
                logger.info(f"✅ Port-forward ready: {self.api_url}")
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
        """Clean up port-forward process and all child processes."""
        if self.process:
            try:
                # Kill the entire process group
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                
                # Wait for process to terminate
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate gracefully
                    os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                    self.process.wait()
                
                logger.info("🧹 Port-forward process terminated")
                
            except (OSError, ProcessLookupError):
                # Process already terminated
                pass
            finally:
                self.process = None
    
    def __enter__(self) -> str:
        """Context manager entry."""
        return self.start_port_forward()
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit with cleanup."""
        self.stop_port_forward()
