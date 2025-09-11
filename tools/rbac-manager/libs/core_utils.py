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
import yaml
from typing import Optional


# ============================================================================
# LOGGING UTILITIES moved to config_manager.py
# ============================================================================


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
# OPENSHIFT API UTILITIES
# ============================================================================

def list_openshift_clustercatalogs() -> int:
    """
    List available ClusterCatalogs from OpenShift cluster using Kubernetes API.
    
    This function queries the Kubernetes API directly for ClusterCatalog custom resources,
    not the catalogd service, so no port-forward is needed.
    
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    try:
        from kubernetes import client
        api_client = client.CustomObjectsApi()
        cluster_catalogs = api_client.list_cluster_custom_object(
            group="olm.operatorframework.io",
            version="v1",
            plural="clustercatalogs"
        )
        
        catalogs_info = []
        for catalog in cluster_catalogs.get('items', []):
            metadata = catalog.get('metadata', {})
            status = catalog.get('status', {})
            
            # Parse serving status from conditions array
            serving_status = False
            conditions = status.get('conditions', [])
            for condition in conditions:
                if condition.get('type') == 'Serving' and condition.get('status') == 'True':
                    serving_status = True
                    break
            
            catalog_info = {
                'name': metadata.get('name', 'unknown'),
                'lastUnpacked': status.get('lastUnpacked', 'never'),
                'serving': serving_status,
                'age': metadata.get('creationTimestamp', 'unknown')
            }
            catalogs_info.append(catalog_info)
        
        # Display results
        if not catalogs_info:
            print("No ClusterCatalogs found in this cluster.")
            return 1
        
        print(f"\nAvailable ClusterCatalogs:")
        print("-" * 80)
        print(f"{'Name':<40} {'Serving':<8} {'Last Unpacked':<25} {'Age':<20}")
        print("-" * 80)
        
        for catalog in catalogs_info:
            serving_status = "True" if catalog['serving'] else "False"
            print(f"{catalog['name']:<40} {serving_status:<8} {catalog['lastUnpacked']:<25} {catalog['age']:<20}")
        
        print("-" * 80)
        print(f"\nTotal: {len(catalogs_info)} ClusterCatalogs")
        print("Note: Only serving catalogs can be reliably queried for packages.")
        
        logging.info(f"Found {len(catalogs_info)} ClusterCatalogs")
        return 0
        
    except Exception as e:
        logging.error(f"Failed to query ClusterCatalogs: {e}")
        print(f"Error listing ClusterCatalogs: {e}")
        return 1


# ============================================================================
# TERMINAL UTILITIES moved to cli_interface.py
# ============================================================================


# ============================================================================
# OPENSHIFT AUTHENTICATION (formerly openshift_auth.py)
# ============================================================================

class OpenShiftAuth:
    """Handle OpenShift authentication."""
    
    def __init__(self, api_url: Optional[str] = None, token: Optional[str] = None, 
                 insecure: bool = False, verify_catalogd_permissions: bool = True):
        """
        Initialize OpenShift authentication.
        
        Args:
            api_url: OpenShift API URL (optional, will auto-discover from kubeconfig)
            token: Authentication token (optional, will try env var)
            insecure: Skip TLS verification
            verify_catalogd_permissions: Verify catalogd namespace permissions
        """
        self.api_url = api_url or self._discover_cluster_url()
        self.token = token or self._get_token_from_env()
        self.insecure = insecure
        self.verify_catalogd_permissions = verify_catalogd_permissions
        self.authenticated = False
        
    def _get_token_from_env(self) -> Optional[str]:
        """Get token from the OPENSHIFT_TOKEN environment variable."""
        return os.getenv('OPENSHIFT_TOKEN')
    
    def _discover_url_from_oc(self) -> Optional[str]:
        """
        Discover cluster URL using 'oc whoami --show-server' command.
        
        This is the most reliable method for OpenShift clusters as it uses
        the native OpenShift CLI tool.
        
        Returns:
            Cluster URL if successful, None otherwise
        """
        try:
            result = subprocess.run(
                ['oc', 'whoami', '--show-server'],
                capture_output=True, text=True, check=True
            )
            server_url = result.stdout.strip()
            if server_url:
                return server_url
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        return None
    
    def _discover_url_from_kubectl(self) -> Optional[str]:
        """
        Discover cluster URL using 'kubectl config view' command.
        
        This method works with both OpenShift and vanilla Kubernetes clusters
        that have kubectl configured.
        
        Returns:
            Cluster URL if successful, None otherwise
        """
        try:
            result = subprocess.run(
                ['kubectl', 'config', 'view', '--minify', '-o', 'jsonpath={.clusters[0].cluster.server}'],
                capture_output=True, text=True, check=True
            )
            server_url = result.stdout.strip()
            if server_url:
                return server_url
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        return None
    
    def _discover_url_from_kubeconfig_parser(self) -> Optional[str]:
        """
        Discover cluster URL by directly parsing the kubeconfig YAML file.
        
        This method provides a fallback when CLI tools are not available
        by parsing the kubeconfig file directly using Python.
        
        Returns:
            Cluster URL if successful, None otherwise
        """
        try:
            import yaml
            
            # Get kubeconfig file path
            kubeconfig_path = os.path.expanduser("~/.kube/config")
            if not os.path.exists(kubeconfig_path):
                return None
            
            # Load and parse kubeconfig
            with open(kubeconfig_path, 'r') as f:
                kubeconfig = yaml.safe_load(f)
            
            # Get current context
            current_context_name = kubeconfig.get('current-context')
            if not current_context_name:
                return None
            
            # Find current context details
            current_context = None
            for context in kubeconfig.get('contexts', []):
                if context.get('name') == current_context_name:
                    current_context = context
                    break
            
            if not current_context:
                return None
            
            # Get cluster name from context
            cluster_name = current_context.get('context', {}).get('cluster')
            if not cluster_name:
                return None
            
            # Find cluster server URL
            for cluster in kubeconfig.get('clusters', []):
                if cluster.get('name') == cluster_name:
                    server_url = cluster.get('cluster', {}).get('server')
                    if server_url:
                        return server_url
            
            return None
            
        except (ImportError, Exception):
            return None
    
    def _discover_cluster_url(self) -> str:
        """
        Automatically discover cluster URL by trying a series of strategies.
        
        This method uses the Strategy Pattern to iterate through different
        discovery approaches until one succeeds. This makes the code more
        modular, readable, and extensible.
        
        Returns:
            Cluster API URL from the first successful strategy
            
        Raises:
            Exception: If cluster URL cannot be discovered by any strategy
        """
        # Define discovery strategies in order of preference
        strategies = [
            self._discover_url_from_oc,           # Most reliable for OpenShift
            self._discover_url_from_kubectl,      # Works with kubectl
            self._discover_url_from_kubeconfig_parser  # Fallback parser
        ]
        
        for strategy in strategies:
            try:
                url = strategy()
                if url:
                    logging.info(f"Auto-discovered cluster URL via {strategy.__name__}: {url}")
                    return url
            except Exception as e:
                logging.debug(f"Strategy {strategy.__name__} failed: {e}")
        
        # If all strategies fail, provide helpful error message
        raise Exception(
            "Could not auto-discover cluster URL from any available method. "
            "Please ensure you are logged in to your cluster (oc login or kubectl) "
            "or provide --openshift-url explicitly"
        )
    
    def _verify_catalogd_access(self) -> bool:
        """
        Verify user has necessary permissions for catalogd access.
        
        Returns:
            True if user can access catalogd service, False otherwise
        """
        try:
            from kubernetes import client
            
            v1 = client.CoreV1Api()
            
            # Check if user can get services in openshift-catalogd namespace
            try:
                services = v1.list_namespaced_service(namespace="openshift-catalogd")
                logging.info("User has access to openshift-catalogd namespace")
                
                # Check if catalogd-service exists
                catalogd_service = None
                for service in services.items:
                    if service.metadata.name == "catalogd-service":
                        catalogd_service = service
                        break
                
                if catalogd_service:
                    logging.info("catalogd-service found and accessible")
                    return True
                else:
                    logging.warning("catalogd-service not found in openshift-catalogd namespace")
                    return False
                    
            except Exception as e:
                logging.error(f"Cannot access openshift-catalogd namespace: {e}")
                return False
                
        except Exception as e:
            logging.error(f"Permission verification failed: {e}")
            return False
    
    def login(self) -> bool:
        """
        Authenticate with OpenShift cluster and verify permissions.
        
        Returns:
            True if authentication and permission verification successful
            
        Raises:
            Exception: If authentication fails or required permissions missing
        """
        try:
            from kubernetes import client, config
            
            # First, try to use existing kubeconfig (from oc login)
            if not self.token:
                logging.info("No explicit token provided, using existing kubeconfig authentication...")
                try:
                    # If insecure mode, disable SSL warnings first
                    if self.insecure:
                        import urllib3
                        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                    
                    # Load kubeconfig and use existing authentication
                    config.load_kube_config()
                    
                    # Override the host and SSL settings to use our discovered/provided URL and insecure setting
                    configuration = client.Configuration.get_default_copy()
                    configuration.host = self.api_url
                    configuration.verify_ssl = not self.insecure
                    
                    # Test the connection with kubeconfig auth
                    api = client.CoreV1Api(client.ApiClient(configuration))
                    api.get_api_resources()
                    
                    logging.info(f"Successfully authenticated using kubeconfig at {self.api_url}")
                    
                    # Set the configuration as default for other operations
                    client.Configuration.set_default(configuration)
                    
                except Exception as kubeconfig_error:
                    logging.warning(f"Kubeconfig authentication failed: {kubeconfig_error}")
                    # Check if this is an SSL certificate error
                    error_msg = str(kubeconfig_error).lower()
                    if "ssl" in error_msg or "certificate" in error_msg or "tls" in error_msg:
                        raise Exception("SSL certificate verification failed. Your cluster appears to use self-signed certificates. Please use the --insecure flag to skip SSL verification, or provide --openshift-token with a valid authentication token.")
                    else:
                        raise Exception("Authentication token required. Please provide --openshift-token, set OPENSHIFT_TOKEN environment variable, or ensure you're logged in with 'oc login'")
            
            else:
                # Use explicit token authentication
                logging.info("Using provided authentication token...")
                
                # Configure the OpenShift client
                configuration = client.Configuration()
                configuration.host = self.api_url
                configuration.api_key = {"authorization": f"Bearer {self.token}"}
                configuration.verify_ssl = not self.insecure
                
                # Set the configuration
                client.Configuration.set_default(configuration)
                oc_client = client.ApiClient(configuration)
                
                # Test the connection
                api = client.CoreV1Api()
                api.get_api_resources()
                
                logging.info(f"Successfully authenticated with token at {self.api_url}")
            
            # Verify catalogd permissions if requested
            if self.verify_catalogd_permissions:
                if not self._verify_catalogd_access():
                    raise Exception("Insufficient permissions to access catalogd service. User needs access to 'services' in 'openshift-catalogd' namespace")
            
            self.authenticated = True
            return True
            
        except ImportError:
            raise Exception("Kubernetes Python client not installed. Run: pip install -r requirements.txt")
        except Exception as e:
            if "Authentication token required" in str(e) or "SSL certificate verification failed" in str(e):
                raise e
            raise Exception(f"OpenShift authentication failed: {e}")


# ============================================================================
# YAML FORMATTING UTILITIES
# ============================================================================

def create_flow_style_yaml_dumper():
    """
    Creates a PyYAML Dumper that formats lists within RBAC rules inline.
    
    This creates a custom YAML dumper that formats RBAC rule lists in flow style
    (inline format) while keeping other lists in block style. This makes RBAC
    rules more compact and readable.
    
    Example output:
        apiGroups: [rbac.authorization.k8s.io]
        resources: [clusterroles, clusterrolebindings]
        verbs: [get, list, watch, create, update, patch, delete]
    
    Returns:
        FlowStyleDumper class that can be used with yaml.dump()
    """
    class FlowStyleDumper(yaml.SafeDumper):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._in_rbac_rule = False
            self._current_key = None

        def represent_mapping(self, tag, mapping, flow_style=None):
            # Check if this is an individual RBAC rule (not the rules array)
            if isinstance(mapping, dict):
                is_rbac_rule = ('apiGroups' in mapping and 'resources' in mapping and 'verbs' in mapping) or \
                              ('nonResourceURLs' in mapping and 'verbs' in mapping)
                if is_rbac_rule:
                    self._in_rbac_rule = True
                    result = super().represent_mapping(tag, mapping, flow_style=False)
                    self._in_rbac_rule = False
                    return result
            
            return super().represent_mapping(tag, mapping, flow_style=flow_style)

        def represent_sequence(self, tag, sequence, flow_style=None):
            # Use flow style only for lists within RBAC rules (apiGroups, resources, verbs)
            # but not for the main 'rules' array
            if self._in_rbac_rule:
                return super().represent_sequence(tag, sequence, flow_style=True)
            else:
                return super().represent_sequence(tag, sequence, flow_style=False)

    return FlowStyleDumper
