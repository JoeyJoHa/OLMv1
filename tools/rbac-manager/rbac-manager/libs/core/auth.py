"""
Authentication Module

Handles OpenShift authentication and context discovery.
"""

import logging
import os
import urllib3
import yaml
from typing import Optional, Tuple, Dict
from kubernetes import client, config
from kubernetes.client.rest import ApiException

from .exceptions import AuthenticationError, ConfigurationError
from .utils import validate_openshift_url, handle_ssl_error

logger = logging.getLogger(__name__)


class OpenShiftAuth:
    """Handles OpenShift authentication and context discovery"""
    
    def __init__(self, skip_tls: bool = False):
        """
        Initialize OpenShift authentication handler
        
        Args:
            skip_tls: Whether to skip TLS verification for requests
        """
        self.skip_tls = skip_tls
        self.openshift_url = None
        self.openshift_token = None
        self.k8s_client = None
        self.custom_api = None
        self.core_api = None
        
    def configure_auth(self, openshift_url: str = None, openshift_token: str = None) -> bool:
        """
        Configure authentication with provided URL and token, or discover from context
        
        Args:
            openshift_url: OpenShift cluster URL (optional)
            openshift_token: OpenShift authentication token (optional)
            
        Returns:
            bool: True if authentication was configured successfully
            
        Raises:
            AuthenticationError: If authentication configuration fails
            ConfigurationError: If provided parameters are invalid
        """
        try:
            # If both URL and token are provided, use them directly
            if openshift_url and openshift_token:
                validate_openshift_url(openshift_url)
                logger.info("Using provided OpenShift URL and token for authentication")
                self.openshift_url = openshift_url
                self.openshift_token = openshift_token
                return self._configure_kubernetes_client_with_token()
            
            # Try to discover from kubeconfig or in-cluster config
            return self._discover_from_context()
            
        except ConfigurationError:
            # Re-raise ConfigurationError as-is (from validate_openshift_url)
            raise
        except Exception as e:
            raise AuthenticationError(f"Failed to configure authentication: {e}")
    
    def _configure_kubernetes_client_with_token(self) -> bool:
        """
        Configure Kubernetes client using URL and token
        
        Returns:
            bool: True if configuration successful
            
        Raises:
            AuthenticationError: If client configuration fails
        """
        try:
            # Create configuration with token
            configuration = client.Configuration()
            configuration.host = self.openshift_url
            configuration.api_key = {"authorization": self.openshift_token}
            configuration.api_key_prefix = {"authorization": "Bearer"}
            
            if self.skip_tls:
                configuration.verify_ssl = False
                configuration.ssl_ca_cert = None
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            # Set the configuration as default
            client.Configuration.set_default(configuration)
            
            # Initialize API clients
            self.k8s_client = client.ApiClient(configuration)
            self.custom_api = client.CustomObjectsApi(self.k8s_client)
            self.core_api = client.CoreV1Api(self.k8s_client)
            
            # Mask sensitive information in URL for logging
            from .utils import mask_sensitive_info
            masked_url = mask_sensitive_info(self.openshift_url, self.openshift_url)
            
            logger.info(f"Successfully configured Kubernetes client for {masked_url}")
            return True
            
        except Exception as e:
            # Use centralized SSL error handler
            handle_ssl_error(e, AuthenticationError)
    
    def _discover_from_context(self) -> bool:
        """
        Discover authentication from kubeconfig or in-cluster config
        
        Returns:
            bool: True if discovery successful
            
        Raises:
            AuthenticationError: If context discovery fails
        """
        try:
            # Try to load from kubeconfig first
            try:
                config.load_kube_config()
                logger.info("Successfully loaded kubeconfig")
                
                # Extract current context info
                contexts, active_context = config.list_kube_config_contexts()
                if active_context:
                    cluster_info = active_context.get('context', {}).get('cluster')
                    if cluster_info:
                        # Load the full config to get cluster URL
                        kube_config = config.kube_config.KUBE_CONFIG_DEFAULT_LOCATION
                        if os.path.exists(os.path.expanduser(kube_config)):
                            with open(os.path.expanduser(kube_config), 'r') as f:
                                config_data = yaml.safe_load(f)
                                
                            # Find cluster URL
                            for cluster in config_data.get('clusters', []):
                                if cluster.get('name') == cluster_info:
                                    self.openshift_url = cluster.get('cluster', {}).get('server')
                                    break
                        
                        # Extract token if available
                        user_info = active_context.get('context', {}).get('user')
                        if user_info:
                            for user in config_data.get('users', []):
                                if user.get('name') == user_info:
                                    user_data = user.get('user', {})
                                    self.openshift_token = user_data.get('token')
                                    break
                
            except Exception as kubeconfig_error:
                logger.warning(f"Failed to load kubeconfig: {kubeconfig_error}")
                
                # Try in-cluster config
                try:
                    config.load_incluster_config()
                    logger.info("Successfully loaded in-cluster config")
                    
                    # For in-cluster, we can get the API server URL from environment
                    self.openshift_url = f"https://{os.getenv('KUBERNETES_SERVICE_HOST')}:{os.getenv('KUBERNETES_SERVICE_PORT', '443')}"
                    
                    # Token is automatically handled by in-cluster config
                    token_path = '/var/run/secrets/kubernetes.io/serviceaccount/token'
                    if os.path.exists(token_path):
                        with open(token_path, 'r') as f:
                            self.openshift_token = f.read().strip()
                            
                except Exception as incluster_error:
                    logger.warning(f"Failed to load in-cluster config: {incluster_error}")
                    return False
            
            # Initialize API clients
            self.k8s_client = client.ApiClient()
            self.custom_api = client.CustomObjectsApi(self.k8s_client)
            self.core_api = client.CoreV1Api(self.k8s_client)
            
            if self.skip_tls:
                # Configure SSL settings for discovered config
                configuration = self.k8s_client.configuration
                configuration.verify_ssl = False
                configuration.ssl_ca_cert = None
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            logger.info("Successfully discovered authentication from context")
            return True
            
        except Exception as e:
            # Use centralized SSL error handler
            handle_ssl_error(e, AuthenticationError)
    
    def get_auth_headers(self) -> Dict[str, str]:
        """
        Get authentication headers for HTTP requests
        
        Returns:
            Dict containing authorization headers
        """
        headers = {}
        if self.openshift_token:
            headers['Authorization'] = f'Bearer {self.openshift_token}'
        return headers
    
    def get_cluster_info(self) -> Tuple[Optional[str], Optional[str]]:
        """
        Get cluster URL and token
        
        Returns:
            Tuple of (openshift_url, openshift_token)
        """
        return self.openshift_url, self.openshift_token
    
    def is_authenticated(self) -> bool:
        """
        Check if authentication is properly configured
        
        Returns:
            bool: True if authenticated
        """
        return self.k8s_client is not None
    
    def test_connection(self) -> bool:
        """
        Test the connection to the OpenShift cluster
        
        Returns:
            bool: True if connection is successful
            
        Raises:
            AuthenticationError: If connection test fails
        """
        if not self.is_authenticated():
            raise AuthenticationError("Not authenticated - no Kubernetes client available")
            
        try:
            # Try to get cluster version or any basic API call
            version = self.core_api.get_api_resources()
            logger.info("Successfully tested connection to OpenShift cluster")
            return True
        except ApiException as e:
            raise AuthenticationError(f"Failed to connect to OpenShift cluster: {e}")
        except Exception as e:
            raise AuthenticationError(f"Unexpected error testing connection: {e}")
    
    def get_kubernetes_clients(self) -> Tuple[Optional[client.ApiClient], Optional[client.CustomObjectsApi], Optional[client.CoreV1Api]]:
        """
        Get initialized Kubernetes API clients
        
        Returns:
            Tuple of (k8s_client, custom_api, core_api)
        """
        return self.k8s_client, self.custom_api, self.core_api
