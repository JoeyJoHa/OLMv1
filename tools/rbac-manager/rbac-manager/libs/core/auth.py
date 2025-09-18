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
    
    def _initialize_api_clients(self, configuration: Optional[client.Configuration] = None) -> bool:
        """
        Initialize Kubernetes API clients and apply TLS settings
        
        Args:
            configuration: Optional Kubernetes configuration object
            
        Returns:
            bool: True if initialization successful
            
        Raises:
            AuthenticationError: If client initialization fails
        """
        try:
            # Apply TLS settings before initializing clients
            if configuration:
                # Apply TLS settings to provided configuration
                if self.skip_tls:
                    configuration.verify_ssl = False
                    configuration.ssl_ca_cert = None
                    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                
                client.Configuration.set_default(configuration)
                api_client = client.ApiClient(configuration)
            else:
                api_client = client.ApiClient()
                configuration = api_client.configuration
                
                # Apply TLS settings to discovered configuration
                if self.skip_tls:
                    configuration.verify_ssl = False
                    configuration.ssl_ca_cert = None
                    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            # Initialize API clients
            self.k8s_client = api_client
            self.custom_api = client.CustomObjectsApi(self.k8s_client)
            self.core_api = client.CoreV1Api(self.k8s_client)
            
            # Extract cluster info from active configuration
            if hasattr(configuration, 'host') and configuration.host:
                self.openshift_url = configuration.host
            
            # Extract token from configuration if available
            if hasattr(configuration, 'api_key') and configuration.api_key:
                auth_header = configuration.api_key.get('authorization', '')
                if auth_header.startswith('Bearer '):
                    self.openshift_token = auth_header[7:]  # Remove 'Bearer ' prefix
                elif auth_header:
                    self.openshift_token = auth_header
            
            # Mask sensitive information in URL for logging
            if self.openshift_url:
                from .utils import mask_sensitive_info
                masked_url = mask_sensitive_info(self.openshift_url, self.openshift_url)
                logger.info(f"Successfully configured Kubernetes client for {masked_url}")
            
            return True
            
        except Exception as e:
            # Use centralized SSL error handler
            handle_ssl_error(e, AuthenticationError)
    
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
            
            # Use shared helper to initialize API clients and apply TLS settings
            return self._initialize_api_clients(configuration)
            
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
                
            except Exception as kubeconfig_error:
                logger.warning(f"Failed to load kubeconfig: {kubeconfig_error}")
                
                # Try in-cluster config
                try:
                    config.load_incluster_config()
                    logger.info("Successfully loaded in-cluster config")
                    
                except Exception as incluster_error:
                    logger.warning(f"Failed to load in-cluster config: {incluster_error}")
                    return False
            
            # Use shared helper to initialize API clients and extract configuration
            # The kubernetes client library automatically handles URL and token extraction
            success = self._initialize_api_clients()
            
            if success:
                logger.info("Successfully discovered authentication from context")
            
            return success
            
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
