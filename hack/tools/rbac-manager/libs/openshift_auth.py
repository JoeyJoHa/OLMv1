"""
OpenShift Authentication Module.

This module handles OpenShift cluster authentication and authorization verification.
"""

import logging
import os
import subprocess
from typing import Optional

import yaml
from decouple import config, UndefinedValueError


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
        """Get token from environment variables."""
        try:
            return config('OPENSHIFT_TOKEN')
        except UndefinedValueError:
            return None
    
    def _discover_cluster_url(self) -> str:
        """
        Automatically discover cluster URL from kubeconfig.
        
        Returns:
            Cluster API URL from kubeconfig
            
        Raises:
            Exception: If cluster URL cannot be discovered
        """
        # Try multiple approaches to discover the cluster URL
        
        # 1. Try oc command first (most reliable for OpenShift)
        try:
            result = subprocess.run(
                ['oc', 'whoami', '--show-server'],
                capture_output=True, text=True, check=True
            )
            server_url = result.stdout.strip()
            if server_url:
                logging.info(f"🔍 Auto-discovered cluster URL: {server_url}")
                return server_url
        except (subprocess.CalledProcessError, FileNotFoundError):
            logging.debug("oc command not available or failed")
        
        # 2. Try kubectl as fallback
        try:
            result = subprocess.run(
                ['kubectl', 'config', 'view', '--minify', '-o', 'jsonpath={.clusters[0].cluster.server}'],
                capture_output=True, text=True, check=True
            )
            server_url = result.stdout.strip()
            if server_url:
                logging.info(f"🔍 Auto-discovered cluster URL: {server_url}")
                return server_url
        except (subprocess.CalledProcessError, FileNotFoundError):
            logging.debug("kubectl command not available or failed")
        
        # 3. Try using Kubernetes Python client to parse kubeconfig
        try:
            from kubernetes import config as k8s_config
            import yaml
            
            # Get kubeconfig file path
            kubeconfig_path = os.path.expanduser("~/.kube/config")
            if not os.path.exists(kubeconfig_path):
                raise Exception("Kubeconfig file not found")
            
            # Load and parse kubeconfig
            with open(kubeconfig_path, 'r') as f:
                kubeconfig = yaml.safe_load(f)
            
            # Get current context
            current_context_name = kubeconfig.get('current-context')
            if not current_context_name:
                raise Exception("No current context in kubeconfig")
            
            # Find current context details
            current_context = None
            for context in kubeconfig.get('contexts', []):
                if context.get('name') == current_context_name:
                    current_context = context
                    break
            
            if not current_context:
                raise Exception("Current context not found in kubeconfig")
            
            # Get cluster name from context
            cluster_name = current_context.get('context', {}).get('cluster')
            if not cluster_name:
                raise Exception("Cluster name not found in current context")
            
            # Find cluster server URL
            for cluster in kubeconfig.get('clusters', []):
                if cluster.get('name') == cluster_name:
                    server_url = cluster.get('cluster', {}).get('server')
                    if server_url:
                        logging.info(f"🔍 Auto-discovered cluster URL: {server_url}")
                        return server_url
            
            raise Exception("Cluster server URL not found in kubeconfig")
            
        except ImportError:
            logging.debug("Required libraries not available for kubeconfig parsing")
        except Exception as e:
            logging.debug(f"Kubeconfig parsing failed: {e}")
        
        # If all methods fail, raise an error
        raise Exception(
            "Could not auto-discover cluster URL. Please ensure you are logged in to your cluster "
            "(oc login or kubectl) or provide --openshift-url explicitly"
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
                logging.info("✅ User has access to openshift-catalogd namespace")
                
                # Check if catalogd-service exists
                catalogd_service = None
                for service in services.items:
                    if service.metadata.name == "catalogd-service":
                        catalogd_service = service
                        break
                
                if catalogd_service:
                    logging.info("✅ catalogd-service found and accessible")
                    return True
                else:
                    logging.warning("⚠️  catalogd-service not found in openshift-catalogd namespace")
                    return False
                    
            except Exception as e:
                logging.error(f"❌ Cannot access openshift-catalogd namespace: {e}")
                return False
                
        except Exception as e:
            logging.error(f"❌ Permission verification failed: {e}")
            return False
    
    def login(self) -> bool:
        """
        Authenticate with OpenShift cluster and verify permissions.
        
        Returns:
            True if authentication and permission verification successful
            
        Raises:
            Exception: If authentication fails or required permissions missing
        """
        if not self.token:
            raise Exception("Authentication token required. Provide --openshift-token or set OPENSHIFT_TOKEN environment variable")
        
        try:
            import openshift as oc
            from kubernetes import client
            
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
            
            logging.info(f"✅ Successfully authenticated with OpenShift at {self.api_url}")
            
            # Verify catalogd permissions if requested
            if self.verify_catalogd_permissions:
                if not self._verify_catalogd_access():
                    raise Exception("Insufficient permissions to access catalogd service. User needs access to 'services' in 'openshift-catalogd' namespace")
            
            self.authenticated = True
            return True
            
        except ImportError:
            raise Exception("OpenShift Python client not installed. Run: pip install openshift")
        except Exception as e:
            raise Exception(f"OpenShift authentication failed: {e}")
