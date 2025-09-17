"""
Protocols and Interfaces

Defines protocols (interfaces) for dependency injection and type hints.
"""

from typing import Protocol, Dict, Any, Optional, Tuple
from kubernetes import client
from .constants import KubernetesConstants


class AuthProvider(Protocol):
    """Protocol for authentication providers"""
    
    def configure_auth(self, openshift_url: str = None, openshift_token: str = None) -> bool:
        """Configure authentication with provided URL and token, or discover from context"""
        ...
    
    def get_kubernetes_clients(self) -> Tuple[Optional[client.ApiClient], Optional[client.CustomObjectsApi], Optional[client.CoreV1Api]]:
        """Get initialized Kubernetes API clients"""
        ...
    
    def get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for HTTP requests"""
        ...
    
    def get_cluster_info(self) -> Tuple[Optional[str], Optional[str]]:
        """Get cluster URL and token"""
        ...
    
    def is_authenticated(self) -> bool:
        """Check if authentication is properly configured"""
        ...
    
    def test_connection(self) -> bool:
        """Test the connection to the OpenShift cluster"""
        ...


class ConfigProvider(Protocol):
    """Protocol for configuration providers"""
    
    def load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        ...
    
    def generate_config_template(self, output_dir: str = None) -> str:
        """Generate configuration template file"""
        ...
    
    def get_config(self) -> Dict[str, Any]:
        """Get current configuration data"""
        ...
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """Get specific configuration section"""
        ...
    
    def get_value(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key"""
        ...


class BundleProvider(Protocol):
    """Protocol for bundle processors"""
    
    def extract_bundle_metadata(self, image: str, registry_token: str = None) -> Dict[str, Any]:
        """Extract bundle metadata from container image"""
        ...
    
    def generate_yaml_manifests(self, bundle_metadata: Dict[str, Any], namespace: str = KubernetesConstants.DEFAULT_NAMESPACE, 
                              operator_name: Optional[str] = None) -> Dict[str, str]:
        """Generate Kubernetes YAML manifests"""
        ...
    
    def generate_helm_values(self, bundle_metadata: Dict[str, Any], 
                           operator_name: Optional[str] = None) -> str:
        """Generate Helm values.yaml content"""
        ...


class CatalogdProvider(Protocol):
    """Protocol for catalogd service providers"""
    
    def display_catalogs_enhanced(self) -> int:
        """Display enhanced catalog information"""
        ...
    
    def get_catalog_packages(self, catalog_name: str, auth_headers: Dict[str, str]) -> list:
        """Get packages from a specific catalog"""
        ...
    
    def get_package_channels(self, catalog_name: str, package: str, auth_headers: Dict[str, str]) -> list:
        """Get channels for a specific package"""
        ...
    
    def get_channel_versions(self, catalog_name: str, package: str, channel: str, auth_headers: Dict[str, str]) -> list:
        """Get versions for a specific channel"""
        ...
    
    def get_version_metadata(self, catalog_name: str, package: str, channel: str, version: str, auth_headers: Dict[str, str]) -> Dict[str, Any]:
        """Get metadata for a specific version"""
        ...


class HelpProvider(Protocol):
    """Protocol for help providers"""
    
    def show_help(self, topic: str = None) -> None:
        """Show help for a specific topic"""
        ...
    
    def show_examples(self) -> None:
        """Show usage examples"""
        ...
