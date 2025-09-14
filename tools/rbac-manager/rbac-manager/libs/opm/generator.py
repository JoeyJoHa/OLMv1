"""
YAML and Helm Generators

Generates YAML manifests and Helm values from bundle metadata.
"""

import logging
import time
from pathlib import Path
from typing import Dict, Any, List

from ..core.exceptions import BundleProcessingError
from ..core.utils import sanitize_filename, validate_namespace

logger = logging.getLogger(__name__)


class YAMLGenerator:
    """Generates Kubernetes YAML manifests from bundle metadata"""
    
    def __init__(self):
        """Initialize YAML generator"""
        pass
    
    def generate_manifests(self, metadata: Dict[str, Any], namespace: str = "default", 
                          least_privileges: bool = False) -> Dict[str, str]:
        """
        Generate Kubernetes YAML manifests
        
        Args:
            metadata: Bundle metadata
            namespace: Target namespace
            least_privileges: Apply least privilege principles
            
        Returns:
            Dict mapping manifest names to YAML content
            
        Raises:
            BundleProcessingError: If generation fails
        """
        try:
            validate_namespace(namespace)
            
            manifests = {}
            
            # Generate ServiceAccount
            manifests['01-serviceaccount'] = self._generate_service_account(metadata, namespace)
            
            # Generate ClusterRole
            manifests['02-clusterrole'] = self._generate_cluster_role(metadata, least_privileges)
            
            # Generate ClusterRoleBinding
            manifests['03-clusterrolebinding'] = self._generate_cluster_role_binding(metadata, namespace)
            
            # Generate ClusterExtension
            manifests['04-clusterextension'] = self._generate_cluster_extension(metadata, namespace)
            
            return manifests
            
        except Exception as e:
            raise BundleProcessingError(f"Failed to generate YAML manifests: {e}")
    
    def _generate_service_account(self, metadata: Dict[str, Any], namespace: str) -> str:
        """Generate ServiceAccount YAML"""
        service_account_name = metadata.get('service_account', 'default')
        
        yaml_content = f"""apiVersion: v1
kind: ServiceAccount
metadata:
  name: {service_account_name}
  namespace: {namespace}
  labels:
    app.kubernetes.io/name: {service_account_name}
    app.kubernetes.io/managed-by: rbac-manager
"""
        return yaml_content
    
    def _generate_cluster_role(self, metadata: Dict[str, Any], least_privileges: bool = False) -> str:
        """Generate ClusterRole YAML"""
        service_account_name = metadata.get('service_account', 'default')
        rbac_rules = metadata.get('rbac_rules', {})
        
        # Combine all rules
        all_rules = []
        all_rules.extend(rbac_rules.get('namespace_rules', []))
        all_rules.extend(rbac_rules.get('cluster_rules', []))
        
        if least_privileges:
            all_rules = self._apply_least_privileges(all_rules)
        
        yaml_content = f"""apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: {service_account_name}-clusterrole
  labels:
    app.kubernetes.io/name: {service_account_name}
    app.kubernetes.io/managed-by: rbac-manager
rules:
"""
        
        for rule in all_rules:
            yaml_content += self._format_rbac_rule(rule)
        
        return yaml_content
    
    def _generate_cluster_role_binding(self, metadata: Dict[str, Any], namespace: str) -> str:
        """Generate ClusterRoleBinding YAML"""
        service_account_name = metadata.get('service_account', 'default')
        
        yaml_content = f"""apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: {service_account_name}-clusterrolebinding
  labels:
    app.kubernetes.io/name: {service_account_name}
    app.kubernetes.io/managed-by: rbac-manager
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: {service_account_name}-clusterrole
subjects:
- kind: ServiceAccount
  name: {service_account_name}
  namespace: {namespace}
"""
        return yaml_content
    
    def _generate_cluster_extension(self, metadata: Dict[str, Any], namespace: str) -> str:
        """Generate ClusterExtension YAML"""
        image = metadata.get('image', '')
        service_account_name = metadata.get('service_account', 'default')
        
        # Extract package name from image or use service account name
        package_name = self._extract_package_name(image) or service_account_name
        
        yaml_content = f"""apiVersion: olm.operatorframework.io/v1alpha1
kind: ClusterExtension
metadata:
  name: {package_name}
  labels:
    app.kubernetes.io/name: {package_name}
    app.kubernetes.io/managed-by: rbac-manager
spec:
  packageName: {package_name}
  installNamespace: {namespace}
  serviceAccount:
    name: {service_account_name}
"""
        
        # Add install modes if available
        install_modes = metadata.get('install_modes', {})
        if install_modes:
            yaml_content += "  installModes:\n"
            for mode, supported in install_modes.items():
                yaml_content += f"  - type: {mode}\n"
                yaml_content += f"    supported: {str(supported).lower()}\n"
        
        return yaml_content
    
    def _format_rbac_rule(self, rule: Dict[str, Any]) -> str:
        """Format a single RBAC rule as YAML"""
        yaml_rule = "- "
        
        # API Groups
        api_groups = rule.get('apiGroups', [])
        if api_groups:
            yaml_rule += f"apiGroups: {api_groups}\n  "
        
        # Resources
        resources = rule.get('resources', [])
        if resources:
            yaml_rule += f"resources: {resources}\n  "
        
        # Verbs
        verbs = rule.get('verbs', [])
        if verbs:
            yaml_rule += f"verbs: {verbs}\n"
        
        # Resource Names (optional)
        resource_names = rule.get('resourceNames', [])
        if resource_names:
            yaml_rule += f"  resourceNames: {resource_names}\n"
        
        return yaml_rule
    
    def _apply_least_privileges(self, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply least privilege principles to RBAC rules"""
        # This is a simplified implementation
        # In practice, this would involve more sophisticated analysis
        filtered_rules = []
        
        for rule in rules:
            verbs = rule.get('verbs', [])
            
            # Remove overly broad permissions
            if '*' in verbs:
                # Replace with more specific verbs
                specific_verbs = ['get', 'list', 'watch', 'create', 'update', 'patch']
                rule = rule.copy()
                rule['verbs'] = specific_verbs
            
            filtered_rules.append(rule)
        
        return filtered_rules
    
    def _extract_package_name(self, image: str) -> str:
        """Extract package name from image URL"""
        if not image:
            return ""
        
        # Extract from image name (e.g., quay.io/redhat/quay-operator-bundle:v3.10.0)
        parts = image.split('/')
        if len(parts) >= 2:
            image_name = parts[-1]  # Get the last part
            # Remove tag/digest
            if ':' in image_name:
                image_name = image_name.split(':')[0]
            if '@' in image_name:
                image_name = image_name.split('@')[0]
            
            # Remove common suffixes
            suffixes = ['-bundle', '-operator-bundle']
            for suffix in suffixes:
                if image_name.endswith(suffix):
                    image_name = image_name[:-len(suffix)]
                    break
            
            return image_name
        
        return ""


class HelmGenerator:
    """Generates Helm values files from bundle metadata"""
    
    def __init__(self):
        """Initialize Helm generator"""
        pass
    
    def generate_helm_values(self, metadata: Dict[str, Any], least_privileges: bool = False) -> str:
        """
        Generate Helm values YAML
        
        Args:
            metadata: Bundle metadata
            least_privileges: Apply least privilege principles
            
        Returns:
            Helm values YAML content
            
        Raises:
            BundleProcessingError: If generation fails
        """
        try:
            service_account_name = metadata.get('service_account', 'default')
            image = metadata.get('image', '')
            package_name = self._extract_package_name(image) or service_account_name
            
            values_content = f"""# Helm values for {package_name}
# Generated by rbac-manager

# Global settings
global:
  imageRegistry: ""
  imagePullSecrets: []

# Operator configuration
operator:
  name: {package_name}
  image: {image}
  
# Service Account configuration
serviceAccount:
  create: true
  name: {service_account_name}
  annotations: {{}}

# RBAC configuration
rbac:
  create: true
  clusterRole:
    name: {service_account_name}-clusterrole
  clusterRoleBinding:
    name: {service_account_name}-clusterrolebinding

# ClusterExtension configuration
clusterExtension:
  create: true
  name: {package_name}
  packageName: {package_name}
  installNamespace: default
"""
            
            # Add install modes
            install_modes = metadata.get('install_modes', {})
            if install_modes:
                values_content += "\n# Install modes\ninstallModes:\n"
                for mode, supported in install_modes.items():
                    values_content += f"  {mode}: {str(supported).lower()}\n"
            
            # Add webhook configuration
            if metadata.get('has_webhooks', False):
                values_content += "\n# Webhook configuration\nwebhooks:\n  enabled: true\n"
            
            return values_content
            
        except Exception as e:
            raise BundleProcessingError(f"Failed to generate Helm values: {e}")
    
    def _extract_package_name(self, image: str) -> str:
        """Extract package name from image URL"""
        if not image:
            return ""
        
        # Extract from image name (e.g., quay.io/redhat/quay-operator-bundle:v3.10.0)
        parts = image.split('/')
        if len(parts) >= 2:
            image_name = parts[-1]  # Get the last part
            # Remove tag/digest
            if ':' in image_name:
                image_name = image_name.split(':')[0]
            if '@' in image_name:
                image_name = image_name.split('@')[0]
            
            # Remove common suffixes
            suffixes = ['-bundle', '-operator-bundle']
            for suffix in suffixes:
                if image_name.endswith(suffix):
                    image_name = image_name[:-len(suffix)]
                    break
            
            return image_name
        
        return ""
