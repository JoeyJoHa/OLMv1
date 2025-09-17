"""
Bundle Processor

High-level processing of operator bundles including metadata extraction and validation.
"""

import logging
from typing import Dict, Any, Optional

from ..core.exceptions import BundleProcessingError
from ..core.constants import OPMConstants, KubernetesConstants
from .client import OPMClient
from .helm_generator import HelmValuesGenerator
from .yaml_generator import YAMLManifestGenerator

logger = logging.getLogger(__name__)


class BundleProcessor:
    """High-level processor for operator bundles"""
    
    def __init__(self, skip_tls: bool = False, debug: bool = False):
        """
        Initialize bundle processor
        
        Args:
            skip_tls: Whether to skip TLS verification
            debug: Enable debug logging
        """
        self.skip_tls = skip_tls
        self.debug = debug
        self.client = OPMClient(skip_tls, debug)
        self.helm_generator = HelmValuesGenerator()
        self.yaml_generator = YAMLManifestGenerator()
    
    def is_index_image(self, image: str) -> bool:
        """
        Check if image is an index image
        
        Args:
            image: Container image URL
            
        Returns:
            bool: True if image is an index image
        """
        return self.client.is_index_image(image)
    
    def extract_bundle_metadata(self, image: str, registry_token: str = None) -> Optional[Dict[str, Any]]:
        """
        Extract and process bundle metadata
        
        Args:
            image: Container image URL
            registry_token: Registry authentication token (optional)
            
        Returns:
            Dict containing processed bundle metadata, None if extraction fails
        """
        try:
            # Validate image first
            self.client.validate_image(image)
            
            # Extract raw metadata
            raw_metadata = self.client.extract_bundle_metadata(image, registry_token)
            
            # Process and enhance metadata
            processed_metadata = self._process_metadata(raw_metadata)
            
            return processed_metadata
            
        except Exception as e:
            logger.error(f"Failed to extract bundle metadata: {e}")
            return None
    
    def _process_metadata(self, raw_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process and enhance raw bundle metadata
        
        Args:
            raw_metadata: Raw metadata from OPM extraction
            
        Returns:
            Dict containing processed metadata
        """
        processed = raw_metadata.copy()
        
        # Ensure required fields exist
        processed.setdefault(OPMConstants.BUNDLE_PERMISSIONS_KEY, [])
        processed.setdefault(OPMConstants.BUNDLE_CLUSTER_PERMISSIONS_KEY, [])
        processed.setdefault('service_account', 'default')
        processed.setdefault('install_modes', {})
        processed.setdefault('has_webhooks', False)
        
        # Process all bundle objects systematically
        self._process_bundle_objects(processed)
        
        # Process permissions for easier consumption
        processed['rbac_rules'] = self._extract_rbac_rules(processed)
        
        # Add metadata summary
        processed['summary'] = self._create_summary(processed)
        
        return processed
    
    def _process_bundle_objects(self, metadata: Dict[str, Any]) -> None:
        """
        Process all bundle objects systematically based on their Kind
        
        Args:
            metadata: Bundle metadata dictionary to update
        """
        try:
            # Initialize resource collections
            cluster_scoped_resources = []
            namespace_scoped_resources = []
            
            # Get raw bundle data
            bundle_data = metadata.get('_raw_bundle_data', [])
            
            for item in bundle_data:
                properties = item.get('properties', [])
                
                for prop in properties:
                    if prop.get('type') == OPMConstants.OLM_BUNDLE_OBJECT_PROPERTY:
                        try:
                            # Decode base64 data
                            import base64
                            import json
                            
                            data = prop.get('value', {}).get('data', '')
                            if data:
                                decoded_data = base64.b64decode(data).decode('utf-8')
                                resource = json.loads(decoded_data)
                                
                                # Process resource based on its kind
                                kind = resource.get('kind', '')
                                if kind:
                                    resource_info = self._create_resource_info(resource)
                                    
                                    # Categorize by scope
                                    if self._is_cluster_scoped_resource(kind):
                                        cluster_scoped_resources.append(resource_info)
                                    elif self._is_namespace_scoped_resource(kind):
                                        namespace_scoped_resources.append(resource_info)
                                    
                        except Exception as e:
                            logger.debug(f"Failed to decode bundle object: {e}")
                            continue
            
            # Store processed resources
            metadata['cluster_scoped_resources'] = cluster_scoped_resources
            metadata['namespace_scoped_resources'] = namespace_scoped_resources
            
            logger.debug(f"Processed bundle objects: {len(cluster_scoped_resources)} cluster-scoped, "
                        f"{len(namespace_scoped_resources)} namespace-scoped")
            
        except Exception as e:
            logger.warning(f"Failed to process bundle objects: {e}")
            metadata['cluster_scoped_resources'] = []
            metadata['namespace_scoped_resources'] = []
    
    def _create_resource_info(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create standardized resource information
        
        Args:
            resource: Kubernetes resource manifest
            
        Returns:
            Standardized resource info dictionary
        """
        metadata = resource.get('metadata', {})
        return {
            'kind': resource.get('kind', ''),
            'name': metadata.get('name', ''),
            'apiVersion': resource.get('apiVersion', ''),
            'namespace': metadata.get('namespace'),  # Will be None for cluster-scoped
            'labels': metadata.get('labels', {}),
            'annotations': metadata.get('annotations', {})
        }
    
    def _is_cluster_scoped_resource(self, kind: str) -> bool:
        """
        Determine if a resource kind is cluster-scoped using algorithmic approach
        
        Uses Kubernetes naming conventions:
        1. Resources starting with "Cluster" are typically cluster-scoped
        2. Global infrastructure resources are cluster-scoped
        3. Security and policy resources are often cluster-scoped
        4. Storage classes and drivers are cluster-scoped
        
        Args:
            kind: Kubernetes resource kind
            
        Returns:
            True if cluster-scoped, False otherwise
        """
        if not kind:
            return False
        
        # Special case: ClusterServiceVersion is neither cluster nor namespace scoped
        # It's a special OLM resource that exists in a namespace but describes cluster resources
        if kind == 'ClusterServiceVersion':
            return False
        
        # Rule 1: Resources with "Cluster" prefix are cluster-scoped
        if kind.startswith('Cluster'):
            return True
        
        # Rule 2: Resources ending with "Class" are typically cluster-scoped
        if kind.endswith('Class'):
            return True
        
        # Rule 3: Custom Resource Definitions are always cluster-scoped
        if kind == 'CustomResourceDefinition':
            return True
        
        # Rule 4: Persistent Volumes (not Claims) are cluster-scoped
        if kind == 'PersistentVolume':
            return True
        
        # Rule 5: CSI (Container Storage Interface) resources are cluster-scoped
        if kind.startswith('CSI'):
            return True
        
        # Rule 6: Webhook configurations are cluster-scoped
        if 'WebhookConfiguration' in kind:
            return True
        
        # Rule 7: API services and reviews are cluster-scoped
        if kind in ('APIService', 'TokenReview', 'SubjectAccessReview', 'SelfSubjectAccessReview'):
            return True
        
        # Rule 8: Certificate and flow control resources are cluster-scoped
        if kind in ('CertificateSigningRequest', 'FlowSchema', 'PriorityLevelConfiguration'):
            return True
        
        # Rule 9: Volume attachments are cluster-scoped
        if 'VolumeAttachment' in kind:
            return True
        
        # Rule 10: Node-related resources are typically cluster-scoped
        if 'Node' in kind:
            return True
        
        # Default: assume namespace-scoped (safer default)
        return False
    
    def _is_namespace_scoped_resource(self, kind: str) -> bool:
        """
        Determine if a resource kind is namespace-scoped using algorithmic approach
        
        Uses logical rules:
        1. If cluster-scoped, then not namespace-scoped
        2. ClusterServiceVersion is special (neither truly cluster nor namespace scoped)
        3. Most other resources are namespace-scoped by default
        
        Args:
            kind: Kubernetes resource kind
            
        Returns:
            True if namespace-scoped, False otherwise
        """
        if not kind:
            return False
        
        # Special case: ClusterServiceVersion is neither truly cluster nor namespace scoped
        # It's a special OLM resource that exists in a namespace but describes cluster resources
        if kind == 'ClusterServiceVersion':
            return False
        
        # If it's cluster-scoped, it's not namespace-scoped
        if self._is_cluster_scoped_resource(kind):
            return False
        
        # Default: most Kubernetes resources are namespace-scoped
        # This is the safer default and handles custom resources correctly
        return True
    
    def _extract_rbac_rules(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract and organize RBAC rules
        
        Args:
            metadata: Bundle metadata
            
        Returns:
            Dict containing organized RBAC rules
        """
        rbac_rules = {
            'namespace_rules': [],
            'cluster_rules': [],
            'service_accounts': []
        }
        
        # Extract namespace-scoped rules
        for permission in metadata.get(OPMConstants.BUNDLE_PERMISSIONS_KEY, []):
            service_account = permission.get('serviceAccountName', 'default')
            rules = permission.get('rules', [])
            
            rbac_rules['namespace_rules'].extend(rules)
            if service_account not in rbac_rules['service_accounts']:
                rbac_rules['service_accounts'].append(service_account)
        
        # Extract cluster-scoped rules
        for cluster_permission in metadata.get(OPMConstants.BUNDLE_CLUSTER_PERMISSIONS_KEY, []):
            service_account = cluster_permission.get('serviceAccountName', 'default')
            rules = cluster_permission.get('rules', [])
            
            rbac_rules['cluster_rules'].extend(rules)
            if service_account not in rbac_rules['service_accounts']:
                rbac_rules['service_accounts'].append(service_account)
        
        return rbac_rules
    
    def _create_summary(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create metadata summary
        
        Args:
            metadata: Bundle metadata
            
        Returns:
            Dict containing summary information
        """
        rbac_rules = metadata.get('rbac_rules', {})
        
        summary = {
            'total_permissions': len(metadata.get(OPMConstants.BUNDLE_PERMISSIONS_KEY, [])),
            'total_cluster_permissions': len(metadata.get(OPMConstants.BUNDLE_CLUSTER_PERMISSIONS_KEY, [])),
            'total_namespace_rules': len(rbac_rules.get('namespace_rules', [])),
            'total_cluster_rules': len(rbac_rules.get('cluster_rules', [])),
            'service_accounts': rbac_rules.get('service_accounts', []),
            'has_webhooks': metadata.get('has_webhooks', False),
            'install_modes': metadata.get('install_modes', {})
        }
        
        return summary
    
    def generate_helm_values(self, bundle_metadata: Dict[str, Any], operator_name: Optional[str] = None, channel: Optional[str] = None) -> str:
        """
        Generate Helm values from processed bundle metadata
        
        Args:
            bundle_metadata: Processed bundle metadata
            operator_name: Optional custom operator name
            channel: Optional channel name for the operator
            
        Returns:
            Helm values YAML string
        """
        return self.helm_generator.generate(bundle_metadata, operator_name, channel=channel)
    
    def generate_yaml_manifests(self, bundle_metadata: Dict[str, Any], namespace: str = KubernetesConstants.DEFAULT_NAMESPACE, 
                              operator_name: Optional[str] = None) -> Dict[str, str]:
        """
        Generate Kubernetes YAML manifests from processed bundle metadata
        
        Args:
            bundle_metadata: Processed bundle metadata
            namespace: Target namespace
            operator_name: Optional custom operator name
            
        Returns:
            Dict mapping manifest names to YAML content
        """
        return self.yaml_generator.generate(bundle_metadata, namespace, operator_name)
