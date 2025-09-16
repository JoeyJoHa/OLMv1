"""
Base Generator Classes and Common Logic

This module provides base classes and shared functionality for generating
YAML manifests and Helm values from OPM bundle metadata.
"""

import logging
import yaml
from typing import Dict, List, Any, Optional, NamedTuple
from abc import ABC, abstractmethod
from enum import Enum

from ..core.constants import (
    KubernetesConstants, 
    OPMConstants, 
    RoleConstants,
    FileConstants
)

logger = logging.getLogger(__name__)


class PermissionStrategy(Enum):
    """Enumeration of permission generation strategies"""
    BOTH_CLUSTER_AND_NAMESPACE = "both_cluster_and_namespace"
    CLUSTER_ONLY = "cluster_only"  # Standard cluster operator
    NAMESPACE_ONLY_AS_CLUSTER = "namespace_only_as_cluster"
    NO_PERMISSIONS = "no_permissions"  # Minimal operator


class PermissionAnalysis(NamedTuple):
    """Analysis result of bundle permissions"""
    strategy: PermissionStrategy
    has_cluster_permissions: bool
    has_namespace_permissions: bool
    cluster_rules: List[Dict[str, Any]]
    namespace_rules: List[Dict[str, Any]]

class BaseGenerator(ABC):
    """Base class for all generators with common functionality"""
    
    def __init__(self):
        self.logger = logger
    
    def analyze_permissions(self, bundle_metadata: Dict[str, Any]) -> PermissionAnalysis:
        """
        Analyze bundle permissions and determine generation strategy
        
        Args:
            bundle_metadata: Bundle metadata from OPM
            
        Returns:
            PermissionAnalysis with strategy and extracted rules
        """
        has_cluster_permissions = bool(bundle_metadata.get(OPMConstants.BUNDLE_CLUSTER_PERMISSIONS_KEY, []))
        has_namespace_permissions = bool(bundle_metadata.get(OPMConstants.BUNDLE_PERMISSIONS_KEY, []))
        
        # Extract rules
        cluster_rules = self._extract_cluster_rules(bundle_metadata)
        namespace_rules = self._extract_namespace_rules(bundle_metadata)
        
        # Determine strategy
        if has_cluster_permissions and has_namespace_permissions:
            strategy = PermissionStrategy.BOTH_CLUSTER_AND_NAMESPACE
        elif has_cluster_permissions:
            strategy = PermissionStrategy.CLUSTER_ONLY
        elif has_namespace_permissions:
            strategy = PermissionStrategy.NAMESPACE_ONLY_AS_CLUSTER
        else:
            strategy = PermissionStrategy.NO_PERMISSIONS
            
        return PermissionAnalysis(
            strategy=strategy,
            has_cluster_permissions=has_cluster_permissions,
            has_namespace_permissions=has_namespace_permissions,
            cluster_rules=cluster_rules,
            namespace_rules=namespace_rules
        )
    
    def _extract_cluster_rules(self, bundle_metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract cluster-scoped rules from bundle metadata"""
        rules = []
        for perm in bundle_metadata.get(OPMConstants.BUNDLE_CLUSTER_PERMISSIONS_KEY, []):
            rules.extend(perm.get('rules', []))
        return rules
    
    def _extract_namespace_rules(self, bundle_metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract namespace-scoped rules from bundle metadata"""  
        rules = []
        for perm in bundle_metadata.get(OPMConstants.BUNDLE_PERMISSIONS_KEY, []):
            rules.extend(perm.get('rules', []))
        return rules
    
    def _extract_crd_names(self, bundle_metadata: Dict[str, Any]) -> List[str]:
        """
        Extract CRD names from bundle metadata
        
        Args:
            bundle_metadata: Bundle metadata from OPM
            
        Returns:
            List of CRD names
        """
        crd_names = []
        
        # Primary source: Extract from CSV spec.customresourcedefinitions.owned
        csv_crds = bundle_metadata.get('csv_crds', [])
        for crd in csv_crds:
            name = crd.get('name')
            if name:
                crd_names.append(name)
        
        # Fallback: infer from API groups
        if not crd_names:
            api_groups = bundle_metadata.get('api_groups', [])
            for api_group in api_groups:
                if '.' in api_group and not api_group.startswith('k8s.io'):
                    # Infer CRD name from API group (e.g., quay.redhat.com -> quayregistries.quay.redhat.com)
                    parts = api_group.split('.')
                    if len(parts) >= 2:
                        resource_name = f"{parts[0]}s"  # Simple pluralization
                        crd_name = f"{resource_name}.{api_group}"
                        crd_names.append(crd_name)
        
        return crd_names
    
    def _generate_operator_rules(self, bundle_metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate operator management rules following OLMv1 security practices
        
        Args:
            bundle_metadata: Bundle metadata from OPM
            
        Returns:
            List of RBAC rules for operator management
        """
        operator_name = bundle_metadata.get('package_name', 'my-operator')
        crd_names = self._extract_crd_names(bundle_metadata)
        
        rules = []
        
        # ClusterExtension finalizer management (scoped to this operator)
        rules.append({
            'apiGroups': [KubernetesConstants.OLM_API_GROUP],
            'resources': [f'{KubernetesConstants.CLUSTER_EXTENSIONS_RESOURCE}/finalizers'],
            'verbs': [KubernetesConstants.UPDATE_VERB]
            # Note: resourceNames should be added post-installation with chosen ClusterExtension name
        })
        
        # CRD management permissions
        # Unscoped permissions for CRD lifecycle
        rules.append({
            'apiGroups': [KubernetesConstants.APIEXTENSIONS_API_GROUP],
            'resources': [KubernetesConstants.CUSTOM_RESOURCE_DEFINITIONS_RESOURCE],
            'verbs': [
                KubernetesConstants.CREATE_VERB, 
                KubernetesConstants.LIST_VERB, 
                KubernetesConstants.WATCH_VERB
            ]
        })
        
        # Scoped permissions for specific CRDs
        if crd_names:
            rules.append({
                'apiGroups': [KubernetesConstants.APIEXTENSIONS_API_GROUP],
                'resources': [KubernetesConstants.CUSTOM_RESOURCE_DEFINITIONS_RESOURCE],
                'verbs': [
                    KubernetesConstants.GET_VERB, 
                    KubernetesConstants.UPDATE_VERB, 
                    KubernetesConstants.PATCH_VERB, 
                    KubernetesConstants.DELETE_VERB
                ],
                'resourceNames': crd_names
            })
        
        # RBAC management permissions
        # Unscoped permissions for RBAC lifecycle
        rules.extend([
            {
                'apiGroups': [KubernetesConstants.RBAC_API_GROUP],
                'resources': [KubernetesConstants.CLUSTER_ROLES_RESOURCE],
                'verbs': [
                    KubernetesConstants.CREATE_VERB, 
                    KubernetesConstants.LIST_VERB, 
                    KubernetesConstants.WATCH_VERB
                ]
            },
            {
                'apiGroups': [KubernetesConstants.RBAC_API_GROUP],
                'resources': [KubernetesConstants.CLUSTER_ROLES_RESOURCE],
                'verbs': [
                    KubernetesConstants.GET_VERB, 
                    KubernetesConstants.UPDATE_VERB, 
                    KubernetesConstants.PATCH_VERB, 
                    KubernetesConstants.DELETE_VERB
                ]
                # Note: resourceNames should be added post-installation
            },
            {
                'apiGroups': [KubernetesConstants.RBAC_API_GROUP],
                'resources': [KubernetesConstants.CLUSTER_ROLE_BINDINGS_RESOURCE],
                'verbs': [
                    KubernetesConstants.CREATE_VERB, 
                    KubernetesConstants.LIST_VERB, 
                    KubernetesConstants.WATCH_VERB
                ]
            },
            {
                'apiGroups': [KubernetesConstants.RBAC_API_GROUP],
                'resources': [KubernetesConstants.CLUSTER_ROLE_BINDINGS_RESOURCE],
                'verbs': [
                    KubernetesConstants.GET_VERB, 
                    KubernetesConstants.UPDATE_VERB, 
                    KubernetesConstants.PATCH_VERB, 
                    KubernetesConstants.DELETE_VERB
                ]
                # Note: resourceNames should be added post-installation
            }
        ])
        
        return rules
    
    def _generate_grantor_rules(self, bundle_metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate grantor rules from extracted CSV permissions
        
        Args:
            bundle_metadata: Bundle metadata from OPM
            
        Returns:
            List of RBAC rules extracted from the CSV
        """
        # Get permissions directly from bundle metadata (raw extracted permissions)
        permissions = bundle_metadata.get(OPMConstants.BUNDLE_PERMISSIONS_KEY, [])
        cluster_permissions = bundle_metadata.get(OPMConstants.BUNDLE_CLUSTER_PERMISSIONS_KEY, [])
        
        rules = []
        
        # Extract rules from permissions (namespace-scoped)
        for permission in permissions:
            permission_rules = permission.get('rules', [])
            rules.extend(permission_rules)
        
        # Extract rules from cluster permissions (cluster-scoped)
        for cluster_permission in cluster_permissions:
            cluster_rules = cluster_permission.get('rules', [])
            rules.extend(cluster_rules)
        
        return rules
    
    def _generate_namespace_rules(self, bundle_metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate namespace-scoped rules from bundle metadata
        
        Args:
            bundle_metadata: Bundle metadata from OPM
            
        Returns:
            List of RBAC rules for namespace-scoped permissions only
        """
        # Extract namespace-scoped permissions from bundle metadata
        permissions = bundle_metadata.get(OPMConstants.BUNDLE_PERMISSIONS_KEY, [])
        
        rules = []
        for perm in permissions:
            perm_rules = perm.get('rules', [])
            rules.extend(perm_rules)
        
        return rules
    
    def _dump_yaml_with_flow_arrays(self, data: Dict[str, Any]) -> str:
        """
        Dump YAML with mixed block/flow style for better readability
        
        Args:
            data: Data to format as YAML
            
        Returns:
            YAML string with flow style arrays for RBAC rules
        """
        # Create a custom YAML dumper that uses flow style for specific arrays
        class FlowArrayDumper(yaml.SafeDumper):
            pass
        
        def represent_list(dumper, data):
            # Only apply flow style to string arrays (not mixed types)
            if not data or not all(isinstance(item, str) for item in data):
                return dumper.represent_sequence('tag:yaml.org,2002:seq', data, flow_style=False)
            
            # Intelligent pattern detection for RBAC arrays
            def is_rbac_array_intelligent(items):
                """
                Intelligently detect RBAC arrays using pattern analysis
                instead of hardcoded lists
                """
                sample_text = ' '.join(items).lower()
                
                # 1. Standard Kubernetes RBAC verbs pattern
                k8s_verbs = {'get', 'list', 'watch', 'create', 'update', 'patch', 'delete'}
                if any(verb in sample_text for verb in k8s_verbs):
                    return True
                
                # 2. API group pattern detection
                # a) Dotted API groups (e.g., rbac.authorization.k8s.io, argoproj.io)
                if any('.' in item and len(item.split('.')) >= 2 for item in items):
                    return True
                
                # b) Pattern-based API group detection (no hardcoded lists)
                # API groups are typically lowercase, single words or compound words
                # that don't look like typical resource names
                for item in items:
                    item_lower = item.lower()
                    # Skip empty string (core API) - handle separately
                    if not item_lower:
                        continue
                    
                    # API groups typically:
                    # - Are single words without slashes or complex suffixes
                    # - Don't end with typical resource plural patterns
                    # - Are relatively short (< 20 chars typically)
                    # - Don't contain numbers or special chars (except dots/hyphens)
                    is_likely_api_group = (
                        len(item_lower) < 20 and  # Reasonable length
                        '/' not in item_lower and  # Not a subresource
                        not item_lower.endswith(('s', 'ies', 'es', 'finalizers', 'status')) and  # Not typical resource plural
                        not any(char.isdigit() for char in item_lower) and  # No version numbers
                        all(char.isalpha() or char in '.-' for char in item_lower)  # Only letters, dots, hyphens
                    )
                    
                    if is_likely_api_group:
                        return True
                
                # 3. Kubernetes resource pattern detection
                # Resources often end with 's' (plural) or have specific patterns
                resource_indicators = {
                    # Common suffixes
                    lambda x: x.endswith(('s', 'ies', 'es')),  # Plural resources
                    # Common patterns
                    lambda x: '/' in x,  # Subresources like 'pods/log', 'deployments/finalizers'
                    lambda x: x.endswith('finalizers'),  # Finalizers
                    lambda x: x.endswith('status'),  # Status subresources
                    lambda x: len(x) > 4 and '-' in x,  # Hyphenated resources
                }
                
                resource_like_count = sum(
                    1 for item in items 
                    if any(indicator(item.lower()) for indicator in resource_indicators)
                )
                
                # If majority of items look like resources, treat as RBAC array
                if len(items) > 0 and resource_like_count / len(items) >= 0.5:
                    return True
                
                # 4. Single wildcard permission
                if items == ['*']:
                    return True
                
                # 5. Pattern-based core resource detection
                # No hardcoded lists - detect by patterns that indicate K8s resources
                for item in items:
                    item_lower = item.lower()
                    # Resources typically end with 's' or have specific patterns
                    is_likely_resource = (
                        item_lower.endswith(('s', 'ies')) and len(item_lower) > 3 or  # Typical plurals
                        '/' in item_lower or  # Subresources
                        item_lower.endswith(('finalizers', 'status')) or  # Common subresources
                        (len(item_lower) > 4 and '-' in item_lower)  # Hyphenated resources
                    )
                    if is_likely_resource:
                        return True
                
                # 6. Empty string API group (core API)
                if '' in items:  # Core API group
                    return True
                
                return False
            
            # Apply flow style if detected as RBAC array
            if is_rbac_array_intelligent(data):
                return dumper.represent_sequence('tag:yaml.org,2002:seq', data, flow_style=True)
            
            # Default to block style for other arrays
            return dumper.represent_sequence('tag:yaml.org,2002:seq', data, flow_style=False)
        
        FlowArrayDumper.add_representer(list, represent_list)
        
        # Dump with custom representer
        yaml_output = yaml.dump(data, Dumper=FlowArrayDumper, default_flow_style=False, sort_keys=False)
        
        # Post-process to add comments for role types (for Helm values)
        lines = yaml_output.split('\n')
        processed_lines = []
        
        for i, line in enumerate(lines):
            # Look for role type indicators to add helpful comments
            if '- name:' in line and i+1 < len(lines) and 'type:' in lines[i+1]:
                role_type = lines[i+1].split('type: ')[1] if 'type: ' in lines[i+1] else ''
                if role_type == 'operator':
                    processed_lines.append(line)
                    processed_lines.append('    # Operator management permissions (CRDs, RBAC, finalizers)')
                elif role_type == 'grantor':
                    processed_lines.append(line)
                    processed_lines.append('    # Application-specific permissions from bundle metadata')
                else:
                    processed_lines.append(line)
            else:
                processed_lines.append(line)
        
        return '\n'.join(processed_lines)
    
    @abstractmethod
    def generate(self, bundle_metadata: Dict[str, Any], **kwargs) -> str:
        """
        Generate output from bundle metadata
        
        Args:
            bundle_metadata: Bundle metadata from OPM
            **kwargs: Additional generation parameters
            
        Returns:
            Generated content as string
        """
        pass


class PermissionStructure:
    """Helper class for managing permission structures"""
    
    @staticmethod
    def create_cluster_role_structure(name: str, role_type: str, rules: List[Dict[str, Any]], 
                                    create: bool = True) -> Dict[str, Any]:
        """
        Create a cluster role structure
        
        Args:
            name: Role name (empty string for template)
            role_type: Type of role ('operator' or 'grantor')
            rules: RBAC rules
            create: Whether to create the role
            
        Returns:
            Cluster role structure
        """
        return {
            'name': name,
            'type': role_type,
            'create': create,
            'customRules': rules
        }
    
    @staticmethod
    def create_role_structure(name: str, role_type: str, rules: List[Dict[str, Any]], 
                            create: bool = False) -> Dict[str, Any]:
        """
        Create a role structure
        
        Args:
            name: Role name (empty string for template)
            role_type: Type of role ('operator' or 'grantor')
            rules: RBAC rules
            create: Whether to create the role
            
        Returns:
            Role structure
        """
        return {
            'name': name,
            'type': role_type,
            'create': create,
            'customRules': rules
        }


class ManifestTemplates:
    """Templates for Kubernetes manifests"""
    
    @staticmethod
    def service_account_template(name: str, namespace: str, operator_name: str) -> Dict[str, Any]:
        """ServiceAccount manifest template"""
        return {
            'apiVersion': 'v1',
            'kind': 'ServiceAccount',
            'metadata': {
                'labels': {
                    KubernetesConstants.MANAGED_BY_LABEL: KubernetesConstants.RBAC_MANAGER_COMPONENT,
                    KubernetesConstants.NAME_LABEL: operator_name,
                    'olmv1': name
                },
                'name': name,
                'namespace': namespace
            }
        }
    
    @staticmethod
    def cluster_role_template(name: str, operator_name: str, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        """ClusterRole manifest template"""
        return {
            'apiVersion': f'{KubernetesConstants.RBAC_API_GROUP}/v1',
            'kind': 'ClusterRole',
            'metadata': {
                'labels': {
                    KubernetesConstants.MANAGED_BY_LABEL: KubernetesConstants.RBAC_MANAGER_COMPONENT,
                    KubernetesConstants.NAME_LABEL: operator_name
                },
                'name': name
            },
            'rules': rules
        }
    
    @staticmethod
    def cluster_role_binding_template(name: str, operator_name: str, role_name: str, 
                                    service_account_name: str, namespace: str) -> Dict[str, Any]:
        """ClusterRoleBinding manifest template"""
        return {
            'apiVersion': f'{KubernetesConstants.RBAC_API_GROUP}/v1',
            'kind': 'ClusterRoleBinding',
            'metadata': {
                'labels': {
                    KubernetesConstants.MANAGED_BY_LABEL: KubernetesConstants.RBAC_MANAGER_COMPONENT,
                    KubernetesConstants.NAME_LABEL: operator_name
                },
                'name': name
            },
            'roleRef': {
                'apiGroup': KubernetesConstants.RBAC_API_GROUP,
                'kind': 'ClusterRole',
                'name': role_name
            },
            'subjects': [{
                'kind': 'ServiceAccount',
                'name': service_account_name,
                'namespace': namespace
            }]
        }
    
    @staticmethod
    def role_template(name: str, namespace: str, operator_name: str, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Role manifest template"""
        return {
            'apiVersion': f'{KubernetesConstants.RBAC_API_GROUP}/v1',
            'kind': 'Role',
            'metadata': {
                'labels': {
                    KubernetesConstants.MANAGED_BY_LABEL: KubernetesConstants.RBAC_MANAGER_COMPONENT,
                    KubernetesConstants.NAME_LABEL: operator_name
                },
                'name': name,
                'namespace': namespace
            },
            'rules': rules
        }
    
    @staticmethod
    def role_binding_template(name: str, namespace: str, operator_name: str, role_name: str, 
                            service_account_name: str) -> Dict[str, Any]:
        """RoleBinding manifest template"""
        return {
            'apiVersion': f'{KubernetesConstants.RBAC_API_GROUP}/v1',
            'kind': 'RoleBinding',
            'metadata': {
                'labels': {
                    KubernetesConstants.MANAGED_BY_LABEL: KubernetesConstants.RBAC_MANAGER_COMPONENT,
                    KubernetesConstants.NAME_LABEL: operator_name
                },
                'name': name,
                'namespace': namespace
            },
            'roleRef': {
                'apiGroup': KubernetesConstants.RBAC_API_GROUP,
                'kind': 'Role',
                'name': role_name
            },
            'subjects': [{
                'kind': 'ServiceAccount',
                'name': service_account_name,
                'namespace': namespace
            }]
        }


class HelmValueTemplates:
    """Templates for Helm values structures"""
    
    @staticmethod
    def base_values_template(operator_name: str, version: str, package_name: str) -> Dict[str, Any]:
        """Base Helm values template"""
        return {
            'nameOverride': '',
            'fullnameOverride': '',
            'operator': {
                'name': operator_name,
                'create': True,
                'appVersion': version,
                'channel': KubernetesConstants.DEFAULT_CHANNEL,
                'packageName': package_name
            },
            'serviceAccount': {
                'create': True,
                'name': '',
                'bind': True,
                'annotations': {},
                'labels': {}
            },
            'permissions': {
                'clusterRoles': [],
                'roles': []
            },
            'additionalResources': []
        }
