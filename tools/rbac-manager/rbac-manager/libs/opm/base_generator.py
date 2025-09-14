"""
Base Generator Classes and Common Logic

This module provides base classes and shared functionality for generating
YAML manifests and Helm values from OPM bundle metadata.
"""

import logging
from typing import Dict, List, Any, Optional
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class BaseGenerator(ABC):
    """Base class for all generators with common functionality"""
    
    def __init__(self):
        self.logger = logger
    
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
            'apiGroups': ['olm.operatorframework.io'],
            'resources': ['clusterextensions/finalizers'],
            'verbs': ['update'],
            'resourceNames': [operator_name]
        })
        
        # CRD management permissions
        # Unscoped permissions for CRD lifecycle
        rules.append({
            'apiGroups': ['apiextensions.k8s.io'],
            'resources': ['customresourcedefinitions'],
            'verbs': ['create', 'list', 'watch']
        })
        
        # Scoped permissions for specific CRDs
        if crd_names:
            rules.append({
                'apiGroups': ['apiextensions.k8s.io'],
                'resources': ['customresourcedefinitions'],
                'verbs': ['get', 'update', 'patch', 'delete'],
                'resourceNames': crd_names
            })
        
        # RBAC management permissions
        # Unscoped permissions for RBAC lifecycle
        rules.extend([
            {
                'apiGroups': ['rbac.authorization.k8s.io'],
                'resources': ['clusterroles'],
                'verbs': ['create', 'list', 'watch']
            },
            {
                'apiGroups': ['rbac.authorization.k8s.io'],
                'resources': ['clusterroles'],
                'verbs': ['get', 'update', 'patch', 'delete']
                # Note: resourceNames should be added post-installation
            },
            {
                'apiGroups': ['rbac.authorization.k8s.io'],
                'resources': ['clusterrolebindings'],
                'verbs': ['create', 'list', 'watch']
            },
            {
                'apiGroups': ['rbac.authorization.k8s.io'],
                'resources': ['clusterrolebindings'],
                'verbs': ['get', 'update', 'patch', 'delete']
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
        permissions = bundle_metadata.get('permissions', [])
        cluster_permissions = bundle_metadata.get('cluster_permissions', [])
        
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
        permissions = bundle_metadata.get('permissions', [])
        
        rules = []
        for perm in permissions:
            perm_rules = perm.get('rules', [])
            rules.extend(perm_rules)
        
        return rules
    
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
                    'app.kubernetes.io/managed-by': 'rbac-manager',
                    'app.kubernetes.io/name': operator_name,
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
            'apiVersion': 'rbac.authorization.k8s.io/v1',
            'kind': 'ClusterRole',
            'metadata': {
                'labels': {
                    'app.kubernetes.io/managed-by': 'rbac-manager',
                    'app.kubernetes.io/name': operator_name
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
            'apiVersion': 'rbac.authorization.k8s.io/v1',
            'kind': 'ClusterRoleBinding',
            'metadata': {
                'labels': {
                    'app.kubernetes.io/managed-by': 'rbac-manager',
                    'app.kubernetes.io/name': operator_name
                },
                'name': name
            },
            'roleRef': {
                'apiGroup': 'rbac.authorization.k8s.io',
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
            'apiVersion': 'rbac.authorization.k8s.io/v1',
            'kind': 'Role',
            'metadata': {
                'labels': {
                    'app.kubernetes.io/managed-by': 'rbac-manager',
                    'app.kubernetes.io/name': operator_name
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
            'apiVersion': 'rbac.authorization.k8s.io/v1',
            'kind': 'RoleBinding',
            'metadata': {
                'labels': {
                    'app.kubernetes.io/managed-by': 'rbac-manager',
                    'app.kubernetes.io/name': operator_name
                },
                'name': name,
                'namespace': namespace
            },
            'roleRef': {
                'apiGroup': 'rbac.authorization.k8s.io',
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
                'channel': 'stable',
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
