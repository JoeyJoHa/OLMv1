"""
YAML Manifest Generator

Generates Kubernetes YAML manifests from OPM bundle metadata.
"""

import yaml
from typing import Dict, List, Any, Optional
from .base_generator import BaseGenerator, ManifestTemplates


class YAMLManifestGenerator(BaseGenerator):
    """Generates Kubernetes YAML manifests from bundle metadata"""
    
    def generate(self, bundle_metadata: Dict[str, Any], namespace: str = "default", 
                operator_name: Optional[str] = None) -> Dict[str, str]:
        """
        Generate Kubernetes YAML manifests
        
        Args:
            bundle_metadata: Bundle metadata from OPM
            namespace: Target namespace
            operator_name: Optional custom operator name
            
        Returns:
            Dict mapping manifest names to YAML content
        """
        # Extract basic info
        package_name = bundle_metadata.get('package_name', 'my-operator')
        operator_name = operator_name or package_name
        
        manifests = {}
        
        # Generate ServiceAccount
        manifests['01-serviceaccount'] = self._generate_service_account(
            operator_name, namespace
        )
        
        # Generate ClusterRoles
        manifests['02-clusterrole'] = self._generate_cluster_roles(
            bundle_metadata, operator_name
        )
        
        # Generate ClusterRoleBindings
        manifests['03-clusterrolebinding'] = self._generate_cluster_role_bindings(
            operator_name, namespace
        )
        
        # Generate Roles and RoleBindings based on permissions logic
        has_cluster_permissions = bool(bundle_metadata.get('cluster_permissions', []))
        has_namespace_permissions = bool(bundle_metadata.get('permissions', []))
        
        # Only generate Roles if both clusterPermissions and permissions exist
        if has_cluster_permissions and has_namespace_permissions:
            # Both exist (e.g., ArgoCD) - generate grantor Role for namespace permissions
            namespace_rules = self._generate_namespace_rules(bundle_metadata)
            if namespace_rules:
                manifests['04-role'] = self._generate_roles(
                    bundle_metadata, operator_name, namespace
                )
                
                # Generate RoleBindings
                manifests['05-rolebinding'] = self._generate_role_bindings(
                    operator_name, namespace
                )
        # For cluster-only permissions (Quay) or permissions-only (legacy), no Roles needed
        
        return manifests
    
    def _generate_service_account(self, operator_name: str, namespace: str) -> str:
        """Generate ServiceAccount YAML"""
        sa_name = f"{operator_name}-installer"
        
        sa_manifest = ManifestTemplates.service_account_template(
            sa_name, namespace, operator_name
        )
        
        return yaml.dump(sa_manifest, default_flow_style=False, sort_keys=False)
    
    def _generate_cluster_roles(self, bundle_metadata: Dict[str, Any], 
                              operator_name: str) -> str:
        """Generate ClusterRole YAML manifests"""
        manifests = []
        
        # Operator ClusterRole
        operator_rules = self._generate_operator_rules(bundle_metadata)
        operator_cr_name = f"{operator_name}-installer-clusterrole"
        
        operator_cr = ManifestTemplates.cluster_role_template(
            operator_cr_name, operator_name, operator_rules
        )
        manifests.append(operator_cr)
        
        # Grantor ClusterRole
        grantor_rules = self._generate_grantor_rules(bundle_metadata)
        if grantor_rules:
            grantor_cr_name = f"{operator_name}-installer-rbac-clusterrole"
            
            grantor_cr = ManifestTemplates.cluster_role_template(
                grantor_cr_name, operator_name, grantor_rules
            )
            manifests.append(grantor_cr)
        
        # Convert to YAML with document separator
        yaml_parts = []
        for manifest in manifests:
            yaml_parts.append(yaml.dump(manifest, default_flow_style=False, sort_keys=False))
        
        return '\n---\n'.join(yaml_parts)
    
    def _generate_cluster_role_bindings(self, operator_name: str, namespace: str) -> str:
        """Generate ClusterRoleBinding YAML manifests"""
        manifests = []
        sa_name = f"{operator_name}-installer"
        
        # Operator ClusterRoleBinding
        operator_crb_name = f"{operator_name}-installer-clusterrolebinding"
        operator_cr_name = f"{operator_name}-installer-clusterrole"
        
        operator_crb = ManifestTemplates.cluster_role_binding_template(
            operator_crb_name, operator_name, operator_cr_name, sa_name, namespace
        )
        manifests.append(operator_crb)
        
        # Grantor ClusterRoleBinding (if grantor rules exist)
        grantor_crb_name = f"{operator_name}-installer-rbac-clusterrolebinding"
        grantor_cr_name = f"{operator_name}-installer-rbac-clusterrole"
        
        grantor_crb = ManifestTemplates.cluster_role_binding_template(
            grantor_crb_name, operator_name, grantor_cr_name, sa_name, namespace
        )
        manifests.append(grantor_crb)
        
        # Convert to YAML with document separator
        yaml_parts = []
        for manifest in manifests:
            yaml_parts.append(yaml.dump(manifest, default_flow_style=False, sort_keys=False))
        
        return '\n---\n'.join(yaml_parts)
    
    def _generate_roles(self, bundle_metadata: Dict[str, Any], 
                       operator_name: str, namespace: str) -> str:
        """Generate Role YAML manifests"""
        manifests = []
        
        # Generate grantor Role (namespace permissions from CSV)
        namespace_rules = self._generate_namespace_rules(bundle_metadata)
        if namespace_rules:
            role_name = f"{operator_name}-installer-role"
            
            role_manifest = ManifestTemplates.role_template(
                role_name, namespace, operator_name, namespace_rules
            )
            manifests.append(role_manifest)
        
        # Convert to YAML with document separator
        yaml_parts = []
        for manifest in manifests:
            yaml_parts.append(yaml.dump(manifest, default_flow_style=False, sort_keys=False))
        
        return '\n---\n'.join(yaml_parts)
    
    def _generate_role_bindings(self, operator_name: str, namespace: str) -> str:
        """Generate RoleBinding YAML manifests"""
        manifests = []
        
        # Generate RoleBinding for the grantor Role
        sa_name = f"{operator_name}-installer"
        role_name = f"{operator_name}-installer-role"
        binding_name = f"{operator_name}-installer-rolebinding"
        
        role_binding = ManifestTemplates.role_binding_template(
            binding_name, namespace, operator_name, role_name, sa_name
        )
        manifests.append(role_binding)
        
        # Convert to YAML with document separator
        yaml_parts = []
        for manifest in manifests:
            yaml_parts.append(yaml.dump(manifest, default_flow_style=False, sort_keys=False))
        
        return '\n---\n'.join(yaml_parts)
