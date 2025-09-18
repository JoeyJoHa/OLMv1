"""
YAML Manifest Generator

Generates Kubernetes YAML manifests from OPM bundle metadata.
"""

import yaml
from typing import Dict, Any, Optional, List
from .base_generator import BaseGenerator, ManifestTemplates
from ..core.constants import OPMConstants, KubernetesConstants


class YAMLManifestGenerator(BaseGenerator):
    """Generates Kubernetes YAML manifests from bundle metadata"""
    
    def generate(self, bundle_metadata: Dict[str, Any], namespace: str = KubernetesConstants.DEFAULT_NAMESPACE, 
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
        
        # Perform centralized RBAC analysis once
        rbac_analysis = self.analyze_rbac_components(bundle_metadata)
        components_needed = rbac_analysis['components_needed']
        rules = rbac_analysis['rules']
        
        manifests = {}
        
        # Generate ServiceAccount (always needed)
        manifests[f'{operator_name}-serviceaccount'] = self._generate_service_account(
            operator_name, namespace
        )
        
        # Generate ClusterRoles using pre-calculated rules
        manifests[f'{operator_name}-clusterrole'] = self._generate_cluster_roles(
            rules, operator_name, package_name, components_needed
        )
        
        # Generate ClusterRoleBindings using components analysis
        manifests[f'{operator_name}-clusterrolebinding'] = self._generate_cluster_role_bindings(
            operator_name, namespace, components_needed
        )
        
        # Generate namespace Role and RoleBinding if needed
        if components_needed['namespace_role']:
            manifests[f'{operator_name}-role'] = self._generate_roles(
                rules['namespace_role'], operator_name, namespace
            )
            
            if components_needed['role_bindings']:
                manifests[f'{operator_name}-rolebinding'] = self._generate_role_bindings(
                    operator_name, namespace
                )
        
        return manifests
    
    def _generate_service_account(self, operator_name: str, namespace: str) -> str:
        """Generate ServiceAccount YAML"""
        sa_name = f"{operator_name}-installer"
        
        sa_manifest = ManifestTemplates.service_account_template(
            sa_name, namespace, operator_name
        )
        
        return self._dump_yaml_with_flowstyle_lists(sa_manifest)
    
    def _join_manifests_to_yaml(self, manifests: list) -> str:
        """
        Convert a list of manifest dictionaries into a multi-document YAML string
        
        Args:
            manifests: List of manifest dictionaries
            
        Returns:
            Multi-document YAML string with '---' separators
        """
        yaml_parts = []
        for manifest in manifests:
            yaml_parts.append(self._dump_yaml_with_flowstyle_lists(manifest))
        
        return '\n---\n'.join(yaml_parts)
    
    def _generate_cluster_roles(self, rules: Dict[str, Any], operator_name: str, 
                              package_name: str, components_needed: Dict[str, bool]) -> str:
        """
        Generate ClusterRole YAML manifests from pre-calculated rules
        
        Args:
            rules: Pre-calculated rules dictionary from analyze_rbac_components
            operator_name: Name of the operator
            package_name: Package name for header comment
            components_needed: Dictionary indicating which components are needed
            
        Returns:
            YAML string containing ClusterRole manifests
        """
        # Generate security header comment for YAML manifests
        header = self._generate_security_header_comment(operator_name, package_name, 'yaml')
        
        manifests = []
        
        # Installer ClusterRole (always needed - operator management permissions)
        if components_needed['installer_cluster_role'] and rules['installer_cluster_role']:
            operator_cr_name = f"{operator_name}-installer-clusterrole"
            
            operator_cr = ManifestTemplates.cluster_role_template(
                operator_cr_name, operator_name, rules['installer_cluster_role']
            )
            manifests.append(operator_cr)
        
        # Grantor ClusterRole (if needed - application-specific permissions)
        if components_needed['grantor_cluster_role'] and rules['grantor_cluster_role']:
            grantor_cr_name = f"{operator_name}-installer-rbac-clusterrole"
            
            grantor_cr = ManifestTemplates.cluster_role_template(
                grantor_cr_name, operator_name, rules['grantor_cluster_role']
            )
            manifests.append(grantor_cr)
        
        # Convert to YAML using shared helper method
        yaml_content = self._join_manifests_to_yaml(manifests)
        
        return f"{header}\n{yaml_content}"
    
    def _generate_cluster_role_bindings(self, operator_name: str, namespace: str, 
                                       components_needed: Dict[str, bool]) -> str:
        """
        Generate ClusterRoleBinding YAML manifests from components analysis
        
        Args:
            operator_name: Name of the operator
            namespace: Target namespace
            components_needed: Dictionary indicating which components are needed
            
        Returns:
            YAML string containing ClusterRoleBinding manifests
        """
        manifests = []
        sa_name = f"{operator_name}-installer"
        
        # Installer ClusterRoleBinding (always needed)
        if components_needed['installer_cluster_role']:
            operator_crb_name = f"{operator_name}-installer-clusterrolebinding"
            operator_cr_name = f"{operator_name}-installer-clusterrole"
            
            operator_crb = ManifestTemplates.cluster_role_binding_template(
                operator_crb_name, operator_name, operator_cr_name, sa_name, namespace
            )
            manifests.append(operator_crb)
        
        # Grantor ClusterRoleBinding (if grantor ClusterRole exists)
        if components_needed['grantor_cluster_role']:
            grantor_crb_name = f"{operator_name}-installer-rbac-clusterrolebinding"
            grantor_cr_name = f"{operator_name}-installer-rbac-clusterrole"
            
            grantor_crb = ManifestTemplates.cluster_role_binding_template(
                grantor_crb_name, operator_name, grantor_cr_name, sa_name, namespace
            )
            manifests.append(grantor_crb)
        
        # Convert to YAML using shared helper method
        return self._join_manifests_to_yaml(manifests)
    
    def _generate_roles(self, role_rules: List[Dict[str, Any]], 
                       operator_name: str, namespace: str) -> str:
        """
        Generate Role YAML manifests from pre-calculated rules
        
        Args:
            role_rules: Pre-calculated role rules from analyze_rbac_components
            operator_name: Name of the operator
            namespace: Target namespace
            
        Returns:
            YAML string containing Role manifests
        """
        manifests = []
        
        # Generate Role only if we have rules
        if role_rules:
            role_name = f"{operator_name}-installer-role"
            
            role_manifest = ManifestTemplates.role_template(
                role_name, namespace, operator_name, role_rules
            )
            manifests.append(role_manifest)
        
        # Convert to YAML using shared helper method
        return self._join_manifests_to_yaml(manifests)
    
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
        
        # Convert to YAML using shared helper method
        return self._join_manifests_to_yaml(manifests)
