"""
YAML Manifest Generator

Generates Kubernetes YAML manifests from OPM bundle metadata.
"""

import yaml
from typing import Dict, List, Any, Optional
from .base_generator import BaseGenerator, ManifestTemplates
from ..core.constants import OPMConstants


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
        manifests[f'{operator_name}-serviceaccount'] = self._generate_service_account(
            operator_name, namespace
        )
        
        # Generate ClusterRoles
        manifests[f'{operator_name}-clusterrole'] = self._generate_cluster_roles(
            bundle_metadata, operator_name
        )
        
        # Generate ClusterRoleBindings
        manifests[f'{operator_name}-clusterrolebinding'] = self._generate_cluster_role_bindings(
            operator_name, namespace
        )
        
        # Generate Roles and RoleBindings based on permissions logic
        has_cluster_permissions = bool(bundle_metadata.get(OPMConstants.BUNDLE_CLUSTER_PERMISSIONS_KEY, []))
        has_namespace_permissions = bool(bundle_metadata.get(OPMConstants.BUNDLE_PERMISSIONS_KEY, []))
        
        # Only generate Roles if both clusterPermissions and permissions exist
        if has_cluster_permissions and has_namespace_permissions:
            # Both exist (e.g., ArgoCD) - generate grantor Role for namespace permissions
            namespace_rules = self._generate_namespace_rules(bundle_metadata)
            if namespace_rules:
                manifests[f'{operator_name}-role'] = self._generate_roles(
                    bundle_metadata, operator_name, namespace
                )
                
                # Generate RoleBindings
                manifests[f'{operator_name}-rolebinding'] = self._generate_role_bindings(
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
        
        return self._dump_yaml_with_flow_arrays(sa_manifest)
    
    def _generate_cluster_roles(self, bundle_metadata: Dict[str, Any], 
                              operator_name: str) -> str:
        """Generate ClusterRole YAML manifests with security header"""
        package_name = bundle_metadata.get('package_name', operator_name)
        
        # Generate security header comment for YAML manifests
        header = self._generate_security_header_comment(operator_name, package_name, 'yaml')
        
        manifests = []
        
        # Operator ClusterRole
        operator_rules = self._generate_operator_rules(bundle_metadata)
        operator_cr_name = f"{operator_name}-installer-clusterrole"
        
        operator_cr = ManifestTemplates.cluster_role_template(
            operator_cr_name, operator_name, operator_rules
        )
        manifests.append(operator_cr)
        
        # Grantor ClusterRole (CSV permissions + bundled cluster resources)
        grantor_rules = self._generate_grantor_rules(bundle_metadata)
        
        # Add bundled cluster-scoped resource permissions
        bundled_cluster_rules = self._generate_bundled_cluster_resource_rules(bundle_metadata)
        combined_grantor_rules = grantor_rules + bundled_cluster_rules
        
        # Apply DRY deduplication to combined grantor rules
        deduplicated_grantor_rules = self._process_and_deduplicate_rules(combined_grantor_rules)
        
        if deduplicated_grantor_rules:
            grantor_cr_name = f"{operator_name}-installer-rbac-clusterrole"
            
            grantor_cr = ManifestTemplates.cluster_role_template(
                grantor_cr_name, operator_name, deduplicated_grantor_rules
            )
            manifests.append(grantor_cr)
        
        # Convert to YAML with document separator using shared formatting
        yaml_parts = []
        for manifest in manifests:
            yaml_parts.append(self._dump_yaml_with_flow_arrays(manifest))
        
        yaml_content = '\n---\n'.join(yaml_parts)
        
        return f"{header}\n{yaml_content}"
    
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
        
        # Convert to YAML with document separator using shared formatting
        yaml_parts = []
        for manifest in manifests:
            yaml_parts.append(self._dump_yaml_with_flow_arrays(manifest))
        
        return '\n---\n'.join(yaml_parts)
    
    def _generate_roles(self, bundle_metadata: Dict[str, Any], 
                       operator_name: str, namespace: str) -> str:
        """Generate Role YAML manifests"""
        manifests = []
        
        # Generate Role with CSV namespace permissions + installer-specific permissions
        # Import CSV namespace permissions as-is
        csv_namespace_rules = self._generate_namespace_rules(bundle_metadata)
        
        # Get cluster rules to filter overlaps (use the deduplicated version)
        from ..core.constants import OPMConstants
        cluster_grantor_rules = []
        for perm in bundle_metadata.get(OPMConstants.BUNDLE_CLUSTER_PERMISSIONS_KEY, []):
            cluster_grantor_rules.extend(perm.get('rules', []))
        
        # Add bundled cluster rules and deduplicate (to match what was done for ClusterRole)
        bundled_cluster_rules = self._generate_bundled_cluster_resource_rules(bundle_metadata)
        combined_cluster_rules = cluster_grantor_rules + bundled_cluster_rules
        deduplicated_cluster_rules = self._process_and_deduplicate_rules(combined_cluster_rules)
        
        # Filter out any namespace rules that overlap with cluster rules
        unique_namespace_rules = self._filter_unique_role_rules(csv_namespace_rules, deduplicated_cluster_rules)
        
        # Add installer-specific permissions
        installer_rules = self._generate_installer_service_account_rules(bundle_metadata)
        
        # Combine unique namespace rules with installer rules
        combined_role_rules = unique_namespace_rules + installer_rules
        
        # Apply DRY deduplication to combined role rules
        if combined_role_rules:
            deduplicated_role_rules = self._process_and_deduplicate_rules(combined_role_rules)
            # Filter again against cluster rules to remove any remaining overlaps
            final_role_rules = self._filter_unique_role_rules(deduplicated_role_rules, deduplicated_cluster_rules)
            
            if final_role_rules:
                role_name = f"{operator_name}-installer-role"
                
                role_manifest = ManifestTemplates.role_template(
                    role_name, namespace, operator_name, final_role_rules
                )
                manifests.append(role_manifest)
        
        # Convert to YAML with document separator using shared formatting
        yaml_parts = []
        for manifest in manifests:
            yaml_parts.append(self._dump_yaml_with_flow_arrays(manifest))
        
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
        
        # Convert to YAML with document separator using shared formatting
        yaml_parts = []
        for manifest in manifests:
            yaml_parts.append(self._dump_yaml_with_flow_arrays(manifest))
        
        return '\n---\n'.join(yaml_parts)
