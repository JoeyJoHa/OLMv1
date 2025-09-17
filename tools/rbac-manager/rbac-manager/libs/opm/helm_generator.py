"""
Helm Values Generator

Generates Helm values.yaml content from OPM bundle metadata.
"""

import yaml
from typing import Dict, List, Any, Optional
from .base_generator import BaseGenerator, PermissionStructure, HelmValueTemplates
from ..core.constants import OPMConstants


class HelmValuesGenerator(BaseGenerator):
    """Generates Helm values.yaml content from bundle metadata"""
    
    def generate(self, bundle_metadata: Dict[str, Any], 
                operator_name: Optional[str] = None) -> str:
        """
        Generate Helm values.yaml content from bundle metadata
        
        Args:
            bundle_metadata: Bundle metadata from OPM
            operator_name: Optional custom operator name
            
        Returns:
            YAML string for values.yaml
        """
        # Extract basic info
        package_name = bundle_metadata.get('package_name', 'my-operator')
        version = bundle_metadata.get('version', 'latest')
        operator_name = operator_name or package_name
        
        # Create base values structure
        values = HelmValueTemplates.base_values_template(operator_name, version, package_name)
        
        # Generate permissions structure
        permissions = self._generate_permissions_structure(bundle_metadata)
        values['permissions'] = permissions
        
        # Generate header comment
        header = self._generate_security_header_comment(operator_name, package_name, 'helm')
        
        # Convert to YAML with flow style for arrays
        yaml_content = self._dump_yaml_with_flow_arrays(values)
        
        return f"{header}\n{yaml_content}"
    
    
    def _generate_permissions_structure(self, bundle_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Generate permissions structure for Helm values"""
        permissions = {
            'clusterRoles': [],
            'roles': []
        }
        
        # Check what types of permissions the operator has
        has_cluster_permissions = bool(bundle_metadata.get(OPMConstants.BUNDLE_CLUSTER_PERMISSIONS_KEY, []))
        has_namespace_permissions = bool(bundle_metadata.get(OPMConstants.BUNDLE_PERMISSIONS_KEY, []))
        
        if has_cluster_permissions and has_namespace_permissions:
            # Both clusterPermissions and permissions exist (e.g., ArgoCD)
            # ClusterRoles: operator (management) + grantor (clusterPermissions from CSV)
            # Roles: grantor only (permissions from CSV) - NO operator Role for namespace scope
            
            # Generate operator ClusterRole (management permissions)
            operator_rules = self._generate_operator_rules(bundle_metadata)
            formatted_operator_rules = self._format_rules_for_helm(operator_rules)
            operator_cluster_role = PermissionStructure.create_cluster_role_structure(
                '', 'operator', formatted_operator_rules, True
            )
            permissions['clusterRoles'].append(operator_cluster_role)
            
            # Generate grantor ClusterRole (ONLY clusterPermissions from CSV + bundled cluster resources)
            cluster_grantor_rules = []
            for perm in bundle_metadata.get(OPMConstants.BUNDLE_CLUSTER_PERMISSIONS_KEY, []):
                cluster_grantor_rules.extend(perm.get('rules', []))
            
            # Add bundled cluster-scoped resource permissions
            bundled_cluster_rules = self._generate_bundled_cluster_resource_rules(bundle_metadata)
            cluster_grantor_rules.extend(bundled_cluster_rules)
            
            # Apply DRY deduplication to cluster rules
            deduplicated_cluster_rules = self._process_and_deduplicate_rules(cluster_grantor_rules)
            
            if deduplicated_cluster_rules:
                grantor_cluster_role = PermissionStructure.create_cluster_role_structure(
                    '', 'grantor', self._format_rules_for_helm(deduplicated_cluster_rules), True
                )
                permissions['clusterRoles'].append(grantor_cluster_role)
            
            # Generate Role with CSV namespace permissions + installer-specific permissions
            # Import CSV namespace permissions as-is
            csv_namespace_rules = self._generate_namespace_rules(bundle_metadata)
            
            # Filter out any namespace rules that overlap with cluster rules
            # Use deduplicated cluster rules or empty list if no cluster rules
            cluster_rules_for_filtering = deduplicated_cluster_rules if deduplicated_cluster_rules else []
            unique_namespace_rules = self._filter_unique_role_rules(csv_namespace_rules, cluster_rules_for_filtering)
            
            # Add installer-specific permissions
            installer_rules = self._generate_installer_service_account_rules(bundle_metadata)
            
            # Combine unique namespace rules with installer rules
            combined_role_rules = unique_namespace_rules + installer_rules
            
            # Apply DRY deduplication to combined role rules
            if combined_role_rules:
                deduplicated_role_rules = self._process_and_deduplicate_rules(combined_role_rules)
                # Filter again against cluster rules to remove any remaining overlaps
                final_role_rules = self._filter_unique_role_rules(deduplicated_role_rules, cluster_rules_for_filtering)
                
                if final_role_rules:
                    installer_role = PermissionStructure.create_role_structure(
                        '', 'grantor', self._format_rules_for_helm(final_role_rules), True
                    )
                    permissions['roles'].append(installer_role)
                
        elif has_cluster_permissions:
            # Only clusterPermissions exist
            # ClusterRoles: operator (management) + grantor (clusterPermissions from CSV)
            # Roles: none (empty roles array)
            
            # Generate operator ClusterRole
            operator_rules = self._generate_operator_rules(bundle_metadata)
            formatted_operator_rules = self._format_rules_for_helm(operator_rules)
            operator_cluster_role = PermissionStructure.create_cluster_role_structure(
                '', 'operator', formatted_operator_rules, True
            )
            permissions['clusterRoles'].append(operator_cluster_role)
            
            # Generate grantor ClusterRole (clusterPermissions from CSV + bundled cluster resources)
            cluster_grantor_rules = []
            for perm in bundle_metadata.get(OPMConstants.BUNDLE_CLUSTER_PERMISSIONS_KEY, []):
                cluster_grantor_rules.extend(perm.get('rules', []))
            
            # Add bundled cluster-scoped resource permissions
            bundled_cluster_rules = self._generate_bundled_cluster_resource_rules(bundle_metadata)
            cluster_grantor_rules.extend(bundled_cluster_rules)
            
            # Apply DRY deduplication to cluster rules
            deduplicated_cluster_rules = self._process_and_deduplicate_rules(cluster_grantor_rules)
            
            if deduplicated_cluster_rules:
                grantor_cluster_role = PermissionStructure.create_cluster_role_structure(
                    '', 'grantor', self._format_rules_for_helm(deduplicated_cluster_rules), True
                )
                permissions['clusterRoles'].append(grantor_cluster_role)
            
            # No Roles needed for cluster-only operators - leave roles array empty
            
        elif has_namespace_permissions:
            # Only permissions exist (e.g., Quay operator - treat as ClusterRoles)
            # ClusterRoles: operator (management) + grantor (permissions treated as cluster-scoped)
            # Roles: none (empty roles array)
            
            # Generate operator ClusterRole (management permissions)
            operator_rules = self._generate_operator_rules(bundle_metadata)
            formatted_operator_rules = self._format_rules_for_helm(operator_rules)
            operator_cluster_role = PermissionStructure.create_cluster_role_structure(
                '', 'operator', formatted_operator_rules, True
            )
            permissions['clusterRoles'].append(operator_cluster_role)
            
            # Generate grantor ClusterRole (treat permissions as cluster-scoped + bundled cluster resources)
            namespace_rules = self._generate_namespace_rules(bundle_metadata)
            
            # Add bundled cluster-scoped resource permissions
            bundled_cluster_rules = self._generate_bundled_cluster_resource_rules(bundle_metadata)
            combined_rules = namespace_rules + bundled_cluster_rules
            
            if combined_rules:
                grantor_cluster_role = PermissionStructure.create_cluster_role_structure(
                    '', 'grantor', self._format_rules_for_helm(combined_rules), True
                )
                permissions['clusterRoles'].append(grantor_cluster_role)
            
            # No Roles needed - leave roles array empty
        else:
            # Operator has no permissions defined (unusual case)
            # Generate minimal operator ClusterRole
            operator_rules = self._generate_operator_rules(bundle_metadata)
            formatted_operator_rules = self._format_rules_for_helm(operator_rules)
            operator_cluster_role = PermissionStructure.create_cluster_role_structure(
                '', 'operator', formatted_operator_rules, True
            )
            permissions['clusterRoles'].append(operator_cluster_role)
            
            # Add empty operator Role
            operator_role = PermissionStructure.create_role_structure('', 'operator', [], False)
            permissions['roles'].append(operator_role)
        
        return permissions
    
    def _format_rules_for_helm(self, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Format RBAC rules for Helm values output
        
        Args:
            rules: List of RBAC rules
            
        Returns:
            Formatted rules for Helm values
        """
        formatted_rules = []
        
        for rule in rules:
            formatted_rule = {}
            
            # API groups
            if 'apiGroups' in rule:
                formatted_rule['apiGroups'] = rule['apiGroups']
            
            # Resources
            if 'resources' in rule:
                formatted_rule['resources'] = rule['resources']
            
            # Verbs
            if 'verbs' in rule:
                formatted_rule['verbs'] = rule['verbs']
            
            # Resource names (if present or needs hardening)
            if 'resourceNames' in rule:
                formatted_rule['resourceNames'] = rule['resourceNames']
            elif self._needs_resource_names_hardening(rule):
                # Add empty resourceNames array for rules that need hardening
                formatted_rule['resourceNames'] = []
            
            formatted_rules.append(formatted_rule)
        
        return formatted_rules
    
    def _needs_resource_names_hardening(self, rule: Dict[str, Any]) -> bool:
        """Check if a rule needs resourceNames hardening"""
        api_groups = rule.get('apiGroups', [])
        resources = rule.get('resources', [])
        verbs = rule.get('verbs', [])
        
        # RBAC management rules that need hardening
        if 'rbac.authorization.k8s.io' in api_groups:
            rbac_resources = ['clusterroles', 'clusterrolebindings']
            rbac_verbs = ['get', 'update', 'patch', 'delete']
            if (any(res in resources for res in rbac_resources) and 
                any(verb in verbs for verb in rbac_verbs)):
                return True
        
        # ClusterExtension finalizer rules that need hardening
        if 'olm.operatorframework.io' in api_groups:
            if any('clusterextensions/finalizers' in res for res in resources):
                return True
        
        return False
    
    def _dump_yaml_with_flow_arrays(self, data: Dict[str, Any]) -> str:
        """
        Dump YAML with flow style for RBAC arrays
        
        Args:
            data: Data to format as YAML
            
        Returns:
            YAML string with flow style arrays for RBAC rules
        """
        # Create a custom YAML dumper that uses flow style for specific arrays
        class FlowArrayDumper(yaml.SafeDumper):
            pass
        
        def represent_list(dumper, data):
            # Check if we're in a context where we want flow style
            # Only use flow style for arrays that contain only strings (not mixed types)
            if data and all(isinstance(item, str) for item in data):
                # Check if this looks like an RBAC array by examining patterns
                sample_str = ' '.join(data).lower()
                
                # Generic patterns that indicate RBAC arrays (not operator-specific)
                is_rbac_array = (
                    # Standard Kubernetes API groups
                    any(group in sample_str for group in [
                        'apiextensions.k8s.io', 'rbac.authorization.k8s.io', 'apps', 'batch',
                        'autoscaling', 'networking.k8s.io', 'policy', 'storage.k8s.io'
                    ]) or
                    # OLM-related API groups
                    'olm.operatorframework.io' in sample_str or
                    # Common monitoring/observability groups
                    'monitoring.coreos.com' in sample_str or
                    # OpenShift-specific groups
                    any(group in sample_str for group in [
                        'route.openshift.io', 'security.openshift.io', 'config.openshift.io'
                    ]) or
                    # Generic patterns for custom API groups (contains dots)
                    any('.' in item for item in data if isinstance(item, str)) or
                    # Standard Kubernetes resources
                    any(resource in sample_str for resource in [
                        'clusterroles', 'clusterrolebindings', 'customresourcedefinitions',
                        'deployments', 'pods', 'services', 'secrets', 'configmaps',
                        'serviceaccounts', 'namespaces', 'roles', 'rolebindings',
                        'persistentvolumeclaims', 'events', 'finalizers'
                    ]) or
                    # Standard Kubernetes verbs
                    any(verb in sample_str for verb in [
                        'create', 'get', 'list', 'watch', 'update', 'patch', 'delete', '*'
                    ]) or
                    # Short arrays (likely RBAC-related)
                    len(data) <= 3
                )
                
                if is_rbac_array:
                    return dumper.represent_sequence('tag:yaml.org,2002:seq', data, flow_style=True)
            
            # Default to block style for other arrays (including mixed types)
            return dumper.represent_sequence('tag:yaml.org,2002:seq', data, flow_style=False)
        
        FlowArrayDumper.add_representer(list, represent_list)
        
        # Generate YAML and add comments
        yaml_content = yaml.dump(data, Dumper=FlowArrayDumper, default_flow_style=False, sort_keys=False)
        
        # Post-process to add comments before customRules sections
        return self._add_rbac_comments(yaml_content)
    
    def _add_rbac_comments(self, yaml_content: str) -> str:
        """
        Add comments before customRules sections
        
        Args:
            yaml_content: YAML content string
            
        Returns:
            YAML content with added comments
        """
        lines = yaml_content.split('\n')
        processed_lines = []
        
        for i, line in enumerate(lines):
            # Check if this line starts a customRules section
            if line.strip() == 'customRules:':
                # Look back to find the type of this cluster role
                role_type = None
                for j in range(i-1, max(0, i-10), -1):
                    if 'type: operator' in lines[j]:
                        role_type = 'operator'
                        break
                    elif 'type: grantor' in lines[j]:
                        role_type = 'grantor'
                        break
                
                # Add appropriate comment before customRules
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
