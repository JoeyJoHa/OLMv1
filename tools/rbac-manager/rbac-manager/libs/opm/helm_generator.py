"""
Helm Values Generator

Generates Helm values.yaml content from OPM bundle metadata.
"""

import yaml
from typing import Dict, List, Any, Optional
from .base_generator import BaseGenerator, PermissionStructure, HelmValueTemplates


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
        header = self._generate_header_comment(operator_name, package_name)
        
        # Convert to YAML with flow style for arrays
        yaml_content = self._dump_yaml_with_flow_arrays(values)
        
        return f"{header}\n{yaml_content}"
    
    def _generate_header_comment(self, operator_name: str, package_name: str) -> str:
        """Generate header comment for values file with security notice"""
        formatted_name = operator_name.replace('-', '-').title()
        return f"""# SECURITY NOTICE: Post-Installation RBAC Hardening Required
# =========================================================
# This values.yaml contains installer permissions with INTENTIONALLY BROAD SCOPE
# for successful initial deployment. The installer ClusterRole uses wildcard
# permissions (no resourceNames specified) which defaults to '*' behavior.
#
# CRITICAL: After successful OLMv1 installation, you MUST harden these permissions:
#
# Step 1: Inspect Created Resources
# ---------------------------------
# Run these commands to see what OLMv1 actually created:
#   kubectl get clusterroles,clusterrolebindings -l app.kubernetes.io/managed-by=olm
#   kubectl get clusterextensions
#
# Step 2: Update Installer Permissions  
# ------------------------------------
# In this values.yaml, find the installer ClusterRole rules and add resourceNames:
#
# For ClusterRole/ClusterRoleBinding management rules:
#   resourceNames: ['<packageName>.<hash1>', '<packageName>.<hash2>']
#   Example: ['{package_name}.a1b2c3d4', '{package_name}.e5f6g7h8']
#
# For ClusterExtension finalizer rules:
#   resourceNames: ['<your-chosen-clusterextension-name>']
#   Example: ['my-{package_name}'] or ['company-gitops']
#
# Step 3: Redeploy with Hardened Permissions
# ------------------------------------------
#   helm upgrade <release-name> <chart-path> -f <this-values.yaml>
#
# =========================================================
#
# {formatted_name} Operator specific values for the generic operator-olm-v1 Helm chart
# This file demonstrates how to configure the generic chart for the {package_name} operator
# Generated automatically from bundle metadata"""
    
    def _generate_permissions_structure(self, bundle_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Generate permissions structure for Helm values"""
        permissions = {
            'clusterRoles': [],
            'roles': []
        }
        
        # Check what types of permissions the operator has
        has_cluster_permissions = bool(bundle_metadata.get('cluster_permissions', []))
        has_namespace_permissions = bool(bundle_metadata.get('permissions', []))
        
        if has_cluster_permissions and has_namespace_permissions:
            # Operator has both cluster and namespace permissions
            # ClusterRole = operator (management) + grantor (cluster permissions)
            # Role = grantor (namespace permissions)
            
            # Generate operator ClusterRole (management permissions)
            operator_rules = self._generate_operator_rules(bundle_metadata)
            formatted_operator_rules = self._format_rules_for_helm(operator_rules)
            operator_cluster_role = PermissionStructure.create_cluster_role_structure(
                '', 'operator', formatted_operator_rules, True
            )
            permissions['clusterRoles'].append(operator_cluster_role)
            
            # Generate grantor ClusterRole (cluster permissions from CSV)
            cluster_grantor_rules = []
            for perm in bundle_metadata.get('cluster_permissions', []):
                cluster_grantor_rules.extend(perm.get('rules', []))
            
            if cluster_grantor_rules:
                grantor_cluster_role = PermissionStructure.create_cluster_role_structure(
                    '', 'grantor', self._format_rules_for_helm(cluster_grantor_rules), True
                )
                permissions['clusterRoles'].append(grantor_cluster_role)
            
            # Generate grantor Role (namespace permissions from CSV)
            namespace_rules = self._generate_namespace_rules(bundle_metadata)
            if namespace_rules:
                grantor_role = PermissionStructure.create_role_structure(
                    '', 'grantor', self._format_rules_for_helm(namespace_rules), True
                )
                permissions['roles'].append(grantor_role)
            else:
                # Add empty role if no namespace permissions
                empty_role = PermissionStructure.create_role_structure('', 'operator', [], False)
                permissions['roles'].append(empty_role)
                
        elif has_cluster_permissions:
            # Operator has only cluster permissions (traditional cluster-scoped operator)
            # ClusterRole = operator + grantor combined
            
            # Generate operator ClusterRole
            operator_rules = self._generate_operator_rules(bundle_metadata)
            formatted_operator_rules = self._format_rules_for_helm(operator_rules)
            operator_cluster_role = PermissionStructure.create_cluster_role_structure(
                '', 'operator', formatted_operator_rules, True
            )
            permissions['clusterRoles'].append(operator_cluster_role)
            
            # Generate grantor ClusterRole
            grantor_rules = self._generate_grantor_rules(bundle_metadata)
            if grantor_rules:
                grantor_cluster_role = PermissionStructure.create_cluster_role_structure(
                    '', 'grantor', self._format_rules_for_helm(grantor_rules), True
                )
                permissions['clusterRoles'].append(grantor_cluster_role)
            
            # Add empty operator Role (not used for cluster-only operators)
            operator_role = PermissionStructure.create_role_structure('', 'operator', [], False)
            permissions['roles'].append(operator_role)
            
        elif has_namespace_permissions:
            # Operator has only namespace permissions (namespace-scoped operator)
            # ClusterRole = operator (management only)
            # Role = grantor (namespace permissions)
            
            # Generate operator ClusterRole (management permissions only)
            operator_rules = self._generate_operator_rules(bundle_metadata)
            formatted_operator_rules = self._format_rules_for_helm(operator_rules)
            operator_cluster_role = PermissionStructure.create_cluster_role_structure(
                '', 'operator', formatted_operator_rules, True
            )
            permissions['clusterRoles'].append(operator_cluster_role)
            
            # Generate grantor Role (namespace permissions from CSV)
            namespace_rules = self._generate_namespace_rules(bundle_metadata)
            if namespace_rules:
                grantor_role = PermissionStructure.create_role_structure(
                    '', 'grantor', self._format_rules_for_helm(namespace_rules), True
                )
                permissions['roles'].append(grantor_role)
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
            
            # Resource names (if present)
            if 'resourceNames' in rule:
                formatted_rule['resourceNames'] = rule['resourceNames']
            
            formatted_rules.append(formatted_rule)
        
        return formatted_rules
    
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
