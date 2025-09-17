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
                operator_name: Optional[str] = None, channel: Optional[str] = None) -> str:
        """
        Generate Helm values.yaml content from bundle metadata
        
        Args:
            bundle_metadata: Bundle metadata from OPM
            operator_name: Optional custom operator name
            channel: Optional channel name for the operator
            
        Returns:
            YAML string for values.yaml
        """
        # Extract basic info
        package_name = bundle_metadata.get('package_name', 'my-operator')
        version = bundle_metadata.get('version', 'latest')
        operator_name = operator_name or package_name
        
        # Create base values structure
        values = HelmValueTemplates.base_values_template(operator_name, version, package_name, channel)
        
        # Generate permissions structure
        permissions = self._generate_permissions_structure(bundle_metadata)
        values['permissions'] = permissions
        
        # Generate header comment
        header = self._generate_security_header_comment(operator_name, package_name, 'helm')
        
        # Convert to YAML with flow style for arrays
        yaml_content = self._dump_yaml_with_flow_arrays(values)
        
        return f"{header}\n{yaml_content}"
    
    
    def _generate_permissions_structure(self, bundle_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Generate permissions structure for Helm values using centralized component analysis"""
        permissions = {
            'clusterRoles': [],
            'roles': []
        }
        
        # Use centralized RBAC component analysis
        rbac_analysis = self.analyze_rbac_components(bundle_metadata)
        components_needed = rbac_analysis['components_needed']
        rules = rbac_analysis['rules']
        
        # Generate installer ClusterRole (always needed)
        if components_needed['installer_cluster_role']:
            formatted_rules = self._format_rules_for_helm(rules['installer_cluster_role'])
            installer_cluster_role = PermissionStructure.create_cluster_role_structure(
                '', 'operator', formatted_rules, True
            )
            permissions['clusterRoles'].append(installer_cluster_role)
        
        # Generate grantor ClusterRole (if needed)
        if components_needed['grantor_cluster_role'] and rules['grantor_cluster_role']:
            formatted_rules = self._format_rules_for_helm(rules['grantor_cluster_role'])
            grantor_cluster_role = PermissionStructure.create_cluster_role_structure(
                '', 'grantor', formatted_rules, True
            )
            permissions['clusterRoles'].append(grantor_cluster_role)
        
        # Generate namespace Role (if needed)
        if components_needed['namespace_role']:
            if rules['namespace_role']:  # Non-empty rules
                formatted_rules = self._format_rules_for_helm(rules['namespace_role'])
                namespace_role = PermissionStructure.create_role_structure(
                    '', 'grantor', formatted_rules, True
                )
                permissions['roles'].append(namespace_role)
            else:  # Empty rules (for no_permissions scenario)
                empty_role = PermissionStructure.create_role_structure('', 'operator', [], False)
                permissions['roles'].append(empty_role)
        
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
