"""
RBAC Converter Module.

This module contains the RBACConverter class that handles conversion of CSV RBAC data
into Kubernetes RBAC resources. It transforms ClusterServiceVersion RBAC specifications
into proper Kubernetes manifests ready for deployment.

Separated from rbac_manager_core.py to follow the Single Responsibility Principle.
"""

import logging
from typing import Dict, List, Optional, Any
import yaml

from .data_models import (
    HelmChartValues, HelmOperator, HelmServiceAccount, HelmPermissions,
    HelmRoleDefinition, HelmRBACRule
)


class RBACConverterError(Exception):
    """Custom exception for RBAC conversion errors."""
    pass


class RBACConverter:
    """
    Converts CSV RBAC data to Kubernetes RBAC resources.
    
    This class transforms the RBAC specifications found in ClusterServiceVersion
    manifests into proper Kubernetes RBAC resources that can be deployed to
    grant necessary permissions to operator service accounts.
    
    Features:
    - Conversion of CSV permissions to Kubernetes Roles/ClusterRoles
    - Generation of appropriate RoleBindings/ClusterRoleBindings
    - ServiceAccount creation with proper metadata
    - Configurable namespace targeting for generated resources
    - Resource naming consistency and collision avoidance
    """
    
    def __init__(self):
        """Initialize the RBAC converter."""
        self.logger = logging.getLogger(__name__)
        
        # Initialize the rule builder for declarative RBAC generation
        self.rule_builder = RBACRuleBuilder(self.logger)
    
    def convert_csv_rbac_to_k8s_resources(self, 
                                        rbac_data: Dict[str, Any], 
                                        package_name: str,
                                        namespace_template: str,
                                        expand_wildcards: bool = False) -> Dict[str, List[Dict]]:
        """
        Convert CSV RBAC data to Kubernetes RBAC resources.
        
        This is the main conversion function that transforms CSV RBAC specifications
        into complete Kubernetes RBAC manifests ready for deployment.
        
        Args:
            rbac_data: RBAC data extracted from CSV (from BundleProcessor.extract_rbac_from_csv())
            package_name: Package name for resource naming consistency
            namespace_template: Target namespace for generated resources
            
        Returns:
            Dictionary with lists of Kubernetes resources:
            {
                'serviceAccounts': [ServiceAccount manifests],
                'clusterRoles': [ClusterRole manifests],
                'roles': [Role manifests],
                'clusterRoleBindings': [ClusterRoleBinding manifests],
                'roleBindings': [RoleBinding manifests]
            }
            
        Raises:
            RBACConverterError: If conversion fails due to invalid input data
        """
        if not isinstance(rbac_data, dict):
            raise RBACConverterError("RBAC data must be a dictionary")
        
        self.logger.info(f"Converting CSV RBAC to Kubernetes resources for package '{package_name}'")
        
        # Initialize resource collections
        resources = {
            'serviceAccounts': [],
            'clusterRoles': [],
            'roles': [],
            'clusterRoleBindings': [],
            'roleBindings': []
        }
        
        # Generate consistent service account name following Helm chart pattern
        # Use package name + "-installer" for consistency across all RBAC resources
        service_account_name = f"{package_name}-installer"
        
        # Create ServiceAccount
        service_account = self._create_service_account(
            service_account_name, package_name, namespace_template
        )
        resources['serviceAccounts'].append(service_account)
        
        # Smart RBAC processing logic:
        # 1. If clusterPermissions exists → always create ClusterRole
        # 2. If permissions exists AND clusterPermissions exists → create Role (namespace-scoped)
        # 3. If ONLY permissions exists (no clusterPermissions) → treat as cluster-scoped (ClusterRole)
        
        cluster_permissions = rbac_data.get('clusterPermissions', [])
        namespace_permissions = rbac_data.get('permissions', [])
        
        has_cluster_permissions = bool(cluster_permissions)
        has_namespace_permissions = bool(namespace_permissions)
        
        # Process cluster permissions (always cluster-scoped)
        if has_cluster_permissions:
            cluster_role, cluster_role_binding = self._create_cluster_rbac_resources(
                cluster_permissions, package_name, service_account_name, namespace_template, expand_wildcards
            )
            if cluster_role:
                resources['clusterRoles'].append(cluster_role)
            if cluster_role_binding:
                resources['clusterRoleBindings'].append(cluster_role_binding)
        
        # Process permissions based on context
        if has_namespace_permissions:
            if has_cluster_permissions:
                # Case 2: Both exist → permissions are namespace-scoped
                self.logger.debug("Both clusterPermissions and permissions found - treating permissions as namespace-scoped")
                role, role_binding = self._create_namespace_rbac_resources(
                    namespace_permissions, package_name, service_account_name, namespace_template, expand_wildcards
                )
                if role:
                    resources['roles'].append(role)
                if role_binding:
                    resources['roleBindings'].append(role_binding)
            else:
                # Case 3: Only permissions exist → treat as cluster-scoped (fallback logic)
                self.logger.info("Only 'permissions' found (no 'clusterPermissions') - treating permissions as cluster-scoped")
                cluster_role, cluster_role_binding = self._create_cluster_rbac_resources(
                    namespace_permissions, package_name, service_account_name, namespace_template, expand_wildcards
                )
                if cluster_role:
                    resources['clusterRoles'].append(cluster_role)
                if cluster_role_binding:
                    resources['clusterRoleBindings'].append(cluster_role_binding)
        
        # Log conversion results
        total_resources = sum(len(resource_list) for resource_list in resources.values())
        self.logger.info(f"Successfully converted RBAC: {total_resources} Kubernetes resource(s) created")
        
        resource_summary = {k: len(v) for k, v in resources.items() if v}
        self.logger.debug(f"Resource breakdown: {resource_summary}")
        
        return resources
    
    def convert_rbac_to_helm_values(self, rbac_data: Dict[str, Any], package_name: str, csv_data: Dict[str, Any] = None) -> 'HelmChartValues':
        """
        Convert RBAC data to a HelmChartValues data class structure.
        
        This simplified version focuses on creating the data structure cleanly,
        separating the logic of building the structure from YAML serialization.
        
        Args:
            rbac_data: RBAC data extracted from CSV (from BundleProcessor.extract_rbac_from_csv())
            package_name: Package name for consistent naming
            csv_data: Optional CSV data for additional CRD extraction
            
        Returns:
            HelmChartValues object ready for YAML serialization
        """
        self.logger.info(f"Converting RBAC to Helm values structure for package '{package_name}'")
        
        # Handle both dataclass and dict for RBAC data
        from dataclasses import is_dataclass, asdict
        if is_dataclass(rbac_data):
            rbac_dict = asdict(rbac_data)
        else:
            rbac_dict = rbac_data if isinstance(rbac_data, dict) else {}
        
        # 1. Create the top-level operator specification
        operator_spec = HelmOperator(
            name=package_name.replace('.', '-'),
            packageName=package_name,
            appVersion=self._extract_version_from_csv(csv_data) if csv_data else 'latest',
            channel='stable'
        )
        
        # 2. Create the Helm values structure with default service account
        helm_values = HelmChartValues(
            operator=operator_spec,
            serviceAccount=HelmServiceAccount(),  # Uses defaults: create=True, name="", bind=True
            permissions=HelmPermissions()
        )
        
        # 3. Build installer permissions using the rule builder
        context = self._build_installer_context(package_name, csv_data)
        rule_builder = RBACRuleBuilder(self.logger)
        installer_cluster_rules = rule_builder.build_installer_cluster_rules(context)
        installer_namespace_rules = rule_builder.build_installer_namespace_rules(context)
        
        # 4. Add installer cluster role (always present)
        if installer_cluster_rules:
            helm_values.permissions.clusterRoles.append(
                HelmRoleDefinition(
                    type="operator",
                    customRules=self._convert_dict_rules_to_helm_rules(
                        self._process_installer_rules_for_helm(installer_cluster_rules)
                    )
                )
            )
        
        # 5. Add operator ("grantor") permissions if they exist
        grantor_rules = self._extract_grantor_rules(rbac_dict)
        if grantor_rules:
            helm_values.permissions.clusterRoles.append(
                HelmRoleDefinition(
                    type="grantor",
                    customRules=self._convert_dict_rules_to_helm_rules(grantor_rules)
                )
            )
        
        # 6. Add namespace-scoped roles if needed
        self._add_namespace_roles(helm_values, rbac_dict, installer_namespace_rules)
        
        return helm_values
    
    def _build_installer_context(self, package_name: str, csv_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Build context for installer rule generation."""
        return {
            'package_name': package_name,
            'csv_data': csv_data
        }
    
    def _extract_grantor_rules(self, rbac_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract and convert grantor (operator) rules from RBAC data."""
        grantor_rules = []
        
        # Get operator permissions
        operator_permissions = rbac_dict.get('permissions', [])
        cluster_permissions = rbac_dict.get('clusterPermissions', [])
        
        if cluster_permissions:
            grantor_rules.extend(self._convert_rules_to_helm_format(cluster_permissions))
        elif operator_permissions:
            # If only permissions exist, treat as cluster-scoped
            grantor_rules.extend(self._convert_rules_to_helm_format(operator_permissions))
        
        return grantor_rules
    
    def _add_namespace_roles(self, helm_values: 'HelmChartValues', rbac_dict: Dict[str, Any], installer_namespace_rules: List[Dict[str, Any]]) -> None:
        """Add namespace-scoped roles to helm values if needed."""
        namespace_permissions = rbac_dict.get('namespace_permissions', [])
        
        if namespace_permissions or installer_namespace_rules:
            # Initialize roles list if not already present
            if helm_values.permissions.roles is None:
                helm_values.permissions.roles = []
            
            # Add installer namespace role
            if installer_namespace_rules:
                helm_values.permissions.roles.append(
                    HelmRoleDefinition(
                        type="operator",
                        customRules=self._convert_dict_rules_to_helm_rules(
                            self._process_installer_rules_for_helm(installer_namespace_rules)
                        )
                    )
                )
            
            # Add namespace grantor role
            if namespace_permissions:
                helm_values.permissions.roles.append(
                    HelmRoleDefinition(
                        type="grantor",
                        customRules=self._convert_dict_rules_to_helm_rules(
                            self._convert_rules_to_helm_format(namespace_permissions)
                        )
                    )
                )
    
    def _convert_dict_rules_to_helm_rules(self, dict_rules: List[Dict[str, Any]]) -> List[HelmRBACRule]:
        """
        Convert dictionary RBAC rules to HelmRBACRule dataclass instances.
        
        Args:
            dict_rules: List of RBAC rule dictionaries
            
        Returns:
            List of HelmRBACRule dataclass instances
        """
        helm_rules = []
        
        for rule_dict in dict_rules:
            if not isinstance(rule_dict, dict):
                continue
                
            helm_rule = HelmRBACRule(
                apiGroups=rule_dict.get('apiGroups', []),
                resources=rule_dict.get('resources', []),
                verbs=rule_dict.get('verbs', []),
                resourceNames=rule_dict.get('resourceNames'),
                nonResourceURLs=rule_dict.get('nonResourceURLs')
            )
            helm_rules.append(helm_rule)
        
        return helm_rules
    
    def _generate_security_notice_header(self) -> str:
        """Generate security notice header for Helm values.yaml files."""
        return """# SECURITY NOTICE: Post-Installation RBAC Hardening Required
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
#   Example: ['quay-operator.a1b2c3d4', 'quay-operator.e5f6g7h8']
#
# For ClusterExtension finalizer rules:
#   resourceNames: ['<your-chosen-clusterextension-name>']
#   Example: ['my-quay-operator'] or ['company-gitops']
#
# Step 3: Redeploy with Hardened Permissions
# ------------------------------------------
#   helm upgrade <release-name> <chart-path> -f <this-values.yaml>
#
# ========================================================="""

    def _extract_version_from_csv(self, csv_data: Dict[str, Any]) -> str:
        """Extract version from CSV data."""
        if csv_data and 'spec' in csv_data:
            return csv_data['spec'].get('version', 'latest')
        return 'latest'
    
    def _convert_rules_to_helm_format(self, permissions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Convert CSV permission rules to Helm chart format with human-readable structure.
        
        Args:
            permissions: List of permission rules from CSV
            
        Returns:
            List of rules in Helm chart format (clean, no duplicates, split verbs)
        """
        if not permissions:
            return []
        
        all_rules = []
        seen_rules = set()
        
        for rule in permissions:
            if 'rules' in rule:
                # Handle nested rules structure
                for nested_rule in rule['rules']:
                    # Process each unique combination of apiGroups + resources
                    api_groups = nested_rule.get('apiGroups', [''])
                    resources = nested_rule.get('resources', [])
                    verbs = nested_rule.get('verbs', [])
                    
                    # Create rule signature for deduplication
                    rule_sig = (tuple(sorted(api_groups)), tuple(sorted(resources)))
                    
                    if rule_sig not in seen_rules:
                        seen_rules.add(rule_sig)
                        
                        # Split verbs into read and write operations
                        read_verbs = [v for v in verbs if v in ['get', 'list', 'watch']]
                        write_verbs = [v for v in verbs if v in ['create', 'update', 'patch', 'delete']]
                        other_verbs = [v for v in verbs if v not in ['get', 'list', 'watch', 'create', 'update', 'patch', 'delete']]
                        
                        # Create separate rules for different verb types
                        for verb_group in [read_verbs, write_verbs, other_verbs]:
                            if verb_group:
                                helm_rule = {
                                    'apiGroups': list(api_groups),
                                    'resources': list(resources),
                                    'verbs': verb_group
                                }
                                
                                # Add resourceNames if present
                                if nested_rule.get('resourceNames'):
                                    helm_rule['resourceNames'] = list(nested_rule['resourceNames'])
                                
                                # Add nonResourceURLs if present
                                if nested_rule.get('nonResourceURLs'):
                                    helm_rule['nonResourceURLs'] = list(nested_rule['nonResourceURLs'])
                                
                                all_rules.append(helm_rule)
        
        return all_rules

    def _create_clean_yaml_dumper(self):
        """
        Create a YAML dumper that doesn't use anchors/references and formats RBAC arrays inline.
        
        This prevents &id### and *id### references that cause issues in Helm values files.
        Formats apiGroups, resources, and verbs as inline arrays like values-quay-operator.yaml.
        """
        class CleanYAMLDumper(yaml.SafeDumper):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self._inside_rbac_rule = False
                
            def ignore_aliases(self, data):
                return True  # Never use aliases/anchors
                
            def represent_dict(self, data):
                # Check if this is an RBAC rule dictionary
                if isinstance(data, dict) and ('apiGroups' in data or 'resources' in data or 'verbs' in data):
                    self._inside_rbac_rule = True
                    result = super().represent_dict(data)
                    self._inside_rbac_rule = False
                    return result
                return super().represent_dict(data)
                
            def represent_list(self, data):
                # Use flow style for RBAC rule lists (apiGroups, resources, verbs)
                # Check if we're in the context of writing out dict values and the current key context
                if hasattr(self, '_inside_rbac_rule') and self._inside_rbac_rule:
                    return self.represent_sequence('tag:yaml.org,2002:seq', data, flow_style=True)
                return self.represent_sequence('tag:yaml.org,2002:seq', data, flow_style=False)
        
        # Override the default representers
        CleanYAMLDumper.add_representer(dict, CleanYAMLDumper.represent_dict)
        CleanYAMLDumper.add_representer(list, CleanYAMLDumper.represent_list)
        
        return CleanYAMLDumper
    
    def _add_security_comments_to_yaml(self, yaml_output: str, rbac_data: Dict[str, Any]) -> str:
        """
        Add security hardening comments to the generated YAML.
        
        This method adds human-readable comments explaining post-installation security steps
        that administrators should take to properly scope RBAC permissions.
        
        Args:
            yaml_output: Generated YAML string
            rbac_data: RBAC data used for context
            
        Returns:
            YAML string with added security comments
        """
        # Add header with comprehensive security guidance
        security_header = """# SECURITY NOTICE: Post-Installation RBAC Hardening Required
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
#   Example: ['quay-operator.a1b2c3d4', 'quay-operator.e5f6g7h8']
#
# For ClusterExtension finalizer rules:
#   resourceNames: ['<your-chosen-clusterextension-name>']
#   Example: ['my-quay-operator'] or ['company-gitops']
#
# Step 3: Redeploy with Hardened Permissions
# ------------------------------------------
#   helm upgrade <release-name> <chart-path> -f <this-values.yaml>
#
# RATIONALE: Initial deployment needs broad permissions because:
# - OLMv1 generates unpredictable resource names with hash suffixes
# - ClusterExtension names are chosen by administrators during deployment
# - Prediction of exact names ahead of time is impossible
# =========================================================

"""
        
        return security_header + yaml_output
    
    def _extract_operator_metadata(self, csv_data: Dict[str, Any], package_name: str) -> Dict[str, str]:
        """
        Extract operator metadata from CSV data.
        
        Args:
            csv_data: ClusterServiceVersion data
            package_name: Package name as fallback
            
        Returns:
            Dictionary with operator metadata
        """
        if not csv_data:
            return {
                'name': package_name.split('.')[0],  # Remove version if present
                'version': 'latest',
                'package_name': package_name.split('.')[0]
            }
        
        metadata = csv_data.get('metadata', {})
        spec = csv_data.get('spec', {})
        
        name = metadata.get('name', package_name)
        # Extract base name without version
        base_name = name.split('.v')[0] if '.v' in name else name.split('.')[0]
        
        # Extract version from name or spec
        version = 'latest'
        if '.v' in name:
            version = name.split('.v')[-1]
        elif 'version' in spec:
            version = spec['version']
        
        return {
            'name': base_name,
            'version': version,
            'package_name': base_name
        }
    
    def _process_installer_rules_for_helm(self, installer_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process installer rules for Helm values generation.
        
        This method handles security notes and documentation for post-installation hardening.
        Removes internal metadata fields and prepares rules for YAML generation.
        
        Args:
            installer_rules: List of installer RBAC rules with potential security notes
            
        Returns:
            List of clean RBAC rules suitable for Helm values
        """
        processed_rules = []
        
        for rule in installer_rules:
            # Create a clean copy of the rule
            clean_rule = {}
            
            # Copy standard RBAC fields
            for field in ['apiGroups', 'resources', 'verbs', 'resourceNames', 'nonResourceURLs']:
                if field in rule:
                    clean_rule[field] = list(rule[field]) if isinstance(rule[field], list) else rule[field]
            
            # Skip internal security note fields - they're for documentation only
            # Comments will be handled by the security header at the top of the file
            
            processed_rules.append(clean_rule)
        
        return processed_rules
    
    def _split_wildcard_verbs(self, verbs: List[str]) -> List[List[str]]:
        """
        Split wildcard verbs into explicit verb groups.
        
        Per user requirements:
        - Replace * wildcard with all explicit verbs
        - Separate create/list/watch from get/update/patch/delete
        
        Args:
            verbs: List of verbs that may contain wildcards
            
        Returns:
            List of verb groups to create separate rules for
        """
        # Define all possible Kubernetes RBAC verbs
        all_verbs = ['create', 'list', 'watch', 'get', 'update', 'patch', 'delete']
        create_ops = ['create', 'list', 'watch']
        manage_ops = ['get', 'update', 'patch', 'delete']
        
        # If wildcard, split into two groups
        if '*' in verbs:
            return [create_ops, manage_ops]
        
        # If no wildcard but contains both types, split appropriately
        has_create_ops = any(v in verbs for v in create_ops)
        has_manage_ops = any(v in verbs for v in manage_ops)
        
        if has_create_ops and has_manage_ops:
            # Split into separate rules for better readability
            create_verbs = [v for v in verbs if v in create_ops]
            manage_verbs = [v for v in verbs if v in manage_ops]
            return [create_verbs, manage_verbs] if create_verbs and manage_verbs else [verbs]
        
        # Single group if only one type or mixed
        return [verbs]

    def _get_installer_permissions(self, package_name: str, operator_metadata: Dict[str, str], 
                                  crd_names: List[str] = None, bundle_data: Dict[str, Any] = None,
                                  csv_data: Dict[str, Any] = None,
                                  cluster_permissions: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Generate installer service account permissions using declarative templates.
        
        This method now uses the RBACRuleBuilder with declarative templates instead of 
        hardcoded rule generation logic, making it much more maintainable and readable.
        
        Based on: https://raw.githubusercontent.com/openshift/operator-framework-operator-controller/refs/heads/main/docs/howto/derive-service-account.md
        
        Args:
            package_name: Package name for scoping resource names
            operator_metadata: Operator metadata for scoping
            crd_names: List of CRD names from bundle
            bundle_data: Raw bundle data for extracting cluster-scoped resources
            csv_data: CSV data for extracting deployment/service account names
            cluster_permissions: Cluster permissions from CSV (not used for installer)
            
        Returns:
            List of RBAC rules following OpenShift OLMv1 guidelines exactly
        """
        # Build context with all the data needed for rule generation
        context = {
            'package_name': package_name,
            'operator_metadata': operator_metadata,
            'crd_names': crd_names or [],
            'bundled_cluster_roles': self._extract_bundled_cluster_roles(bundle_data),
            'deployment_names': self._extract_deployment_names(csv_data) if csv_data else [],
            'service_names': self._extract_service_names(bundle_data) if bundle_data else [],
            'configmap_names': self._extract_configmap_names(bundle_data) if bundle_data else []
        }
        
        # Use the rule builder to generate rules from declarative templates
        return self.rule_builder.build_installer_cluster_rules(context)
    
    def _get_installer_namespace_permissions(self, package_name: str, operator_metadata: Dict[str, str], 
                                            csv_data: Dict[str, Any] = None, bundle_data: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Generate installer namespace permissions using declarative templates.
        
        This method now uses the RBACRuleBuilder with declarative templates instead of 
        hardcoded rule generation logic, making it much more maintainable and readable.
        
        Based on: https://raw.githubusercontent.com/openshift/operator-framework-operator-controller/refs/heads/main/docs/howto/derive-service-account.md
        
        Args:
            package_name: Package name for scoping resource names  
            operator_metadata: Operator metadata for scoping
            csv_data: CSV data for extracting deployment and service account names
            bundle_data: Raw bundle data for extracting specific resource names
            
        Returns:
            List of namespace-scoped RBAC rules following OpenShift OLMv1 guidelines exactly
        """
        # Build context with all the data needed for rule generation
        context = {
            'package_name': package_name,
            'operator_metadata': operator_metadata,
            'deployment_names': self._extract_deployment_names(csv_data) if csv_data else [],
            'service_account_names': self._extract_service_account_names(csv_data) if csv_data else [],
            'service_names': self._extract_service_names(bundle_data) if bundle_data else [],
            'configmap_names': self._extract_configmap_names(bundle_data) if bundle_data else []
        }
        
        # Use the rule builder to generate rules from declarative templates
        return self.rule_builder.build_installer_namespace_rules(context)
    
    def _extract_resource_names_from_manifests(self, manifests: List[Dict[str, Any]], kind: str, api_version_prefix: str) -> List[str]:
        """
        Generic helper to extract resource names from a list of manifests.
        
        This method eliminates code duplication across multiple resource extraction methods
        by providing a common pattern for filtering manifests by kind and apiVersion.
        
        Args:
            manifests: List of Kubernetes manifest dictionaries
            kind: Kubernetes resource kind (e.g., 'Service', 'ConfigMap', 'ClusterRole')
            api_version_prefix: API version prefix to match (e.g., 'v1', 'rbac.authorization.k8s.io/', 'apiextensions.k8s.io/')
            
        Returns:
            List of resource names extracted from matching manifests
        """
        if not manifests:
            return []
        
        names = []
        for manifest in manifests:
            if (manifest.get('kind') == kind and 
                manifest.get('apiVersion', '').startswith(api_version_prefix)):
                name = manifest.get('metadata', {}).get('name')
                if name:
                    names.append(name)
        return names
    
    def _extract_deployment_names(self, csv_data: Dict[str, Any]) -> List[str]:
        """Extract deployment names from CSV data."""
        if not csv_data:
            return []
        
        deployments = csv_data.get('spec', {}).get('install', {}).get('deployments', [])
        return [deployment.get('name') for deployment in deployments if deployment.get('name')]
    
    def _extract_service_account_names(self, csv_data: Dict[str, Any]) -> List[str]:
        """Extract service account names from CSV deployment specs."""
        if not csv_data:
            return []
        
        sa_names = []
        deployments = csv_data.get('spec', {}).get('install', {}).get('deployments', [])
        for deployment in deployments:
            spec = deployment.get('spec', {})
            template = spec.get('template', {})
            pod_spec = template.get('spec', {})
            service_account = pod_spec.get('serviceAccount') or pod_spec.get('serviceAccountName')
            if service_account:
                sa_names.append(service_account)
        return sa_names
    
    def _extract_service_names(self, bundle_data: Dict[str, Any]) -> List[str]:
        """Extract service names from bundle manifests."""
        return self._extract_resource_names_from_manifests(
            bundle_data.get('manifests', []) if bundle_data else [], 
            'Service', 
            'v1'
        )
    
    def _extract_configmap_names(self, bundle_data: Dict[str, Any]) -> List[str]:
        """Extract configmap names from bundle manifests."""
        return self._extract_resource_names_from_manifests(
            bundle_data.get('manifests', []) if bundle_data else [], 
            'ConfigMap', 
            'v1'
        )
    
    def _extract_crd_names(self, bundle_data: Dict[str, Any]) -> List[str]:
        """Extract CRD names from bundle manifests."""
        if not bundle_data:
            return []
        
        manifests = bundle_data.get('manifests', [])
        return self._extract_crd_names_from_manifests(manifests)
    
    def _extract_crd_names_from_manifests(self, manifests: List[Dict[str, Any]]) -> List[str]:
        """Extract CRD names from a list of manifests."""
        return self._extract_resource_names_from_manifests(
            manifests, 
            'CustomResourceDefinition', 
            'apiextensions.k8s.io/'
        )
    
    def _extract_crd_names_from_csv_spec(self, csv_data: Dict[str, Any]) -> List[str]:
        """
        Extract CRD names from CSV spec.customresourcedefinitions.owned.
        
        This is a fallback when bundle manifests are not available in context.
        """
        crd_names = []
        if not csv_data:
            return crd_names
            
        spec = csv_data.get('spec', {})
        crd_definitions = spec.get('customresourcedefinitions', {})
        owned_crds = crd_definitions.get('owned', [])
        
        for crd in owned_crds:
            name = crd.get('name')
            if name:
                crd_names.append(name)
                
        return crd_names
    
    def _extract_bundled_cluster_roles(self, bundle_data: Dict[str, Any]) -> List[str]:
        """
        Extract bundled ClusterRole names from bundle manifests (Step 4 from guidelines).
        
        These are ClusterRoles included in the bundle (like metrics-reader roles)
        that the installer needs permission to manage.
        """
        return self._extract_resource_names_from_manifests(
            bundle_data.get('manifests', []) if bundle_data else [], 
            'ClusterRole', 
            'rbac.authorization.k8s.io/v1'
        )
    
    def _create_k8s_resource(self, kind: str, api_version: str, name: str, package_name: str, namespace: Optional[str] = None) -> Dict[str, Any]:
        """
        Create the basic structure for a Kubernetes resource.
        
        This factory method eliminates boilerplate code across resource creation methods
        by providing a common pattern for defining apiVersion, kind, and metadata.
        
        Args:
            kind: Kubernetes resource kind (e.g., 'ServiceAccount', 'ClusterRole', 'Role')
            api_version: Kubernetes API version (e.g., 'v1', 'rbac.authorization.k8s.io/v1')
            name: Resource name
            package_name: Package name for consistent labeling
            namespace: Optional namespace for namespaced resources
            
        Returns:
            Basic Kubernetes resource structure with consistent metadata and labels
        """
        resource = {
            'apiVersion': api_version,
            'kind': kind,
                'metadata': {
                'name': name,
                'labels': {
                    'app.kubernetes.io/name': package_name,
                    'app.kubernetes.io/component': 'rbac',
                    'app.kubernetes.io/created-by': 'rbac-manager'
                }
            }
        }
        if namespace:
            resource['metadata']['namespace'] = namespace
        return resource
    
    def _create_service_account(self, 
                              service_account_name: str,
                              package_name: str, 
                              namespace_template: str) -> Dict[str, Any]:
        """
        Create a ServiceAccount manifest.
        
        Args:
            service_account_name: Name for the service account
            package_name: Package name for labels and annotations
            namespace_template: Namespace template string
            
        Returns:
            ServiceAccount manifest dictionary
        """
        service_account = self._create_k8s_resource(
            'ServiceAccount', 
            'v1', 
            service_account_name, 
            package_name, 
            namespace=namespace_template
        )
        
        self.logger.debug(f"Created ServiceAccount: {service_account_name}")
        return service_account
    
    def _create_rbac_pair(self,
                         permissions: List[Dict[str, Any]],
                         package_name: str,
                         service_account_name: str,
                         namespace_template: str,
                         is_cluster_scoped: bool = True,
                         expand_wildcards: bool = False) -> tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """
        Unified method to create Role/ClusterRole and RoleBinding/ClusterRoleBinding pairs.
        
        This method eliminates code duplication by handling both cluster-scoped and 
        namespace-scoped RBAC resource creation with a single implementation.
        
        Args:
            permissions: List of permission sets from CSV (cluster or namespace)
            package_name: Package name for resource naming
            service_account_name: Service account to bind to
            namespace_template: Namespace template string
            is_cluster_scoped: If True, creates ClusterRole/ClusterRoleBinding; 
                             if False, creates Role/RoleBinding
            expand_wildcards: If True, expands wildcard verbs for least-privileges mode;
                            if False, preserves wildcards as specified in operator bundle
            
        Returns:
            Tuple of (Role/ClusterRole, RoleBinding/ClusterRoleBinding) or (None, None) if no valid rules
        """
        # Extract and combine all rules from permission sets
        all_rules = []
        permission_type = "cluster" if is_cluster_scoped else "namespace"
        
        for perm_set in permissions:
            rules = perm_set.get('rules', [])
            if isinstance(rules, list):
                # Format, validate and clean up rules
                for rule in rules:
                    if self._validate_rbac_rule(rule):
                        formatted_rule = self._format_rbac_rule(rule, expand_wildcards)
                        all_rules.append(formatted_rule)
            else:
                self.logger.warning(f"Invalid rules format in {permission_type} permission set: {type(rules)}")
        
        if not all_rules:
            self.logger.warning(f"No valid {permission_type} rules found")
            return None, None
        
        # Determine resource kinds and naming based on scope
        if is_cluster_scoped:
            role_kind = 'ClusterRole'
            binding_kind = 'ClusterRoleBinding'
            role_name = f"{package_name}-installer-cr"
            binding_name = f"{package_name}-installer-crb"
        else:
            role_kind = 'Role'
            binding_kind = 'RoleBinding'
            role_name = f"{package_name}-installer-role"
            binding_name = f"{package_name}-installer-rb"
        
        # Create Role/ClusterRole using factory
        if is_cluster_scoped:
            role = self._create_k8s_resource(
                role_kind, 
                'rbac.authorization.k8s.io/v1', 
                role_name, 
                package_name
            )
        else:
            role = self._create_k8s_resource(
                role_kind, 
                'rbac.authorization.k8s.io/v1', 
                role_name, 
                package_name, 
                namespace=namespace_template
            )
        role['rules'] = all_rules
        
        # Create RoleBinding/ClusterRoleBinding using factory
        if is_cluster_scoped:
            binding = self._create_k8s_resource(
                binding_kind, 
                'rbac.authorization.k8s.io/v1', 
                binding_name, 
                package_name
            )
        else:
            binding = self._create_k8s_resource(
                binding_kind, 
                'rbac.authorization.k8s.io/v1', 
                binding_name, 
                package_name, 
                namespace=namespace_template
            )
        
        # Configure binding roleRef and subjects
        binding.update({
            'roleRef': {
                'apiGroup': 'rbac.authorization.k8s.io',
                'kind': role_kind,
                'name': role_name
            },
            'subjects': [{
                'kind': 'ServiceAccount',
                'name': service_account_name,
                'namespace': namespace_template
            }]
        })
        
        self.logger.debug(f"Created {role_kind} with {len(all_rules)} rule(s): {role_name}")
        return role, binding
    
    def _create_cluster_rbac_resources(self,
                                     cluster_permissions: List[Dict[str, Any]],
                                     package_name: str,
                                     service_account_name: str,
                                     namespace_template: str,
                                     expand_wildcards: bool = False) -> tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """
        Create ClusterRole and ClusterRoleBinding from cluster permissions.
        
        This method is now a simple wrapper around the unified _create_rbac_pair method.
        
        Args:
            cluster_permissions: List of cluster permission sets from CSV
            package_name: Package name for resource naming
            service_account_name: Service account to bind to
            namespace_template: Namespace template string
            expand_wildcards: If True, expands wildcard verbs for least-privileges mode
            
        Returns:
            Tuple of (ClusterRole, ClusterRoleBinding) or (None, None) if no valid rules
        """
        return self._create_rbac_pair(
            permissions=cluster_permissions,
            package_name=package_name,
            service_account_name=service_account_name,
            namespace_template=namespace_template,
            is_cluster_scoped=True,
            expand_wildcards=expand_wildcards
        )
    
    def _create_namespace_rbac_resources(self,
                                       namespace_permissions: List[Dict[str, Any]],
                                       package_name: str,
                                       service_account_name: str,
                                       namespace_template: str,
                                       expand_wildcards: bool = False) -> tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """
        Create Role and RoleBinding from namespace permissions.
        
        This method is now a simple wrapper around the unified _create_rbac_pair method.
        
        Args:
            namespace_permissions: List of namespace permission sets from CSV
            package_name: Package name for resource naming
            service_account_name: Service account to bind to
            namespace_template: Namespace template string
            expand_wildcards: If True, expands wildcard verbs for least-privileges mode
            
        Returns:
            Tuple of (Role, RoleBinding) or (None, None) if no valid rules
        """
        return self._create_rbac_pair(
            permissions=namespace_permissions,
            package_name=package_name,
            service_account_name=service_account_name,
            namespace_template=namespace_template,
            is_cluster_scoped=False,
            expand_wildcards=expand_wildcards
        )
    
    def _expand_wildcard_verbs(self, rule: Dict[str, Any], expand_wildcards: bool = False) -> Dict[str, Any]:
        """
        Conditionally expand wildcard verbs (*) to explicit verb lists.
        
        By default, preserves wildcards as specified in operator bundles to maintain
        operator functionality. Only expands when explicitly requested for least-privilege mode.
        
        Args:
            rule: RBAC rule dictionary potentially containing wildcard verbs
            expand_wildcards: If True, replaces '*' with explicit verbs; if False, preserves wildcards
            
        Returns:
            Rule with conditionally expanded verbs
        """
        # Standard RBAC verbs to use when expanding wildcards
        standard_verbs = ["get", "list", "watch", "create", "update", "patch", "delete"]
        
        # Create a copy of the rule to avoid modifying the original
        expanded_rule = rule.copy()
        
        verbs = expanded_rule.get('verbs', [])
        if isinstance(verbs, list) and '*' in verbs and expand_wildcards:
            # Only expand wildcards when explicitly requested (least-privileges mode)
            # Keep any other specific verbs that might be present
            expanded_verbs = []
            for verb in verbs:
                if verb == '*':
                    # Replace wildcard with standard verbs
                    expanded_verbs.extend(standard_verbs)
                else:
                    # Keep specific verbs
                    expanded_verbs.append(verb)
            
            # Remove duplicates while preserving order
            seen = set()
            unique_verbs = []
            for verb in expanded_verbs:
                if verb not in seen:
                    seen.add(verb)
                    unique_verbs.append(verb)
            
            expanded_rule['verbs'] = unique_verbs
            self.logger.debug(f"Expanded wildcard verbs for least-privileges mode: {verbs} -> {unique_verbs}")
        elif isinstance(verbs, list) and '*' in verbs:
            # Preserve wildcards by default to maintain operator functionality
            self.logger.debug(f"Preserving wildcard verbs as specified in operator bundle: {verbs}")
        
        return expanded_rule
    
    def _format_rbac_rule(self, rule: Dict[str, Any], expand_wildcards: bool = False) -> Dict[str, Any]:
        """
        Format RBAC rule according to specified structure and standards.
        
        Ensures rules follow the proper format:
        - apiGroups: [""] (list format, empty string for core API)
        - resources: ["pods"] (list format)
        - verbs: Explicit verbs when expand_wildcards=True, otherwise preserves wildcards
        
        Args:
            rule: Raw RBAC rule dictionary
            expand_wildcards: If True, expands wildcard verbs for least-privileges mode
            
        Returns:
            Formatted rule dictionary
        """
        # Start with conditional wildcard expansion
        formatted_rule = self._expand_wildcard_verbs(rule, expand_wildcards)
        
        # Ensure apiGroups is a list and handle empty/core API group
        api_groups = formatted_rule.get('apiGroups', [''])
        if not isinstance(api_groups, list):
            api_groups = [str(api_groups)] if api_groups is not None else ['']
        
        # Convert None or empty string to core API group
        normalized_groups = []
        for group in api_groups:
            if group is None or group == '':
                normalized_groups.append('')  # Core API group
            else:
                normalized_groups.append(str(group))
        
        formatted_rule['apiGroups'] = normalized_groups
        
        # Ensure resources is a list
        resources = formatted_rule.get('resources', [])
        if not isinstance(resources, list):
            resources = [str(resources)] if resources is not None else []
        formatted_rule['resources'] = [str(r) for r in resources]
        
        # Ensure verbs is a list (already handled by wildcard expansion)
        verbs = formatted_rule.get('verbs', [])
        if not isinstance(verbs, list):
            verbs = [str(verbs)] if verbs is not None else []
        formatted_rule['verbs'] = [str(v) for v in verbs]
        
        # Handle resourceNames if present
        resource_names = formatted_rule.get('resourceNames')
        if resource_names is not None:
            if not isinstance(resource_names, list):
                resource_names = [str(resource_names)]
            formatted_rule['resourceNames'] = [str(rn) for rn in resource_names]
        
        return formatted_rule
    
    def _validate_rbac_rule(self, rule: Dict[str, Any]) -> bool:
        """
        Validate an RBAC rule structure.
        
        Ensures that the rule has the required fields and valid structure
        according to Kubernetes RBAC specifications.
        
        Args:
            rule: RBAC rule dictionary to validate
            
        Returns:
            True if rule is valid, False otherwise
        """
        if not isinstance(rule, dict):
            self.logger.debug(f"Invalid rule type: {type(rule)}")
            return False
        
        # Check required fields
        required_fields = ['verbs']
        for field in required_fields:
            if field not in rule:
                self.logger.debug(f"Missing required field '{field}' in rule: {rule}")
                return False
        
        # Validate verbs
        verbs = rule.get('verbs', [])
        if not isinstance(verbs, list) or not verbs:
            self.logger.debug(f"Invalid or empty verbs in rule: {verbs}")
            return False
        
        # Validate resources (if present)
        resources = rule.get('resources', [])
        if resources is not None and not isinstance(resources, list):
            self.logger.debug(f"Invalid resources format in rule: {type(resources)}")
            return False
        
        # Validate apiGroups (if present)
        api_groups = rule.get('apiGroups', [])
        if api_groups is not None and not isinstance(api_groups, list):
            self.logger.debug(f"Invalid apiGroups format in rule: {type(api_groups)}")
            return False
        
        return True
    
    def get_rbac_summary(self, resources: Dict[str, List[Dict]]) -> Dict[str, Any]:
        """
        Generate a summary of converted RBAC resources.
        
        Provides useful statistics and information about the generated resources
        for logging, debugging, and user feedback.
        
        Args:
            resources: Dictionary of converted Kubernetes resources
            
        Returns:
            Dictionary containing RBAC resource summary
        """
        summary = {
            'total_resources': 0,
            'resource_counts': {},
            'service_accounts': [],
            'total_rules': 0,
            'cluster_scope': False,
            'namespace_scope': False
        }
        
        for resource_type, resource_list in resources.items():
            count = len(resource_list)
            summary['resource_counts'][resource_type] = count
            summary['total_resources'] += count
            
            # Extract specific information
            if resource_type == 'serviceAccounts':
                summary['service_accounts'] = [
                    res.get('metadata', {}).get('name', 'unknown') 
                    for res in resource_list
                ]
            elif resource_type == 'clusterRoles':
                summary['cluster_scope'] = count > 0
                for cluster_role in resource_list:
                    rules = cluster_role.get('rules', [])
                    summary['total_rules'] += len(rules)
            elif resource_type == 'roles':
                summary['namespace_scope'] = count > 0  
                for role in resource_list:
                    rules = role.get('rules', [])
                    summary['total_rules'] += len(rules)
        
        self.logger.debug(f"RBAC summary: {summary}")
        return summary
    
    def validate_converted_resources(self, resources: Dict[str, List[Dict]]) -> List[str]:
        """
        Validate converted Kubernetes resources for common issues.
        
        Performs basic validation checks on the generated resources to catch
        potential issues before deployment.
        
        Args:
            resources: Dictionary of converted Kubernetes resources
            
        Returns:
            List of validation warning/error messages (empty if all valid)
        """
        issues = []
        
        # Check for empty resource collections
        if not any(resources.values()):
            issues.append("No resources generated - RBAC conversion may have failed")
        
        # Validate ServiceAccount presence
        if not resources.get('serviceAccounts'):
            issues.append("No ServiceAccount created - RBAC bindings will fail")
        
        # Validate RBAC pairing
        has_cluster_roles = bool(resources.get('clusterRoles'))
        has_cluster_bindings = bool(resources.get('clusterRoleBindings'))
        if has_cluster_roles != has_cluster_bindings:
            issues.append("Mismatch between ClusterRoles and ClusterRoleBindings")
        
        has_roles = bool(resources.get('roles'))
        has_role_bindings = bool(resources.get('roleBindings'))
        if has_roles != has_role_bindings:
            issues.append("Mismatch between Roles and RoleBindings")
        
        # Validate resource structure
        for resource_type, resource_list in resources.items():
            for i, resource in enumerate(resource_list):
                if not resource.get('apiVersion'):
                    issues.append(f"Missing apiVersion in {resource_type}[{i}]")
                if not resource.get('kind'):
                    issues.append(f"Missing kind in {resource_type}[{i}]")
                if not resource.get('metadata', {}).get('name'):
                    issues.append(f"Missing metadata.name in {resource_type}[{i}]")
        
        if issues:
            self.logger.warning(f"Resource validation found {len(issues)} issue(s)")
            for issue in issues:
                self.logger.warning(f"  - {issue}")
        else:
            self.logger.debug("Resource validation passed")
        
        return issues


# ============================================================================
# RBAC MANAGER CORE CLASS
# ============================================================================

# ============================================================================
# RBAC RULE BUILDER (Merged from rbac_builder.py)
# ============================================================================


class RBACRuleTemplates:
    """
    Declarative templates for RBAC rule generation.
    
    This class separates the rule definitions (data) from the rule construction logic,
    making the code much more maintainable and easier to modify.
    """
    
    @staticmethod
    def get_installer_cluster_rules_template() -> List[Dict[str, Any]]:
        """
        Template for installer ClusterRole rules following OpenShift OLMv1 guidelines.
        
        Returns:
            List of rule templates with placeholders for dynamic values
        """
        return [
            # Step 1: RBAC creation and management permissions
            {
                'rule_type': 'static',
                'description': 'ClusterRole management - unscoped create operations',
                'apiGroups': ['rbac.authorization.k8s.io'],
                'resources': ['clusterroles'],
                'verbs': ['create', 'list', 'watch']
            },
            {
                'rule_type': 'post_install_hardening',
                'description': 'ClusterRole management - OLM v1 generated names (requires post-install hardening)',
                'apiGroups': ['rbac.authorization.k8s.io'],
                'resources': ['clusterroles'],
                'verbs': ['get', 'update', 'patch', 'delete'],
                '_post_install_security_note': 'Add resourceNames with actual ClusterRole names created by OLMv1'
            },
            {
                'rule_type': 'static',
                'description': 'ClusterRoleBinding management - unscoped create operations',
                'apiGroups': ['rbac.authorization.k8s.io'],
                'resources': ['clusterrolebindings'],
                'verbs': ['create', 'list', 'watch']
            },
            {
                'rule_type': 'post_install_hardening',
                'description': 'ClusterRoleBinding management - OLM v1 generated names (requires post-install hardening)',
                'apiGroups': ['rbac.authorization.k8s.io'],
                'resources': ['clusterrolebindings'],
                'verbs': ['get', 'update', 'patch', 'delete'],
                '_post_install_security_note': 'Add resourceNames with actual ClusterRoleBinding names created by OLMv1'
            },
            
            # Step 2: CustomResourceDefinition permissions
            {
                'rule_type': 'static',
                'description': 'CRD management - unscoped create operations',
                'apiGroups': ['apiextensions.k8s.io'],
                'resources': ['customresourcedefinitions'],
                'verbs': ['create', 'list', 'watch']
            },
            {
                'rule_type': 'conditional',
                'condition': 'crd_names',
                'description': 'CRD management - scoped to bundle CRDs',
                'apiGroups': ['apiextensions.k8s.io'],
                'resources': ['customresourcedefinitions'],
                'verbs': ['get', 'update', 'patch', 'delete'],
                'resourceNames_source': 'crd_names'
            },
            
            # Step 3: ClusterExtension finalizer permissions
            {
                'rule_type': 'post_install_hardening',
                'description': 'ClusterExtension finalizer management (requires post-install hardening)',
                'apiGroups': ['olm.operatorframework.io'],
                'resources': ['clusterextensions/finalizers'],
                'verbs': ['update'],
                '_post_install_security_note': 'Add resourceNames with actual ClusterExtension name chosen during deployment'
            },
            
            # Step 4: Bundled cluster-scoped resource permissions
            {
                'rule_type': 'conditional',
                'condition': 'bundled_cluster_roles',
                'description': 'Bundled ClusterRole management - scoped to bundle resources',
                'apiGroups': ['rbac.authorization.k8s.io'],
                'resources': ['clusterroles'],
                'verbs': ['get', 'update', 'patch', 'delete'],
                'resourceNames_source': 'bundled_cluster_roles'
            }
        ]
    
    @staticmethod
    def get_installer_namespace_rules_template() -> List[Dict[str, Any]]:
        """
        Template for installer namespace Role rules following OLMv1 guidelines.
        
        Returns:
            List of rule templates for namespace-scoped permissions
        """
        return [
            # Deployment management
            {
                'rule_type': 'static',
                'description': 'Deployment creation - unscoped',
                'apiGroups': ['apps'],
                'resources': ['deployments'],
                'verbs': ['create', 'list', 'watch']
            },
            {
                'rule_type': 'conditional',
                'condition': 'deployment_names',
                'description': 'Deployment management - scoped to operator deployments',
                'apiGroups': ['apps'],
                'resources': ['deployments'],
                'verbs': ['get', 'update', 'patch', 'delete'],
                'resourceNames_source': 'deployment_names'
            },
            
            # ServiceAccount management
            {
                'rule_type': 'static',
                'description': 'ServiceAccount creation - unscoped',
                'apiGroups': [''],
                'resources': ['serviceaccounts'],
                'verbs': ['create', 'list', 'watch']
            },
            {
                'rule_type': 'conditional',
                'condition': 'service_account_names',
                'description': 'ServiceAccount management - scoped to operator service accounts',
                'apiGroups': [''],
                'resources': ['serviceaccounts'],
                'verbs': ['get', 'update', 'patch', 'delete'],
                'resourceNames_source': 'service_account_names'
            },
            
            # Service management
            {
                'rule_type': 'conditional_pair',
                'condition': 'service_names',
                'rules': [
                    {
                        'description': 'Service creation - unscoped',
                        'apiGroups': [''],
                        'resources': ['services'],
                        'verbs': ['create', 'list', 'watch']
                    },
                    {
                        'description': 'Service management - scoped to operator services',
                        'apiGroups': [''],
                        'resources': ['services'],
                        'verbs': ['get', 'update', 'patch', 'delete'],
                        'resourceNames_source': 'service_names'
                    }
                ]
            },
            
            # ConfigMap management
            {
                'rule_type': 'conditional_pair',
                'condition': 'configmap_names',
                'rules': [
                    {
                        'description': 'ConfigMap creation - unscoped',
                        'apiGroups': [''],
                        'resources': ['configmaps'],
                        'verbs': ['create', 'list', 'watch']
                    },
                    {
                        'description': 'ConfigMap management - scoped to operator configmaps',
                        'apiGroups': [''],
                        'resources': ['configmaps'],
                        'verbs': ['get', 'update', 'patch', 'delete'],
                        'resourceNames_source': 'configmap_names'
                    }
                ]
            },
            
            # Role management
            {
                'rule_type': 'static',
                'description': 'Role creation - unscoped',
                'apiGroups': ['rbac.authorization.k8s.io'],
                'resources': ['roles'],
                'verbs': ['create', 'list', 'watch']
            },
            {
                'rule_type': 'static',
                'description': 'Role management - scoped to expected role names',
                'apiGroups': ['rbac.authorization.k8s.io'],
                'resources': ['roles'],
                'verbs': ['get', 'update', 'patch', 'delete'],
                'resourceNames_source': 'expected_role_names'
            },
            
            # RoleBinding management
            {
                'rule_type': 'static',
                'description': 'RoleBinding creation - unscoped',
                'apiGroups': ['rbac.authorization.k8s.io'],
                'resources': ['rolebindings'],
                'verbs': ['create', 'list', 'watch']
            },
            {
                'rule_type': 'static',
                'description': 'RoleBinding management - scoped to expected rolebinding names',
                'apiGroups': ['rbac.authorization.k8s.io'],
                'resources': ['rolebindings'],
                'verbs': ['get', 'update', 'patch', 'delete'],
                'resourceNames_source': 'expected_rolebinding_names'
            }
        ]


class RBACRuleBuilder:
    """
    Builder class that processes declarative RBAC rule templates.
    
    This class contains the logic for processing rule templates and building
    the final RBAC rules based on the provided data.
    """
    
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
    
    def build_installer_cluster_rules(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Build installer ClusterRole rules from declarative templates.
        
        Args:
            context: Dictionary containing all the data needed for rule generation:
                - crd_names: List of CRD names
                - bundled_cluster_roles: List of bundled ClusterRole names
                - deployment_names: List of deployment names
                - service_names: List of service names
                - configmap_names: List of ConfigMap names
                - package_name: Package name
                - operator_metadata: Operator metadata
                
        Returns:
            List of processed RBAC rules
        """
        template = RBACRuleTemplates.get_installer_cluster_rules_template()
        return self._process_rule_template(template, context)
    
    def build_installer_namespace_rules(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Build installer namespace Role rules from declarative templates.
        
        Args:
            context: Dictionary containing all the data needed for rule generation
                
        Returns:
            List of processed RBAC rules
        """
        template = RBACRuleTemplates.get_installer_namespace_rules_template()
        return self._process_rule_template(template, context)
    
    def _process_rule_template(self, template: List[Dict[str, Any]], context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process a rule template by applying context data and conditions.
        
        Args:
            template: List of rule template dictionaries
            context: Context data for rule generation
            
        Returns:
            List of processed RBAC rules
        """
        processed_rules = []
        
        for rule_template in template:
            rule_type = rule_template.get('rule_type', 'static')
            
            if rule_type == 'static':
                # Static rules are always included
                rule = self._build_rule_from_template(rule_template, context)
                processed_rules.append(rule)
                
            elif rule_type == 'conditional':
                # Conditional rules are included only if condition is met
                condition = rule_template.get('condition')
                if condition and context.get(condition):
                    rule = self._build_rule_from_template(rule_template, context)
                    processed_rules.append(rule)
                    
            elif rule_type == 'conditional_pair':
                # Conditional pairs add both rules if condition is met
                condition = rule_template.get('condition')
                if condition and context.get(condition):
                    for sub_rule_template in rule_template.get('rules', []):
                        rule = self._build_rule_from_template(sub_rule_template, context)
                        processed_rules.append(rule)
                        
            elif rule_type == 'post_install_hardening':
                # Post-install hardening rules are always included with security notes
                rule = self._build_rule_from_template(rule_template, context)
                processed_rules.append(rule)
                
        return processed_rules
    
    def _build_rule_from_template(self, rule_template: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build a single RBAC rule from a template.
        
        Args:
            rule_template: Rule template dictionary
            context: Context data for rule generation
            
        Returns:
            Processed RBAC rule
        """
        # Start with base rule structure
        rule = {
            'apiGroups': rule_template['apiGroups'],
            'resources': rule_template['resources'],
            'verbs': rule_template['verbs']
        }
        
        # Add resourceNames if specified
        resource_names_source = rule_template.get('resourceNames_source')
        if resource_names_source:
            resource_names = context.get(resource_names_source)
            if resource_names:
                rule['resourceNames'] = list(resource_names)
        elif 'resourceNames_source' in rule_template and rule_template['resourceNames_source'] == 'expected_role_names':
            # Special handling for expected role names
            rule['resourceNames'] = self._get_expected_role_names(context)
        elif 'resourceNames_source' in rule_template and rule_template['resourceNames_source'] == 'expected_rolebinding_names':
            # Special handling for expected rolebinding names  
            rule['resourceNames'] = self._get_expected_rolebinding_names(context)
        
        # Add security notes for post-install hardening
        if '_post_install_security_note' in rule_template:
            rule['_post_install_security_note'] = rule_template['_post_install_security_note']
            
        return rule
    
    def _get_expected_role_names(self, context: Dict[str, Any]) -> List[str]:
        """Get expected role names based on operator metadata."""
        package_name = context.get('package_name', 'operator')
        operator_metadata = context.get('operator_metadata', {})
        operator_name = operator_metadata.get('name', package_name)
        
        return [
            f"{operator_name}-installer",
            f"{operator_name}-controller"
        ]
    
    def _get_expected_rolebinding_names(self, context: Dict[str, Any]) -> List[str]:
        """Get expected rolebinding names based on operator metadata."""
        # Same as role names for this pattern
        return self._get_expected_role_names(context)

