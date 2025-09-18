"""
Base Generator Classes and Common Logic

This module provides base classes and shared functionality for generating
YAML manifests and Helm values from OPM bundle metadata.
"""

import logging
import re
import yaml
from typing import Dict, List, Any, NamedTuple
from abc import ABC, abstractmethod
from enum import Enum

from ..core.constants import (
    KubernetesConstants, 
    OPMConstants, 
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
    
    def _generate_installer_service_account_rules(self, bundle_metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
e        Generate installer service account Role permissions - ONLY installer-specific permissions
        
        The installer service account needs ONLY these specific permissions:
        1. Create and manage Deployments for extension controllers (from CSV spec.install.deployments)  
        2. Create and manage ServiceAccounts for extension controllers (from deployment templates)
        3. Create and manage bundled namespace-scoped resources (ConfigMaps, Services)
        
        Note: All CSV permissions (.spec.install.permissions) go to ClusterRole to avoid duplication
        
        Args:
            bundle_metadata: Bundle metadata containing deployment info
            
        Returns:
            List of RBAC rules for installer service account Role (minimal, no overlaps)
        """
        rules = []
        deployments = bundle_metadata.get(OPMConstants.CSV_DEPLOYMENTS_SECTION, [])
        
        if deployments:
            # Extract deployment names and service account names from CSV
            deployment_names = []
            service_account_names = set()
            
            for deployment in deployments:
                # Get deployment name
                deployment_name = deployment.get('name')
                if deployment_name:
                    deployment_names.append(deployment_name)
                
                # Get service account name from deployment spec
                deployment_spec = deployment.get('spec', {})
                template = deployment_spec.get('template', {})
                template_spec = template.get('spec', {})
                service_account_name = template_spec.get('serviceAccountName')
                if service_account_name:
                    service_account_names.add(service_account_name)
            
            # Step 1: Deployment permissions (installer-specific)
            if deployment_names:
                # Broad permissions (create, list, watch)
                deployment_broad_rule = {
                    'apiGroups': [KubernetesConstants.APPS_API_GROUP],
                    'resources': [KubernetesConstants.DEPLOYMENTS_RESOURCE],
                    'verbs': [
                        KubernetesConstants.CREATE_VERB,
                        KubernetesConstants.LIST_VERB,
                        KubernetesConstants.WATCH_VERB
                    ]
                }
                rules.append(deployment_broad_rule)
                
                # Scoped permissions (get, update, patch, delete)
                deployment_scoped_rule = {
                    'apiGroups': [KubernetesConstants.APPS_API_GROUP],
                    'resources': [KubernetesConstants.DEPLOYMENTS_RESOURCE],
                    'verbs': [
                        KubernetesConstants.GET_VERB,
                        KubernetesConstants.UPDATE_VERB,
                        KubernetesConstants.PATCH_VERB,
                        KubernetesConstants.DELETE_VERB
                    ],
                    'resourceNames': deployment_names
                }
                rules.append(deployment_scoped_rule)
            
            # Step 2: ServiceAccount permissions (installer-specific)
            if service_account_names:
                service_account_names_list = list(service_account_names)
                
                # Broad permissions (create, list, watch)
                sa_broad_rule = {
                    'apiGroups': [KubernetesConstants.CORE_API_GROUP],
                    'resources': [KubernetesConstants.SERVICE_ACCOUNTS_RESOURCE],
                    'verbs': [
                        KubernetesConstants.CREATE_VERB,
                        KubernetesConstants.LIST_VERB,
                        KubernetesConstants.WATCH_VERB
                    ]
                }
                rules.append(sa_broad_rule)
                
                # Scoped permissions (get, update, patch, delete)
                sa_scoped_rule = {
                    'apiGroups': [KubernetesConstants.CORE_API_GROUP],
                    'resources': [KubernetesConstants.SERVICE_ACCOUNTS_RESOURCE],
                    'verbs': [
                        KubernetesConstants.GET_VERB,
                        KubernetesConstants.UPDATE_VERB,
                        KubernetesConstants.PATCH_VERB,
                        KubernetesConstants.DELETE_VERB
                    ],
                    'resourceNames': service_account_names_list
                }
                rules.append(sa_scoped_rule)
        
        # Step 3: Bundled namespace-scoped resource permissions (installer-specific)
        namespace_resources = bundle_metadata.get('namespace_scoped_resources', [])
        if namespace_resources:
            # Group resources by API group and resource type for efficient rules
            resource_groups = {}
            
            for resource in namespace_resources:
                kind = resource.get('kind', '')
                name = resource.get('name', '')
                api_version = resource.get('apiVersion', '')
                
                # Extract API group and resource type from kind and apiVersion
                api_group, resource_type = self._get_api_group_and_resource(kind, api_version)
                
                if api_group is not None and resource_type:
                    group_key = (api_group, resource_type)
                    if group_key not in resource_groups:
                        resource_groups[group_key] = []
                    
                    if name:
                        resource_groups[group_key].append(name)
            
            # Create rules for each resource group
            for (api_group, resource_type), resource_names in resource_groups.items():
                # Broad permissions (create, list, watch)
                broad_rule = {
                    'apiGroups': [api_group],
                    'resources': [resource_type],
                    'verbs': [
                        KubernetesConstants.CREATE_VERB,
                        KubernetesConstants.LIST_VERB,
                        KubernetesConstants.WATCH_VERB
                    ]
                }
                rules.append(broad_rule)
                
                # Scoped permissions (get, update, patch, delete) - if we have names
                if resource_names:
                    scoped_rule = {
                        'apiGroups': [api_group],
                        'resources': [resource_type],
                        'verbs': [
                            KubernetesConstants.GET_VERB,
                            KubernetesConstants.UPDATE_VERB,
                            KubernetesConstants.PATCH_VERB,
                            KubernetesConstants.DELETE_VERB
                        ],
                        'resourceNames': resource_names
                    }
                    rules.append(scoped_rule)
        
        return rules
    
    def _process_and_deduplicate_rules(self, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process and deduplicate RBAC rules using DRY principle
        
        This method implements comprehensive deduplication logic:
        1. Removes exact duplicates
        2. Handles wildcard permissions (broader permissions supersede narrower ones)
        3. Preserves resourceNames-specific rules even if broader rules exist
        4. Groups similar rules to reduce redundancy
        
        Args:
            rules: List of RBAC rules to deduplicate
            
        Returns:
            Deduplicated list of RBAC rules
        """
        if not rules:
            return []
        
        # Step 1: Remove exact duplicates
        unique_rules = []
        seen_rules = set()
        
        for rule in rules:
            # Create a hashable representation of the rule
            rule_key = self._create_rule_key(rule)
            if rule_key not in seen_rules:
                seen_rules.add(rule_key)
                unique_rules.append(rule.copy())
        
        # Step 2: Group rules by (apiGroups, resources) for deduplication analysis
        rule_groups = {}
        for rule in unique_rules:
            api_groups = tuple(sorted(rule.get('apiGroups', [])))
            resources = tuple(sorted(rule.get('resources', [])))
            group_key = (api_groups, resources)
            
            if group_key not in rule_groups:
                rule_groups[group_key] = []
            rule_groups[group_key].append(rule)
        
        # Step 3: Deduplicate within each group
        deduplicated_rules = []
        for group_key, group_rules in rule_groups.items():
            deduplicated_group = self._deduplicate_rule_group(group_rules)
            deduplicated_rules.extend(deduplicated_group)
        
        return deduplicated_rules
    
    def _create_rule_key(self, rule: Dict[str, Any]) -> tuple:
        """Create a hashable key for rule comparison"""
        api_groups = tuple(sorted(rule.get('apiGroups', [])))
        resources = tuple(sorted(rule.get('resources', [])))
        verbs = tuple(sorted(rule.get('verbs', [])))
        resource_names = tuple(sorted(rule.get('resourceNames', [])))
        return (api_groups, resources, verbs, resource_names)
    
    def _deduplicate_rule_group(self, group_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Deduplicate rules within a group (same apiGroups and resources)
        
        Args:
            group_rules: List of rules with same apiGroups and resources
            
        Returns:
            Deduplicated rules from the group
        """
        if len(group_rules) <= 1:
            return group_rules
        
        # Separate rules with resourceNames from those without
        broad_rules = []  # Rules without resourceNames
        specific_rules = []  # Rules with resourceNames
        
        for rule in group_rules:
            if rule.get('resourceNames'):
                specific_rules.append(rule)
            else:
                broad_rules.append(rule)
        
        # Deduplicate broad rules (merge verbs)
        deduplicated_broad = self._merge_broad_rules(broad_rules)
        
        # Check if broad rules supersede specific rules
        if deduplicated_broad and specific_rules:
            # For each broad rule, check if it covers the specific rules
            filtered_specific_rules = []
            for specific_rule in specific_rules:
                is_superseded = False
                for broad_rule in deduplicated_broad:
                    if self._broad_rule_supersedes_specific(broad_rule, specific_rule):
                        is_superseded = True
                        break
                if not is_superseded:
                    filtered_specific_rules.append(specific_rule)
            specific_rules = filtered_specific_rules
        
        # Deduplicate remaining specific rules among themselves
        deduplicated_specific = self._deduplicate_specific_rules(specific_rules)
        
        return deduplicated_broad + deduplicated_specific
    
    def _broad_rule_supersedes_specific(self, broad_rule: Dict[str, Any], specific_rule: Dict[str, Any]) -> bool:
        """
        Check if a broad rule (without resourceNames) supersedes a specific rule (with resourceNames)
        
        Args:
            broad_rule: Rule without resourceNames
            specific_rule: Rule with resourceNames
            
        Returns:
            True if the broad rule covers all permissions of the specific rule
        """
        # Both rules should have the same apiGroups and resources (they're in the same group)
        broad_verbs = set(broad_rule.get('verbs', []))
        specific_verbs = set(specific_rule.get('verbs', []))
        
        # Check if broad rule has all verbs of the specific rule (or more)
        # If broad rule has wildcard (*) verb, it supersedes everything
        if '*' in broad_verbs:
            return True
        
        # If broad rule verbs are a superset of specific rule verbs, it supersedes
        return specific_verbs.issubset(broad_verbs)
    
    def _merge_broad_rules(self, broad_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Merge broad rules (without resourceNames) by combining verbs
        
        Special handling for RBAC resources: Don't merge rules that mix
        broad verbs (create, list, watch) with scoped verbs (get, update, patch, delete)
        
        Args:
            broad_rules: Rules without resourceNames
            
        Returns:
            Merged rules with combined verbs
        """
        if not broad_rules:
            return []
        
        if len(broad_rules) == 1:
            return broad_rules
        
        # Special case: RBAC resources should not merge broad and scoped verbs
        if self._is_rbac_resource_group(broad_rules):
            return self._merge_rbac_broad_rules(broad_rules)
        
        # General case: merge all verbs
        # Collect all verbs from broad rules
        all_verbs = set()
        for rule in broad_rules:
            verbs = rule.get('verbs', [])
            # If any rule has wildcard, use wildcard
            if '*' in verbs:
                all_verbs = {'*'}
                break
            all_verbs.update(verbs)
        
        # Create merged rule using the first rule as template
        merged_rule = broad_rules[0].copy()
        merged_rule['verbs'] = sorted(list(all_verbs))
        
        return [merged_rule]
    
    def _is_rbac_resource_group(self, rules: List[Dict[str, Any]]) -> bool:
        """Check if rules are for RBAC resources (clusterroles, clusterrolebindings, roles, rolebindings)"""
        if not rules:
            return False
        
        first_rule = rules[0]
        api_groups = first_rule.get('apiGroups', [])
        resources = first_rule.get('resources', [])
        
        return ('rbac.authorization.k8s.io' in api_groups and 
                any(resource in ['clusterroles', 'clusterrolebindings', 'roles', 'rolebindings'] 
                    for resource in resources))
    
    def _merge_rbac_broad_rules(self, broad_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Special merge logic for RBAC resources that preserves separation between
        broad verbs (create, list, watch) and scoped verbs (get, update, patch, delete)
        """
        if not broad_rules:
            return []
        
        # Define verb categories for RBAC resources
        broad_verbs = {'create', 'list', 'watch'}
        scoped_verbs = {'get', 'update', 'patch', 'delete'}
        
        # Separate rules by verb categories
        rules_with_broad_verbs = []
        rules_with_scoped_verbs = []
        rules_with_mixed_verbs = []
        
        for rule in broad_rules:
            verbs = set(rule.get('verbs', []))
            
            # If wildcard, treat as mixed
            if '*' in verbs:
                rules_with_mixed_verbs.append(rule)
                continue
            
            has_broad = bool(verbs & broad_verbs)
            has_scoped = bool(verbs & scoped_verbs)
            
            if has_broad and has_scoped:
                rules_with_mixed_verbs.append(rule)
            elif has_broad:
                rules_with_broad_verbs.append(rule)
            elif has_scoped:
                rules_with_scoped_verbs.append(rule)
        
        result_rules = []
        
        # Merge broad verb rules
        if rules_with_broad_verbs:
            broad_verb_set = set()
            for rule in rules_with_broad_verbs:
                broad_verb_set.update(rule.get('verbs', []))
            
            merged_broad_rule = rules_with_broad_verbs[0].copy()
            merged_broad_rule['verbs'] = sorted(list(broad_verb_set & broad_verbs))
            result_rules.append(merged_broad_rule)
        
        # Merge scoped verb rules
        if rules_with_scoped_verbs:
            scoped_verb_set = set()
            for rule in rules_with_scoped_verbs:
                scoped_verb_set.update(rule.get('verbs', []))
            
            merged_scoped_rule = rules_with_scoped_verbs[0].copy()
            merged_scoped_rule['verbs'] = sorted(list(scoped_verb_set & scoped_verbs))
            result_rules.append(merged_scoped_rule)
        
        # Handle mixed verb rules (keep as-is, don't merge)
        result_rules.extend(rules_with_mixed_verbs)
        
        return result_rules
    
    def _deduplicate_specific_rules(self, specific_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Deduplicate rules with resourceNames
        
        Args:
            specific_rules: Rules with resourceNames
            
        Returns:
            Deduplicated specific rules
        """
        if not specific_rules:
            return []
        
        # Group by verbs
        verb_groups = {}
        for rule in specific_rules:
            verbs = tuple(sorted(rule.get('verbs', [])))
            if verbs not in verb_groups:
                verb_groups[verbs] = []
            verb_groups[verbs].append(rule)
        
        deduplicated = []
        for verbs, rules in verb_groups.items():
            # Merge resourceNames for rules with same verbs
            all_resource_names = set()
            for rule in rules:
                all_resource_names.update(rule.get('resourceNames', []))
            
            # Create merged rule
            merged_rule = rules[0].copy()
            merged_rule['resourceNames'] = sorted(list(all_resource_names))
            deduplicated.append(merged_rule)
        
        return deduplicated
    
    def _filter_unique_role_rules(self, role_rules: List[Dict[str, Any]], 
                                  cluster_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter Role rules to exclude those already covered by ClusterRole rules
        Uses advanced logic to detect when cluster rules cover namespace rules
        
        Args:
            role_rules: Namespace-scoped rules for Role
            cluster_rules: Cluster-scoped rules from ClusterRole
            
        Returns:
            Filtered Role rules with no overlap with ClusterRole
        """
        if not role_rules:
            return []
        
        if not cluster_rules:
            return role_rules
        
        # Process cluster rules to understand what they cover
        cluster_coverage = self._analyze_cluster_rule_coverage(cluster_rules)
        
        # Filter role rules based on cluster coverage
        unique_role_rules = []
        for role_rule in role_rules:
            if not self._is_rule_covered_by_cluster(role_rule, cluster_coverage):
                unique_role_rules.append(role_rule)
        
        return unique_role_rules
    
    def _analyze_cluster_rule_coverage(self, cluster_rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze what permissions are covered by cluster rules
        
        Args:
            cluster_rules: List of cluster-scoped RBAC rules
            
        Returns:
            Dictionary describing the coverage of cluster rules
        """
        coverage = {
            'wildcard_permissions': set(),  # (apiGroups, resources) with wildcard verbs
            'specific_permissions': {},     # (apiGroups, resources) -> set of verbs
            'resource_specific': {}         # (apiGroups, resources) -> {resourceNames -> verbs}
        }
        
        for rule in cluster_rules:
            api_groups = tuple(sorted(rule.get('apiGroups', [])))
            resources = tuple(sorted(rule.get('resources', [])))
            verbs = rule.get('verbs', [])
            resource_names = rule.get('resourceNames', [])
            
            permission_key = (api_groups, resources)
            
            # Handle wildcard verbs
            if '*' in verbs:
                if not resource_names:
                    # Broad wildcard permission
                    coverage['wildcard_permissions'].add(permission_key)
                else:
                    # Resource-specific wildcard
                    if permission_key not in coverage['resource_specific']:
                        coverage['resource_specific'][permission_key] = {}
                    for resource_name in resource_names:
                        coverage['resource_specific'][permission_key][resource_name] = set(['*'])
            else:
                if not resource_names:
                    # Broad specific permissions
                    if permission_key not in coverage['specific_permissions']:
                        coverage['specific_permissions'][permission_key] = set()
                    coverage['specific_permissions'][permission_key].update(verbs)
                else:
                    # Resource-specific permissions
                    if permission_key not in coverage['resource_specific']:
                        coverage['resource_specific'][permission_key] = {}
                    for resource_name in resource_names:
                        if resource_name not in coverage['resource_specific'][permission_key]:
                            coverage['resource_specific'][permission_key][resource_name] = set()
                        coverage['resource_specific'][permission_key][resource_name].update(verbs)
        
        return coverage
    
    def _is_rule_covered_by_cluster(self, role_rule: Dict[str, Any], cluster_coverage: Dict[str, Any]) -> bool:
        """
        Check if a role rule is already covered by cluster rules
        
        Args:
            role_rule: The role rule to check
            cluster_coverage: Coverage analysis from cluster rules
            
        Returns:
            True if the role rule is covered by cluster rules
        """
        api_groups = tuple(sorted(role_rule.get('apiGroups', [])))
        resources = tuple(sorted(role_rule.get('resources', [])))
        verbs = set(role_rule.get('verbs', []))
        resource_names = role_rule.get('resourceNames', [])
        
        permission_key = (api_groups, resources)
        
        # Check for exact wildcard match
        if permission_key in cluster_coverage['wildcard_permissions'] and not resource_names:
            return True
        
        # Check for wildcard resources (e.g., ['*'] in resources) or if cluster rule covers this resource
        for covered_key in cluster_coverage['wildcard_permissions']:
            covered_api_groups, covered_resources = covered_key
            if covered_api_groups == api_groups and not resource_names:
                # Check if cluster rule has wildcard resources
                if '*' in covered_resources:
                    return True
                # Check if cluster rule explicitly contains our resources
                if any(resource in covered_resources for resource in resources):
                    return True
        
        # Check specific permissions coverage
        if permission_key in cluster_coverage['specific_permissions']:
            cluster_verbs = cluster_coverage['specific_permissions'][permission_key]
            if not resource_names and verbs.issubset(cluster_verbs):
                return True
        
        # Check if any cluster rule covers this resource with broader permissions
        for covered_key, cluster_verbs in cluster_coverage['specific_permissions'].items():
            covered_api_groups, covered_resources = covered_key
            if (covered_api_groups == api_groups and not resource_names and
                any(resource in covered_resources for resource in resources)):
                # Check if cluster verbs cover our verbs
                if '*' in cluster_verbs or verbs.issubset(cluster_verbs):
                    return True
        
        # Check resource-specific coverage
        if resource_names and permission_key in cluster_coverage['resource_specific']:
            resource_coverage = cluster_coverage['resource_specific'][permission_key]
            for resource_name in resource_names:
                if resource_name in resource_coverage:
                    covered_verbs = resource_coverage[resource_name]
                    if '*' in covered_verbs or verbs.issubset(covered_verbs):
                        # This specific resource is covered
                        continue
                    else:
                        # This resource is not fully covered
                        return False
                else:
                    # This resource is not covered at all
                    return False
            # All resources are covered
            return True
        
        return False
    
    def _get_api_group_and_resource(self, kind: str, api_version: str) -> tuple[str, str]:
        """
        Extract API group and resource type from kind and apiVersion
        
        Args:
            kind: Kubernetes resource kind (e.g., 'Service', 'ClusterRole')
            api_version: API version (e.g., 'v1', 'rbac.authorization.k8s.io/v1')
            
        Returns:
            Tuple of (api_group, resource_type) or (None, '') if cannot determine
        """
        if not kind:
            return None, ''
        
        # Extract API group from apiVersion
        if '/' in api_version:
            api_group = api_version.split('/')[0]
        else:
            # Core API group (v1, etc.) uses empty string
            api_group = KubernetesConstants.CORE_API_GROUP
        
        # Convert kind to resource type (pluralize and lowercase)
        resource_type = self._kind_to_resource_type(kind)
        
        return api_group, resource_type
    
    def _kind_to_resource_type(self, kind: str) -> str:
        """
        Convert Kubernetes kind to resource type using algorithmic approach
        
        Follows Kubernetes naming conventions:
        1. Convert PascalCase to lowercase
        2. Apply English pluralization rules
        3. Handle compound words properly
        
        Args:
            kind: Kubernetes resource kind (e.g., 'Pod', 'ServiceAccount')
            
        Returns:
            Resource type (pluralized, lowercase, e.g., 'pods', 'serviceaccounts')
        """
        if not kind:
            return ""
        
        # Convert PascalCase/CamelCase to lowercase with word boundaries
        # This handles cases like 'ServiceAccount' -> 'service account' -> 'serviceaccounts'
        # Insert spaces before capital letters (except the first one)
        spaced = re.sub(r'(?<!^)(?=[A-Z])', ' ', kind)
        
        # Convert to lowercase and remove spaces
        normalized = spaced.lower().replace(' ', '')
        
        # Apply English pluralization rules
        return self._pluralize_english_word(normalized)
    
    def _pluralize_english_word(self, word: str) -> str:
        """
        Apply English pluralization rules algorithmically
        
        Args:
            word: Singular word to pluralize
            
        Returns:
            Pluralized word following English grammar rules
        """
        if not word:
            return word
        
        # Handle irregular plurals that don't follow standard rules
        # These are genuine linguistic exceptions, not Kubernetes-specific
        irregular_plurals = {
            'person': 'people',
            'child': 'children', 
            'foot': 'feet',
            'tooth': 'teeth',
            'mouse': 'mice',
            'goose': 'geese'
        }
        
        if word in irregular_plurals:
            return irregular_plurals[word]
        
        # Handle words ending in 'y' preceded by consonant
        if len(word) > 1 and word.endswith('y') and word[-2] not in 'aeiou':
            return word[:-1] + 'ies'  # policy -> policies, category -> categories
        
        # Handle words ending in 's', 'ss', 'sh', 'ch', 'x', 'z'
        if word.endswith(('s', 'ss', 'sh', 'ch', 'x', 'z')):
            return word + 'es'  # class -> classes, box -> boxes
        
        # Handle words ending in 'f' or 'fe'
        if word.endswith('f'):
            return word[:-1] + 'ves'  # leaf -> leaves, shelf -> shelves
        elif word.endswith('fe'):
            return word[:-2] + 'ves'  # knife -> knives, life -> lives
        
        # Handle words ending in 'o' preceded by consonant
        if len(word) > 1 and word.endswith('o') and word[-2] not in 'aeiou':
            # Most words ending in consonant + 'o' add 'es'
            # But some just add 's' (like 'photo' -> 'photos')
            # For Kubernetes resources, this is typically 'es'
            return word + 'es'  # hero -> heroes, potato -> potatoes
        
        # Default rule: just add 's'
        return word + 's'  # pod -> pods, deployment -> deployments

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
        
        # RBAC management permissions - data-driven approach for easy extension
        rbac_management_config = {
            'api_group': KubernetesConstants.RBAC_API_GROUP,
            'lifecycle_verbs': [
                KubernetesConstants.CREATE_VERB, 
                KubernetesConstants.LIST_VERB, 
                KubernetesConstants.WATCH_VERB
            ],
            'management_verbs': [
                KubernetesConstants.GET_VERB, 
                KubernetesConstants.UPDATE_VERB, 
                KubernetesConstants.PATCH_VERB, 
                KubernetesConstants.DELETE_VERB
            ],
            'resources': [
                KubernetesConstants.CLUSTER_ROLES_RESOURCE,
                KubernetesConstants.CLUSTER_ROLE_BINDINGS_RESOURCE
                # Future: Add ServiceAccounts, RoleBindings, etc. as needed
                # KubernetesConstants.SERVICE_ACCOUNTS_RESOURCE,
                # KubernetesConstants.ROLE_BINDINGS_RESOURCE
            ]
        }
        
        # Generate RBAC management rules from configuration
        for resource in rbac_management_config['resources']:
            # Unscoped permissions for RBAC lifecycle
            rules.append({
                'apiGroups': [rbac_management_config['api_group']],
                'resources': [resource],
                'verbs': rbac_management_config['lifecycle_verbs']
            })
            
            # Scoped permissions for RBAC management (resourceNames added post-installation)
            rules.append({
                'apiGroups': [rbac_management_config['api_group']],
                'resources': [resource],
                'verbs': rbac_management_config['management_verbs']
                # Note: resourceNames should be added post-installation
            })
        
        return rules
    
    def _generate_bundled_cluster_resource_rules(self, bundle_metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate rules for bundled cluster-scoped resources (ClusterRoles, CRDs, etc.)
        
        Args:
            bundle_metadata: Bundle metadata from OPM
            
        Returns:
            List of RBAC rules for managing cluster-scoped resources from bundle
        """
        rules = []
        cluster_resources = bundle_metadata.get('cluster_scoped_resources', [])
        
        if cluster_resources:
            # Separate ClusterRoles from other cluster resources for special handling
            cluster_roles = []
            other_cluster_resources = []
            
            for resource in cluster_resources:
                kind = resource.get('kind', '')
                if kind == 'ClusterRole':
                    cluster_roles.append(resource)
                else:
                    other_cluster_resources.append(resource)
            
            # Handle ClusterRoles specifically - create individual rules for each ClusterRole
            if cluster_roles:
                for cluster_role in cluster_roles:
                    name = cluster_role.get('name', '')
                    if name:
                        # Create a specific rule for this ClusterRole
                        cluster_role_rule = {
                            'apiGroups': ['rbac.authorization.k8s.io'],
                            'resources': ['clusterroles'],
                            'verbs': [
                                KubernetesConstants.GET_VERB,
                                KubernetesConstants.UPDATE_VERB,
                                KubernetesConstants.PATCH_VERB,
                                KubernetesConstants.DELETE_VERB
                            ],
                            'resourceNames': [name]
                        }
                        rules.append(cluster_role_rule)
            
            # Handle other cluster-scoped resources with the existing grouping logic
            if other_cluster_resources:
                # Group other cluster-scoped resources by API group and resource type
                cluster_resource_groups = {}
                
                for resource in other_cluster_resources:
                    kind = resource.get('kind', '')
                    name = resource.get('name', '')
                    api_version = resource.get('apiVersion', '')
                    
                    # Extract API group and resource type from kind and apiVersion
                    api_group, resource_type = self._get_api_group_and_resource(kind, api_version)
                    
                    if api_group is not None and resource_type:
                        group_key = (api_group, resource_type)
                        if group_key not in cluster_resource_groups:
                            cluster_resource_groups[group_key] = []
                        
                        if name:
                            cluster_resource_groups[group_key].append(name)
                
                # Create rules for each cluster resource group
                for (api_group, resource_type), resource_names in cluster_resource_groups.items():
                    # For cluster-scoped resources, add scoped permissions
                    if resource_names:
                        cluster_manage_rule = {
                            'apiGroups': [api_group],
                            'resources': [resource_type],
                            'verbs': [
                                KubernetesConstants.GET_VERB,
                                KubernetesConstants.UPDATE_VERB,
                                KubernetesConstants.PATCH_VERB,
                                KubernetesConstants.DELETE_VERB
                            ],
                            'resourceNames': resource_names
                        }
                        rules.append(cluster_manage_rule)
        
        return rules
    
    def _generate_bundled_cluster_resource_rules_for_grantor(self, bundle_metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate rules for bundled cluster-scoped resources EXCLUDING ClusterRoles (for grantor ClusterRole)
        ClusterRole management should only be in the installer ClusterRole, not grantor
        
        Args:
            bundle_metadata: Bundle metadata from OPM
            
        Returns:
            List of RBAC rules for managing non-ClusterRole cluster-scoped resources from bundle
        """
        rules = []
        cluster_resources = bundle_metadata.get('cluster_scoped_resources', [])
        
        if cluster_resources:
            # Only process non-ClusterRole cluster resources for grantor
            other_cluster_resources = []
            
            for resource in cluster_resources:
                kind = resource.get('kind', '')
                if kind != 'ClusterRole':  # Exclude ClusterRoles from grantor
                    other_cluster_resources.append(resource)
            
            # Handle non-ClusterRole cluster-scoped resources with the existing grouping logic
            if other_cluster_resources:
                # Group cluster-scoped resources by API group and resource type
                cluster_resource_groups = {}
                
                for resource in other_cluster_resources:
                    kind = resource.get('kind', '')
                    name = resource.get('name', '')
                    api_version = resource.get('apiVersion', '')
                    
                    # Extract API group and resource type from kind and apiVersion
                    api_group, resource_type = self._get_api_group_and_resource(kind, api_version)
                    
                    if api_group is not None and resource_type:
                        group_key = (api_group, resource_type)
                        if group_key not in cluster_resource_groups:
                            cluster_resource_groups[group_key] = []
                        
                        if name:
                            cluster_resource_groups[group_key].append(name)
                
                # Create rules for each cluster resource group
                for (api_group, resource_type), resource_names in cluster_resource_groups.items():
                    # For cluster-scoped resources, add scoped permissions
                    if resource_names:
                        cluster_manage_rule = {
                            'apiGroups': [api_group],
                            'resources': [resource_type],
                            'verbs': [
                                KubernetesConstants.GET_VERB,
                                KubernetesConstants.UPDATE_VERB,
                                KubernetesConstants.PATCH_VERB,
                                KubernetesConstants.DELETE_VERB
                            ],
                            'resourceNames': resource_names
                        }
                        rules.append(cluster_manage_rule)
        
        return rules
    
    def _generate_grantor_rules(self, bundle_metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate grantor ClusterRole rules from ONLY cluster permissions (spec.install.clusterPermissions)
        
        Args:
            bundle_metadata: Bundle metadata from OPM
            
        Returns:
            List of RBAC rules from CSV cluster permissions ONLY
        """
        # Get ONLY cluster permissions (namespace permissions go to Role)
        cluster_permissions = bundle_metadata.get(OPMConstants.BUNDLE_CLUSTER_PERMISSIONS_KEY, [])
        
        rules = []
        
        # Extract rules from cluster permissions (cluster-scoped) ONLY
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
                k8s_verbs = {
                    KubernetesConstants.GET_VERB,
                    KubernetesConstants.LIST_VERB, 
                    KubernetesConstants.WATCH_VERB,
                    KubernetesConstants.CREATE_VERB,
                    KubernetesConstants.UPDATE_VERB,
                    KubernetesConstants.PATCH_VERB,
                    KubernetesConstants.DELETE_VERB
                }
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
                if items == [KubernetesConstants.WILDCARD_VERB]:
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

    def _generate_security_header_comment(self, operator_name: str, package_name: str, 
                                        output_type: str = 'helm') -> str:
        """
        Generate security hardening header comment for both Helm and YAML outputs
        
        Args:
            operator_name: Name of the operator
            package_name: Package name
            output_type: 'helm' for Helm values, 'yaml' for YAML manifests
            
        Returns:
            Formatted header comment with security guidance
        """
        formatted_name = operator_name.replace('-', '-').title()
        
        if output_type == 'helm':
            return self._generate_helm_header_comment(formatted_name, package_name)
        elif output_type == 'yaml':
            return self._generate_yaml_header_comment(formatted_name, package_name)
        else:
            raise ValueError(f"Unsupported output_type: {output_type}")
    
    def _generate_helm_header_comment(self, formatted_name: str, package_name: str) -> str:
        """Generate header comment for Helm values file"""
        return f"""# IMPORTANT: Verify Correct Channel Before Deployment
# ====================================================
# The 'channel' field below is set to 'stable' by default, but many operators
# use different channels (alpha, beta, candidate, etc.).
#
# 🔍 FIND THE CORRECT CHANNEL:
# Use the RBAC Manager tool to discover available channels for this operator:
#
#   # Step 1: List available catalogs
#   python3 rbac-manager.py list-catalogs --skip-tls
#
#   # Step 2: Show channels for {package_name} (use catalog from step 1)
#   python3 rbac-manager.py catalogd --catalog-name operatorhubio-catalog \\
#     --package {package_name}
#
#   # Alternative: Direct OpenShift API access
#   python3 rbac-manager.py catalogd --catalog-name operatorhubio-catalog \\
#     --package {package_name} --openshift-url https://api.cluster.example.com:6443 \\
#     --openshift-token sha256~your-token
#
#   # Example: ArgoCD operator uses 'alpha' channel, not 'stable':
#   operator:
#     channel: alpha  # ← Update this based on catalogd output
#
# ⚠️  Using wrong channel will cause deployment failures!
#
# =========================================================
#
# SECURITY NOTICE: Post-Installation RBAC Hardening Required
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
#   oc get clusterroles,clusterrolebindings -l app.kubernetes.io/managed-by=olm
#   oc get clusterextensions
#
# Step 2: Update Installer Permissions  
# ------------------------------------
# In this values.yaml, look for rules with 'resourceNames: []' (empty arrays).
# These are the rules that need hardening after the operator is installed:
#
# For ClusterRole/ClusterRoleBinding management rules:
#   resourceNames: [] # After install, add: ["<packageName>.<hash1>", "<packageName>.<hash2>"]
#   Example: ['{package_name}.a1b2c3d4', '{package_name}.e5f6g7h8']
#   Command: oc get clusterroles,clusterrolebindings -l app.kubernetes.io/managed-by=olm
#
# For ClusterExtension finalizer rules:
#   resourceNames: [] # After install, add: ["<your-chosen-clusterextension-name>"]
#   Example: ['my-argocd-operator'] or ['company-gitops']
#   Command: oc get clusterextensions
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

    def _generate_yaml_header_comment(self, formatted_name: str, package_name: str) -> str:
        """Generate header comment for YAML manifests"""
        return f"""# SECURITY NOTICE: Post-Installation RBAC Hardening Required
# =========================================================
# These YAML manifests contain installer permissions with INTENTIONALLY BROAD SCOPE
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
# Step 2: Edit and Harden ClusterRole Permissions
# ------------------------------------------------
# Look for ClusterRole rules with empty resourceNames arrays in the manifests below.
# These are the rules that need hardening after the operator is installed:
#
# For ClusterRole/ClusterRoleBinding management rules:
#   Edit this file and replace empty resourceNames: [] with actual resource names:
#   resourceNames: ["{package_name}.a1b2c3d4", "{package_name}.e5f6g7h8"]
#   Command to find actual names: oc get clusterroles,clusterrolebindings -l app.kubernetes.io/managed-by=olm
#
# For ClusterExtension finalizer rules:
#   Edit this file and replace empty resourceNames: [] with your ClusterExtension name:
#   resourceNames: ["my-argocd-operator"]
#   Command to find actual names: oc get clusterextensions
#
# Step 3: Apply Hardened Permissions
# -----------------------------------
#   oc apply -f <this-updated-yaml-file>
#   # or
#   kubectl apply -f <this-updated-yaml-file>
#
# =========================================================
#
# {formatted_name} Operator RBAC manifests for OLMv1 installation
# Package: {package_name}
# Generated automatically from bundle metadata"""
    
    def analyze_rbac_components(self, bundle_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze bundle metadata and determine which RBAC components are needed.
        
        This method centralizes the decision-making logic for RBAC component creation,
        eliminating duplication between HelmValuesGenerator and YAMLManifestGenerator.
        
        Args:
            bundle_metadata: Bundle metadata from OPM
            
        Returns:
            Dictionary containing:
            {
                'components_needed': {
                    'installer_cluster_role': bool,
                    'grantor_cluster_role': bool,
                    'namespace_role': bool,
                    'cluster_role_bindings': bool,
                    'role_bindings': bool
                },
                'rules': {
                    'installer_cluster_role': [...],  # Rules for operator management ClusterRole
                    'grantor_cluster_role': [...],    # Rules for grantor ClusterRole
                    'namespace_role': [...]           # Rules for namespace Role
                },
                'permission_scenario': str,  # Description of the permission scenario
                'analysis': dict             # Result from analyze_permissions method
            }
        """
        # Use existing analyze_permissions method
        analysis = self.analyze_permissions(bundle_metadata)
        has_cluster_permissions = analysis.has_cluster_permissions
        has_namespace_permissions = analysis.has_namespace_permissions
        
        # Initialize result structure
        result = {
            'components_needed': {
                'installer_cluster_role': True,  # Always needed for operator management
                'grantor_cluster_role': False,
                'namespace_role': False,
                'cluster_role_bindings': True,   # Always needed for installer ClusterRole
                'role_bindings': False
            },
            'rules': {
                'installer_cluster_role': [],
                'grantor_cluster_role': [],
                'namespace_role': []
            },
            'permission_scenario': '',
            'analysis': analysis
        }
        
        # Generate base operator management rules (always needed)
        operator_rules = self._generate_operator_rules(bundle_metadata)
        bundled_cluster_rules = self._generate_bundled_cluster_resource_rules(bundle_metadata)
        combined_operator_rules = operator_rules + bundled_cluster_rules
        result['rules']['installer_cluster_role'] = self._process_and_deduplicate_rules(combined_operator_rules)
        
        # Decision logic based on permission types
        if has_cluster_permissions and has_namespace_permissions:
            # Scenario 1: Both clusterPermissions and permissions (e.g., ArgoCD)
            # - installer ClusterRole: operator management + bundled cluster resources
            # - grantor ClusterRole: CSV cluster permissions + bundled cluster resources (excluding ClusterRoles)
            # - namespace Role: CSV namespace permissions (deduplicated against cluster rules)
            result['permission_scenario'] = 'both_cluster_and_namespace'
            result['components_needed']['grantor_cluster_role'] = True
            result['components_needed']['namespace_role'] = True
            result['components_needed']['role_bindings'] = True
            
            # Generate grantor ClusterRole rules
            cluster_grantor_rules = []
            for perm in bundle_metadata.get(OPMConstants.BUNDLE_CLUSTER_PERMISSIONS_KEY, []):
                cluster_grantor_rules.extend(perm.get('rules', []))
            
            # Add bundled cluster resources (excluding ClusterRoles for grantor)
            bundled_cluster_rules_grantor = self._generate_bundled_cluster_resource_rules_for_grantor(bundle_metadata)
            cluster_grantor_rules.extend(bundled_cluster_rules_grantor)
            
            if cluster_grantor_rules:
                result['rules']['grantor_cluster_role'] = self._process_and_deduplicate_rules(cluster_grantor_rules)
            else:
                result['components_needed']['grantor_cluster_role'] = False
            
            # Generate namespace Role rules (deduplicated against cluster rules)
            namespace_rules = self._generate_namespace_rules(bundle_metadata)
            installer_rules = self._generate_installer_service_account_rules(bundle_metadata)
            combined_role_rules = namespace_rules + installer_rules
            
            if combined_role_rules:
                deduplicated_role_rules = self._process_and_deduplicate_rules(combined_role_rules)
                
                # Get cluster rules for filtering (combine installer + grantor)
                all_cluster_rules = result['rules']['installer_cluster_role'] + result['rules']['grantor_cluster_role']
                final_role_rules = self._filter_unique_role_rules(deduplicated_role_rules, all_cluster_rules)
                
                if final_role_rules:
                    result['rules']['namespace_role'] = final_role_rules
                else:
                    result['components_needed']['namespace_role'] = False
                    result['components_needed']['role_bindings'] = False
            else:
                result['components_needed']['namespace_role'] = False
                result['components_needed']['role_bindings'] = False
                
        elif has_cluster_permissions:
            # Scenario 2: Only clusterPermissions (cluster-only operator)
            # - installer ClusterRole: operator management + bundled cluster resources
            # - grantor ClusterRole: CSV cluster permissions + bundled cluster resources (excluding ClusterRoles)
            # - No namespace Role needed
            result['permission_scenario'] = 'cluster_only'
            result['components_needed']['grantor_cluster_role'] = True
            
            # Generate grantor ClusterRole rules
            cluster_grantor_rules = []
            for perm in bundle_metadata.get(OPMConstants.BUNDLE_CLUSTER_PERMISSIONS_KEY, []):
                cluster_grantor_rules.extend(perm.get('rules', []))
            
            # Add bundled cluster resources (excluding ClusterRoles for grantor)
            bundled_cluster_rules_grantor = self._generate_bundled_cluster_resource_rules_for_grantor(bundle_metadata)
            cluster_grantor_rules.extend(bundled_cluster_rules_grantor)
            
            if cluster_grantor_rules:
                result['rules']['grantor_cluster_role'] = self._process_and_deduplicate_rules(cluster_grantor_rules)
            else:
                result['components_needed']['grantor_cluster_role'] = False
                
        elif has_namespace_permissions:
            # Scenario 3: Only permissions (e.g., Quay operator - treat as ClusterRoles)
            # - installer ClusterRole: operator management + bundled cluster resources
            # - grantor ClusterRole: CSV namespace permissions (treated as cluster-scoped) + bundled cluster resources
            # - No namespace Role needed
            result['permission_scenario'] = 'namespace_treated_as_cluster'
            result['components_needed']['grantor_cluster_role'] = True
            
            # Generate grantor ClusterRole rules (treat namespace permissions as cluster-scoped)
            namespace_rules = self._generate_namespace_rules(bundle_metadata)
            bundled_cluster_rules_grantor = self._generate_bundled_cluster_resource_rules_for_grantor(bundle_metadata)
            combined_rules = namespace_rules + bundled_cluster_rules_grantor
            
            if combined_rules:
                result['rules']['grantor_cluster_role'] = combined_rules
            else:
                result['components_needed']['grantor_cluster_role'] = False
                
        else:
            # Scenario 4: No permissions defined (unusual case)
            # - installer ClusterRole: operator management + bundled cluster resources only
            # - No grantor ClusterRole needed
            # - Add empty namespace Role for Helm compatibility
            result['permission_scenario'] = 'no_permissions'
            # grantor_cluster_role already False
            # For Helm compatibility, we might need an empty Role
            result['components_needed']['namespace_role'] = True  # Empty role for Helm
            result['components_needed']['role_bindings'] = True
            result['rules']['namespace_role'] = []  # Empty rules
        
        return result

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
    def base_values_template(operator_name: str, version: str, package_name: str, channel: str = None) -> Dict[str, Any]:
        """Base Helm values template with channel guidance"""
        return {
            'nameOverride': '',
            'fullnameOverride': '',
            'operator': {
                'name': operator_name,
                'create': True,
                'appVersion': version,
                # IMPORTANT: Verify correct channel with catalogd before deployment!
                # Many operators use 'alpha', 'beta', or 'candidate' instead of 'stable'
                # Run: kubectl get package <package-name> -o jsonpath='{.status.channels[*].name}'
                'channel': channel or "#<VERIFY_WITH_CATALOGD_AND_SET_CHANNEL>",  # Use provided channel or placeholder
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
