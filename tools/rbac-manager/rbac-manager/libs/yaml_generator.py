"""
YAML Generator

Generates Kubernetes YAML manifests for RBAC resources and ClusterExtension.
"""

import yaml
from typing import Dict, Any


class YAMLGenerator:
    """Generates YAML manifests for OLMv1 operators"""
    
    def __init__(self):
        pass
    
    def generate_yaml_manifests(self, metadata: Dict[str, Any], namespace: str = "default", 
                               operator_name: str = None, least_privileges: bool = False) -> Dict[str, str]:
        """Generate YAML manifests from bundle metadata"""
        if not operator_name:
            operator_name = metadata.get('operator_name', 'operator').replace('.', '-')
        
        manifests = {}
        
        # Generate ServiceAccount
        manifests['01-serviceaccount.yaml'] = self.generate_service_account(operator_name, namespace)
        
        # Generate ClusterRoles
        cluster_role_yaml = self.generate_cluster_roles(operator_name, metadata.get('rbac_rules', []), least_privileges)
        manifests['02-clusterrole.yaml'] = cluster_role_yaml
        
        # Generate ClusterRoleBindings
        manifests['03-clusterrolebinding.yaml'] = self.generate_cluster_role_bindings(
            operator_name, namespace
        )
        
        # Generate ClusterExtension
        manifests['04-clusterextension.yaml'] = self.generate_cluster_extension(
            operator_name, namespace, metadata
        )
        
        return manifests
    
    def generate_service_account(self, operator_name: str, namespace: str) -> str:
        """Generate ServiceAccount YAML"""
        sa = {
            'kind': 'ServiceAccount',
            'apiVersion': 'v1',
            'metadata': {
                'name': f'{operator_name}-installer',
                'namespace': namespace,
                'labels': {
                    'olmv1': f'{operator_name}-installer'
                }
            }
        }
        
        return yaml.dump(sa, default_flow_style=False)
    
    def generate_cluster_roles(self, operator_name: str, rbac_rules: list, least_privileges: bool = False) -> str:
        """Generate ClusterRole YAMLs"""
        # Operator ClusterRole
        operator_rules = [
            {
                'apiGroups': ['olm.operatorframework.io'],
                'resources': ['clusterextensions/finalizers'],
                'verbs': ['update'],
                'resourceNames': [operator_name]
            },
            {
                'apiGroups': ['apiextensions.k8s.io'],
                'resources': ['customresourcedefinitions'],
                'verbs': ['create', 'list', 'watch']
            },
            {
                'apiGroups': ['apiextensions.k8s.io'],
                'resources': ['customresourcedefinitions'],
                'verbs': ['get', 'update', 'patch', 'delete']
            },
            {
                'apiGroups': ['rbac.authorization.k8s.io'],
                'resources': ['clusterroles'],
                'verbs': ['create', 'list', 'watch']
            },
            {
                'apiGroups': ['rbac.authorization.k8s.io'],
                'resources': ['clusterroles'],
                'verbs': ['get', 'update', 'patch', 'delete']
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
            }
        ]
        
        operator_cluster_role = {
            'apiVersion': 'rbac.authorization.k8s.io/v1',
            'kind': 'ClusterRole',
            'metadata': {
                'name': f'{operator_name}-installer-clusterrole'
            },
            'rules': operator_rules
        }
        
        # Grantor ClusterRole (with extracted RBAC rules)
        processed_rbac_rules = rbac_rules if rbac_rules else []
        if least_privileges and processed_rbac_rules:
            processed_rbac_rules = [self._apply_least_privileges(rule) for rule in processed_rbac_rules]
        
        grantor_cluster_role = {
            'apiVersion': 'rbac.authorization.k8s.io/v1',
            'kind': 'ClusterRole',
            'metadata': {
                'name': f'{operator_name}-installer-rbac-clusterrole'
            },
            'rules': processed_rbac_rules
        }
        
        # Combine both roles in one YAML
        combined_yaml = yaml.dump(operator_cluster_role, default_flow_style=False)
        combined_yaml += "---\n"
        combined_yaml += yaml.dump(grantor_cluster_role, default_flow_style=False)
        
        return combined_yaml
    
    def _apply_least_privileges(self, rule: dict) -> dict:
        """Apply least-privilege principles to RBAC rules"""
        # Remove wildcard permissions and replace with specific ones
        if 'resources' in rule:
            # Replace wildcard resources with specific ones
            resources = rule['resources']
            if '*' in resources:
                # This is a simplified example - in practice, you'd need to analyze
                # what specific resources the operator actually needs
                resources = [r for r in resources if r != '*']
                if not resources:
                    resources = ['pods', 'services', 'configmaps', 'secrets']
            rule['resources'] = resources
        
        if 'verbs' in rule:
            # Remove dangerous verbs if present
            verbs = rule['verbs']
            dangerous_verbs = ['*', 'escalate', 'bind']
            verbs = [v for v in verbs if v not in dangerous_verbs]
            if not verbs:
                verbs = ['get', 'list', 'watch']
            rule['verbs'] = verbs
        
        # Add resourceNames if not present to limit scope
        if 'resourceNames' not in rule and 'resources' in rule:
            # This is a simplified example - in practice, you'd need to analyze
            # what specific resource names the operator actually needs
            pass
        
        return rule
    
    def generate_cluster_role_bindings(self, operator_name: str, namespace: str) -> str:
        """Generate ClusterRoleBinding YAMLs"""
        operator_binding = {
            'kind': 'ClusterRoleBinding',
            'apiVersion': 'rbac.authorization.k8s.io/v1',
            'metadata': {
                'name': f'{operator_name}-installer-clusterrolebinding'
            },
            'subjects': [{
                'kind': 'ServiceAccount',
                'name': f'{operator_name}-installer',
                'namespace': namespace
            }],
            'roleRef': {
                'apiGroup': 'rbac.authorization.k8s.io',
                'kind': 'ClusterRole',
                'name': f'{operator_name}-installer-clusterrole'
            }
        }
        
        grantor_binding = {
            'kind': 'ClusterRoleBinding',
            'apiVersion': 'rbac.authorization.k8s.io/v1',
            'metadata': {
                'name': f'{operator_name}-installer-rbac-clusterrolebinding'
            },
            'subjects': [{
                'kind': 'ServiceAccount',
                'name': f'{operator_name}-installer',
                'namespace': namespace
            }],
            'roleRef': {
                'apiGroup': 'rbac.authorization.k8s.io',
                'kind': 'ClusterRole',
                'name': f'{operator_name}-installer-rbac-clusterrole'
            }
        }
        
        combined_yaml = yaml.dump(operator_binding, default_flow_style=False)
        combined_yaml += "---\n"
        combined_yaml += yaml.dump(grantor_binding, default_flow_style=False)
        
        return combined_yaml
    
    def generate_cluster_extension(self, operator_name: str, namespace: str, 
                                 metadata: Dict[str, Any]) -> str:
        """Generate ClusterExtension YAML"""
        cluster_extension = {
            'apiVersion': 'olm.operatorframework.io/v1',
            'kind': 'ClusterExtension',
            'metadata': {
                'name': operator_name
            },
            'spec': {
                'namespace': namespace,
                'serviceAccount': {
                    'name': f'{operator_name}-installer'
                },
                'source': {
                    'catalog': {
                        'channels': ['stable'],  # Default channel
                        'packageName': operator_name,
                        'upgradeConstraintPolicy': 'CatalogProvided'
                    },
                    'sourceType': 'Catalog'
                }
            }
        }
        
        # Add version if available
        version = metadata.get('operator_version')
        if version:
            cluster_extension['spec']['source']['catalog']['version'] = version
        
        return yaml.dump(cluster_extension, default_flow_style=False)
