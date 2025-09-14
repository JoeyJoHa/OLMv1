"""
Helm Generator

Generates Helm values files for OLMv1 operators.
"""

import yaml
from typing import Dict, Any


class HelmGenerator:
    """Generates Helm values for OLMv1 operators"""
    
    def __init__(self):
        pass
    
    def generate_helm_values(self, metadata: Dict[str, Any], operator_name: str = None, least_privileges: bool = False) -> Dict[str, str]:
        """Generate Helm values files"""
        if not operator_name:
            operator_name = metadata.get('operator_name', 'operator').replace('.', '-')
        
        helm_files = {}
        
        # Generate RBAC-only example
        rbac_only = self.generate_rbac_only_helm_values(operator_name, metadata, least_privileges)
        helm_files['rbac-only-example.yaml'] = rbac_only
        
        # Generate full operator values
        operator_values = self.generate_operator_helm_values(operator_name, metadata, least_privileges)
        helm_files[f'values-{operator_name}.yaml'] = operator_values
        
        return helm_files
    
    def generate_rbac_only_helm_values(self, operator_name: str, metadata: Dict[str, Any], least_privileges: bool = False) -> str:
        """Generate RBAC-only Helm values"""
        rbac_rules = metadata.get('rbac_rules', [])
        
        # Split rules into operator and grantor categories
        operator_rules = [
            {
                'apiGroups': ['olm.operatorframework.io'],
                'resources': ['clusterextensions/finalizers'],
                'verbs': ['update']
            },
            {
                'apiGroups': ['apiextensions.k8s.io'],
                'resources': ['customresourcedefinitions'],
                'verbs': ['create', 'list', 'watch', 'get', 'update', 'patch', 'delete']
            },
            {
                'apiGroups': ['rbac.authorization.k8s.io'],
                'resources': ['clusterroles', 'clusterrolebindings'],
                'verbs': ['create', 'list', 'watch', 'get', 'update', 'patch', 'delete']
            }
        ]
        
        values = {
            'operator': {
                'name': operator_name,
                'create': False,
                'appVersion': metadata.get('operator_version', '1.0.0'),
                'channel': 'stable',
                'packageName': operator_name
            },
            'serviceAccount': {
                'create': True,
                'name': '',
                'bind': True,
                'annotations': {
                    'description': 'Service account for operator RBAC testing'
                },
                'labels': {
                    'purpose': 'rbac-only'
                }
            },
            'permissions': {
                'clusterRoles': [
                    {
                        'name': '',
                        'type': 'operator',
                        'create': True,
                        'customRules': operator_rules
                    },
                    {
                        'name': '',
                        'type': 'grantor',
                        'create': True,
                        'customRules': self._apply_least_privileges_to_rules(rbac_rules, least_privileges)
                    }
                ],
                'roles': [
                    {
                        'name': '',
                        'type': 'operator',
                        'create': True,
                        'customRules': [
                            {
                                'apiGroups': ['apps'],
                                'resources': ['deployments'],
                                'verbs': ['create', 'list', 'watch', 'get', 'update', 'patch', 'delete']
                            },
                            {
                                'apiGroups': [''],
                                'resources': ['serviceaccounts'],
                                'verbs': ['create', 'list', 'watch', 'get', 'update', 'patch', 'delete']
                            }
                        ]
                    }
                ]
            },
            'additionalResources': []
        }
        
        return yaml.dump(values, default_flow_style=False)
    
    def _apply_least_privileges_to_rules(self, rules: list, least_privileges: bool) -> list:
        """Apply least-privilege principles to RBAC rules"""
        if not least_privileges or not rules:
            return rules
        
        processed_rules = []
        for rule in rules:
            if isinstance(rule, dict):
                processed_rule = rule.copy()
                
                # Remove wildcard permissions
                if 'resources' in processed_rule and '*' in processed_rule['resources']:
                    processed_rule['resources'] = [r for r in processed_rule['resources'] if r != '*']
                    if not processed_rule['resources']:
                        processed_rule['resources'] = ['pods', 'services', 'configmaps']
                
                if 'verbs' in processed_rule and '*' in processed_rule['verbs']:
                    processed_rule['verbs'] = [v for v in processed_rule['verbs'] if v != '*']
                    if not processed_rule['verbs']:
                        processed_rule['verbs'] = ['get', 'list', 'watch']
                
                processed_rules.append(processed_rule)
            else:
                processed_rules.append(rule)
        
        return processed_rules
    
    def generate_operator_helm_values(self, operator_name: str, metadata: Dict[str, Any], least_privileges: bool = False) -> str:
        """Generate full operator Helm values"""
        rbac_rules = metadata.get('rbac_rules', [])
        
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
        
        values = {
            'operator': {
                'name': operator_name,
                'create': True,
                'appVersion': metadata.get('operator_version', '1.0.0'),
                'channel': 'stable',
                'packageName': operator_name
            },
            'serviceAccount': {
                'create': True,
                'name': '',
                'bind': True,
                'annotations': {},
                'labels': {}
            },
            'permissions': {
                'clusterRoles': [
                    {
                        'name': '',
                        'type': 'operator',
                        'create': True,
                        'customRules': operator_rules
                    },
                    {
                        'name': '',
                        'type': 'grantor',
                        'create': True,
                        'customRules': self._apply_least_privileges_to_rules(rbac_rules, least_privileges)
                    }
                ],
                'roles': [
                    {
                        'name': '',
                        'type': 'operator',
                        'create': False,
                        'customRules': [
                            {
                                'apiGroups': [''],
                                'resources': ['pods', 'services', 'configmaps', 'secrets'],
                                'verbs': ['*']
                            }
                        ]
                    }
                ]
            },
            'additionalResources': []
        }
        
        return yaml.dump(values, default_flow_style=False)
    
    def _apply_least_privileges_to_rules(self, rules: list, least_privileges: bool) -> list:
        """Apply least-privilege principles to RBAC rules"""
        if not least_privileges or not rules:
            return rules
        
        processed_rules = []
        for rule in rules:
            if isinstance(rule, dict):
                processed_rule = rule.copy()
                
                # Remove wildcard permissions
                if 'resources' in processed_rule and '*' in processed_rule['resources']:
                    processed_rule['resources'] = [r for r in processed_rule['resources'] if r != '*']
                    if not processed_rule['resources']:
                        processed_rule['resources'] = ['pods', 'services', 'configmaps']
                
                if 'verbs' in processed_rule and '*' in processed_rule['verbs']:
                    processed_rule['verbs'] = [v for v in processed_rule['verbs'] if v != '*']
                    if not processed_rule['verbs']:
                        processed_rule['verbs'] = ['get', 'list', 'watch']
                
                processed_rules.append(processed_rule)
            else:
                processed_rules.append(rule)
        
        return processed_rules
