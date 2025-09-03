#!/usr/bin/env python3
"""
Shared RBAC Utilities.

This module provides common RBAC processing functions shared between
OPM and ClusterCatalog query libraries.
"""

from typing import Dict, List, Optional, Any


def get_csv_metadata(bundle: Dict) -> Optional[Dict]:
    """
    Extract CSV metadata from bundle.
    
    Args:
        bundle: Bundle data (from either OPM or ClusterCatalog)
        
    Returns:
        CSV metadata or None if not found
    """
    properties = bundle.get('properties', [])
    for prop in properties:
        if prop.get('type') == 'olm.csv.metadata':
            return prop.get('value', {})
    return None


def extract_service_account(install_spec: Dict, rbac_data: Dict) -> None:
    """
    Extract service account from install spec.
    
    Args:
        install_spec: Install specification from CSV
        rbac_data: RBAC data dictionary to update
    """
    if 'spec' in install_spec:
        sa = install_spec['spec'].get('serviceAccountName')
        if sa and not rbac_data.get('serviceAccount'):
            rbac_data['serviceAccount'] = sa


def extract_permissions(install_spec: Dict, rbac_data: Dict) -> None:
    """
    Extract permissions from install spec.
    
    Args:
        install_spec: Install specification from CSV
        rbac_data: RBAC data dictionary to update
    """
    spec = install_spec.get('spec', {})
    rbac_data['permissions'].extend(spec.get('permissions', []))
    rbac_data['clusterPermissions'].extend(spec.get('clusterPermissions', []))


def convert_to_k8s_resources(raw_rbac: Dict, package_name: str) -> Dict:
    """
    Convert raw RBAC permissions to Kubernetes YAML structures.
    
    Args:
        raw_rbac: Raw RBAC data with permissions arrays
        package_name: Package name for consistent resource naming
        
    Returns:
        Dict with clusterRoles, roles, and serviceAccount
    """
    rbac_resources = {
        'clusterRoles': [],
        'roles': [],
        'serviceAccount': raw_rbac.get('serviceAccount', f'{package_name}-sa')
    }
    
    # Process namespace-scoped permissions (Roles)
    for perm in raw_rbac.get('permissions', []):
        role = {
            'apiVersion': 'rbac.authorization.k8s.io/v1',
            'kind': 'Role',
            'metadata': {
                'name': f"{package_name}-role",  # Use package name for consistency
                'namespace': '{{ .Release.Namespace }}'  # Helm template
            },
            'rules': perm.get('rules', [])
        }
        rbac_resources['roles'].append(role)
    
    # Process cluster-scoped permissions (ClusterRoles)
    for perm in raw_rbac.get('clusterPermissions', []):
        cluster_role = {
            'apiVersion': 'rbac.authorization.k8s.io/v1',
            'kind': 'ClusterRole',
            'metadata': {
                'name': f"{package_name}-cluster-role"  # Use package name for consistency
            },
            'rules': perm.get('rules', [])
        }
        rbac_resources['clusterRoles'].append(cluster_role)
    
    return rbac_resources


def extract_rbac_from_bundles(bundles: List[Dict], package_name: str) -> Optional[Dict]:
    """
    Extract RBAC resources from operator bundles.
    
    This is the main extraction function that both libraries can use.
    
    Args:
        bundles: List of operator bundles
        package_name: Package name for consistent resource naming
        
    Returns:
        Dict with clusterRoles, roles, and serviceAccount, or None if no RBAC found
    """
    if not bundles:
        return None
    
    raw_rbac = {
        'clusterPermissions': [],
        'permissions': [],
        'serviceAccount': None
    }
    
    # Extract raw permissions from bundles
    for bundle in bundles:
        csv_data = get_csv_metadata(bundle)
        if csv_data:
            install_spec = csv_data.get('spec', {}).get('install', {})
            extract_service_account(install_spec, raw_rbac)
            extract_permissions(install_spec, raw_rbac)
    
    # Return None if no permissions found
    if not (raw_rbac['permissions'] or raw_rbac['clusterPermissions']):
        return None
    
    # Convert raw permissions to Kubernetes YAML structures
    return convert_to_k8s_resources(raw_rbac, package_name)


# Helper functions for specific checks (used by catalog library)
def has_all_namespaces_support(csv_data: Dict) -> bool:
    """
    Check if CSV supports AllNamespaces install mode.
    
    Args:
        csv_data: CSV metadata
        
    Returns:
        True if AllNamespaces is supported
    """
    install_modes = csv_data.get('spec', {}).get('installModes', [])
    for mode in install_modes:
        if (mode.get('type') == 'AllNamespaces' and 
            mode.get('supported') is True):
            return True
    return False


def has_webhooks(bundle_entry: Dict) -> bool:
    """
    Check if bundle has webhook definitions.
    
    Args:
        bundle_entry: Bundle entry data
        
    Returns:
        True if webhooks are defined
    """
    webhook_defs = bundle_entry.get('spec', {}).get('webhookdefinitions')
    return bool(webhook_defs)
