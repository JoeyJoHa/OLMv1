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
    import logging
    logger = logging.getLogger(__name__)
    
    if not bundles:
        logger.warning(f"No bundles provided for package: {package_name}")
        return None
    
    logger.info(f"Processing {len(bundles)} bundle(s) for RBAC extraction")
    
    raw_rbac = {
        'clusterPermissions': [],
        'permissions': [],
        'serviceAccount': None
    }
    
    # Extract raw permissions from bundles
    bundles_processed = 0
    csv_found_count = 0
    
    for i, bundle in enumerate(bundles):
        logger.debug(f"Processing bundle {i+1}/{len(bundles)}")
        
        # Diagnostic: Log bundle structure
        bundle_keys = list(bundle.keys())
        logger.debug(f"Bundle keys: {bundle_keys}")
        
        csv_data = get_csv_metadata(bundle)
        if csv_data:
            csv_found_count += 1
            logger.debug(f"CSV metadata found in bundle {i+1}")
            
            # Check install specification
            install_spec = csv_data.get('spec', {}).get('install', {})
            if not install_spec:
                logger.debug(f"No install specification in CSV for bundle {i+1}")
                continue
            
            logger.debug(f"Install spec keys: {list(install_spec.keys())}")
            
            # Extract service account and permissions
            before_sa = raw_rbac['serviceAccount']
            before_perms = len(raw_rbac['permissions'])
            before_cluster_perms = len(raw_rbac['clusterPermissions'])
            
            extract_service_account(install_spec, raw_rbac)
            extract_permissions(install_spec, raw_rbac)
            
            # Log what was extracted
            sa_added = raw_rbac['serviceAccount'] != before_sa
            perms_added = len(raw_rbac['permissions']) - before_perms
            cluster_perms_added = len(raw_rbac['clusterPermissions']) - before_cluster_perms
            
            logger.debug(f"From bundle {i+1}: SA added: {sa_added}, Perms: +{perms_added}, ClusterPerms: +{cluster_perms_added}")
            bundles_processed += 1
        else:
            logger.debug(f"No CSV metadata found in bundle {i+1}")
            # Log bundle properties to understand structure
            properties = bundle.get('properties', [])
            prop_types = [p.get('type') for p in properties]
            logger.debug(f"Bundle {i+1} property types: {prop_types}")
    
    # Diagnostic summary
    logger.info(f"RBAC extraction summary:")
    logger.info(f"   Bundles processed: {bundles_processed}/{len(bundles)}")
    logger.info(f"   CSVs found: {csv_found_count}")
    logger.info(f"   Service accounts: {1 if raw_rbac['serviceAccount'] else 0}")
    logger.info(f"   Permissions: {len(raw_rbac['permissions'])}")
    logger.info(f"   Cluster permissions: {len(raw_rbac['clusterPermissions'])}")
    
    # Return None if no permissions found
    if not (raw_rbac['permissions'] or raw_rbac['clusterPermissions']):
        logger.warning(f"No RBAC permissions found for package '{package_name}'")
        logger.warning(f"Possible reasons:")
        logger.warning(f"   - The operator doesn't require special permissions")
        logger.warning(f"   - The bundle format is not OLMv1 compatible") 
        logger.warning(f"   - The CSV install specification is missing or malformed")
        logger.warning(f"   - The bundle metadata structure is different than expected")
        return None
    
    logger.info(f"Successfully extracted RBAC for package '{package_name}'")
    
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
