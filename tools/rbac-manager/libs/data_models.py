"""
Data Models Module.

This module defines typed data structures using Python dataclasses to improve
type safety, IDE support, and code maintainability. It replaces generic Dict[str, Any]
usage with strongly typed models for core data structures.

Key Benefits:
- Type safety and IDE autocompletion
- Protection against typos in field names
- Clear documentation of data structure
- Better maintainability and debugging
"""

from dataclasses import dataclass, field, asdict, fields, is_dataclass, MISSING
from typing import List, Dict, Optional, Any, Union, Type, TypeVar
from enum import Enum
import argparse

# Generic type variable for from_dict helper
T = TypeVar('T')


def from_dict(data_class: Type[T], data: Dict[str, Any]) -> T:
    """
    Recursively creates a dataclass instance from a dictionary.
    
    This is a dependency-free alternative to Pydantic's .model_validate() that
    automatically handles nested dataclasses and provides clean serialization.
    
    Args:
        data_class: The target dataclass type to create
        data: Dictionary containing the data to populate the dataclass
        
    Returns:
        Instance of the specified dataclass populated with the provided data
        
    Example:
        >>> @dataclass
        ... class Person:
        ...     name: str
        ...     age: int
        >>> person = from_dict(Person, {"name": "Alice", "age": 30})
        >>> person.name
        'Alice'
    """
    if not is_dataclass(data_class):
        raise ValueError(f"{data_class} is not a dataclass")
    
    if not isinstance(data, dict):
        raise ValueError("data must be a dictionary")
    
    # Get all fields for the dataclass
    field_values = {}
    
    for field_obj in fields(data_class):
        field_name = field_obj.name
        field_type = field_obj.type
        
        if field_name in data:
            field_value = data[field_name]
            
            # Handle nested dataclasses recursively
            if is_dataclass(field_type) and isinstance(field_value, dict):
                field_values[field_name] = from_dict(field_type, field_value)
            # Handle lists of dataclasses
            elif (hasattr(field_type, '__origin__') and 
                  field_type.__origin__ is list and 
                  len(field_type.__args__) > 0 and 
                  is_dataclass(field_type.__args__[0]) and 
                  isinstance(field_value, list)):
                nested_type = field_type.__args__[0]
                field_values[field_name] = [
                    from_dict(nested_type, item) if isinstance(item, dict) else item
                    for item in field_value
                ]
            else:
                field_values[field_name] = field_value
        elif field_obj.default is not field_obj.default_factory:
            # Field has a default value, use it
            continue
        elif field_obj.default_factory is not MISSING:
            # Field has a default factory, use it
            continue
        else:
            # Field is required but not provided
            # Let dataclass constructor handle the error
            pass
    
    return data_class(**field_values)


class ResourceScope(Enum):
    """Scope of RBAC resources."""
    CLUSTER = "cluster"
    NAMESPACE = "namespace"


class ServiceAccountType(Enum):
    """Type of service account."""
    INSTALLER = "installer" 
    CONTROLLER = "controller"


@dataclass
class DiscoveryResult:
    """Result of a bundle discovery operation."""
    method: str  # Discovery method used (e.g., "opm", "catalogd")
    bundle_urls: List[str]
    metadata: Dict[str, Any]
    success: bool
    error_message: Optional[str] = None


@dataclass
class PermissionRule:
    """
    Represents a single RBAC permission rule.
    
    This corresponds to a rule in a Kubernetes Role or ClusterRole.
    """
    api_groups: List[str] = field(default_factory=list)
    resources: List[str] = field(default_factory=list)
    verbs: List[str] = field(default_factory=list)
    resource_names: Optional[List[str]] = None
    non_resource_urls: Optional[List[str]] = None
    
    # to_dict() method removed - use dataclasses.asdict() instead


@dataclass
class PermissionSet:
    """
    Represents a set of permission rules with an associated service account.
    
    This corresponds to a permissions or clusterPermissions section in a CSV.
    """
    service_account_name: str
    rules: List[PermissionRule] = field(default_factory=list)
    
    # to_dict() method removed - use dataclasses.asdict() instead


@dataclass 
class RBACData:
    """
    Extracted RBAC data from a ClusterServiceVersion.
    
    This represents the parsed RBAC permissions from CSV install strategy.
    """
    permissions: List[PermissionSet] = field(default_factory=list)
    cluster_permissions: List[PermissionSet] = field(default_factory=list) 
    service_account_name: Optional[str] = None
    deployments: List[Dict[str, Any]] = field(default_factory=list)
    
    # to_dict() method removed - use dataclasses.asdict() instead


@dataclass
class OperatorMetadata:
    """
    Metadata about an operator extracted from CSV.
    """
    name: str
    display_name: Optional[str] = None
    version: Optional[str] = None
    provider: Optional[str] = None
    description: Optional[str] = None
    keywords: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    
    # to_dict() method removed - use dataclasses.asdict() instead


@dataclass
class CSVManifest:
    """
    Represents a ClusterServiceVersion manifest.
    
    This is a typed wrapper around CSV data with strongly typed access
    to commonly used fields while preserving the raw manifest data.
    """
    api_version: str
    kind: str
    metadata: Dict[str, Any]
    spec: Dict[str, Any]
    raw_manifest: Dict[str, Any] = field(default_factory=dict)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CSVManifest':
        """Create CSVManifest from dictionary data."""
        return cls(
            api_version=data.get('apiVersion', ''),
            kind=data.get('kind', ''),
            metadata=data.get('metadata', {}),
            spec=data.get('spec', {}),
            raw_manifest=data
        )
    
    @property
    def name(self) -> str:
        """Get CSV name from metadata."""
        return self.metadata.get('name', '')
    
    @property  
    def version(self) -> str:
        """Get CSV version from spec."""
        return self.spec.get('version', '')
    
    @property
    def display_name(self) -> str:
        """Get display name from spec."""
        return self.spec.get('displayName', '')
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert back to dictionary format (returns raw manifest data)."""
        return self.raw_manifest


@dataclass
class BundleData:
    """
    Represents data from OPM render of a bundle image.
    
    Contains all manifests from the bundle with typed access to common fields.
    """
    documents: List[Dict[str, Any]] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    @classmethod 
    def from_dict(cls, data: Dict[str, Any]) -> 'BundleData':
        """Create BundleData from dictionary data."""
        return cls(
            documents=data.get('documents', []),
            raw_data=data
        )
    
    def get_csv(self) -> Optional[CSVManifest]:
        """Extract CSV manifest from bundle documents."""
        for doc in self.documents:
            if (doc.get('kind') == 'ClusterServiceVersion' and 
                doc.get('apiVersion', '').startswith('operators.coreos.com/')):
                return CSVManifest.from_dict(doc)
        return None
    
    def get_manifests_by_kind(self, kind: str) -> List[Dict[str, Any]]:
        """Get all manifests of a specific kind."""
        return [doc for doc in self.documents if doc.get('kind') == kind]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert back to dictionary format (returns raw data)."""
        return self.raw_data


@dataclass
class KubernetesResource:
    """
    Represents a Kubernetes resource with metadata.
    """
    api_version: str
    kind: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    spec: Optional[Dict[str, Any]] = None
    data: Optional[Dict[str, Any]] = None  # For ConfigMaps/Secrets
    rules: Optional[List[Dict[str, Any]]] = None  # For Roles/ClusterRoles
    subjects: Optional[List[Dict[str, Any]]] = None  # For Bindings
    role_ref: Optional[Dict[str, Any]] = None  # For Bindings
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary format for YAML generation.
        
        Note: This method has custom logic to exclude None fields,
        so it's preserved instead of using asdict().
        """
        resource = {
            'apiVersion': self.api_version,
            'kind': self.kind,
            'metadata': self.metadata
        }
        
        if self.spec is not None:
            resource['spec'] = self.spec
        if self.data is not None:
            resource['data'] = self.data
        if self.rules is not None:
            resource['rules'] = self.rules
        if self.subjects is not None:
            resource['subjects'] = self.subjects
        if self.role_ref is not None:
            resource['roleRef'] = self.role_ref
            
        return resource


@dataclass
class RBACResources:
    """
    Collection of Kubernetes RBAC resources.
    
    This represents the final output of RBAC processing with all
    the Kubernetes resources needed for deployment.
    """
    service_accounts: List[KubernetesResource] = field(default_factory=list)
    cluster_roles: List[KubernetesResource] = field(default_factory=list)
    roles: List[KubernetesResource] = field(default_factory=list)
    cluster_role_bindings: List[KubernetesResource] = field(default_factory=list)
    role_bindings: List[KubernetesResource] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary format for backward compatibility.
        
        Note: This method has custom logic to handle mixed resource types,
        so it's preserved instead of using asdict().
        """
        def _convert_resource(resource):
            """Convert resource to dict, handling both KubernetesResource objects and plain dicts."""
            if hasattr(resource, 'to_dict'):
                return resource.to_dict()
            elif isinstance(resource, dict):
                return resource
            else:
                return resource
        
        return {
            'serviceAccounts': [_convert_resource(sa) for sa in self.service_accounts],
            'clusterRoles': [_convert_resource(cr) for cr in self.cluster_roles], 
            'roles': [_convert_resource(r) for r in self.roles],
            'clusterRoleBindings': [_convert_resource(crb) for crb in self.cluster_role_bindings],
            'roleBindings': [_convert_resource(rb) for rb in self.role_bindings]
        }
    
    def all_resources(self) -> List[KubernetesResource]:
        """Get all resources as a flat list."""
        return (self.service_accounts + self.cluster_roles + self.roles + 
                self.cluster_role_bindings + self.role_bindings)


# Duplicate HelmChartValues removed - using the complete version below


@dataclass
class ProcessingContext:
    """
    Context data used during RBAC processing.
    
    This consolidates various context information passed between
    processing methods to reduce parameter passing complexity.
    """
    package_name: str
    operator_metadata: OperatorMetadata
    namespace_template: str  # Should be set based on operation context (Helm vs YAML)
    deployment_names: List[str] = field(default_factory=list)
    service_account_names: List[str] = field(default_factory=list) 
    service_names: List[str] = field(default_factory=list)
    configmap_names: List[str] = field(default_factory=list)
    csv_data: Optional[CSVManifest] = None
    bundle_data: Optional[BundleData] = None
    
    # to_dict() method removed - use dataclasses.asdict() instead


# Helper functions for converting between dict and dataclass formats

def dict_to_permission_rules(rules_data: List[Dict[str, Any]]) -> List[PermissionRule]:
    """Convert list of rule dictionaries to PermissionRule objects."""
    return [
        PermissionRule(
            api_groups=rule.get('apiGroups', []),
            resources=rule.get('resources', []), 
            verbs=rule.get('verbs', []),
            resource_names=rule.get('resourceNames'),
            non_resource_urls=rule.get('nonResourceURLs')
        )
        for rule in rules_data
    ]


def dict_to_permission_sets(perms_data: List[Dict[str, Any]]) -> List[PermissionSet]:
    """Convert list of permission dictionaries to PermissionSet objects."""
    return [
        PermissionSet(
            service_account_name=perm.get('serviceAccountName', ''),
            rules=dict_to_permission_rules(perm.get('rules', []))
        )
        for perm in perms_data
    ]


def dict_to_rbac_data(data: Dict[str, Any]) -> RBACData:
    """Convert RBAC dictionary to RBACData object."""
    return RBACData(
        permissions=dict_to_permission_sets(data.get('permissions', [])),
        cluster_permissions=dict_to_permission_sets(data.get('clusterPermissions', [])),
        service_account_name=data.get('serviceAccountName'),
        deployments=data.get('deployments', [])
    )


# =============================================================================
# Helm Values Dataclasses - For operator-olmv1 chart values.yaml structure
# =============================================================================

@dataclass
class HelmRBACRule:
    """Represents an RBAC rule in Helm values format."""
    apiGroups: List[str] = field(default_factory=list)
    resources: List[str] = field(default_factory=list) 
    verbs: List[str] = field(default_factory=list)
    resourceNames: Optional[List[str]] = None
    nonResourceURLs: Optional[List[str]] = None

    # to_dict() method removed - use dataclasses.asdict() instead

    # from_dict() method removed - use generic from_dict() function instead


@dataclass
class HelmRoleDefinition:
    """Represents a Role or ClusterRole definition in Helm values."""
    name: str = ""
    type: str = "operator"  # 'operator' or 'grantor'
    create: bool = True
    customRules: List[HelmRBACRule] = field(default_factory=list)

    # to_dict() method removed - use dataclasses.asdict() instead

    # from_dict() method removed - use generic from_dict() function instead


@dataclass
class HelmPermissions:
    """Represents the permissions section in Helm values."""
    clusterRoles: List[HelmRoleDefinition] = field(default_factory=list)
    roles: Optional[List[HelmRoleDefinition]] = None

    # to_dict() method removed - use dataclasses.asdict() instead

    # from_dict() method removed - use generic from_dict() function instead


@dataclass
class HelmServiceAccount:
    """Represents the serviceAccount section in Helm values."""
    create: bool = True
    name: str = ""
    bind: bool = True
    annotations: Dict[str, str] = field(default_factory=dict)
    labels: Dict[str, str] = field(default_factory=dict)

    # to_dict() method removed - use dataclasses.asdict() instead

    # from_dict() method removed - use generic from_dict() function instead


@dataclass
class HelmOperator:
    """Represents the operator section in Helm values."""
    name: str = ""
    appVersion: str = "latest"
    channel: str = "stable"
    packageName: str = ""

    # to_dict() method removed - use dataclasses.asdict() instead

    # from_dict() method removed - use generic from_dict() function instead


@dataclass
class HelmChartValues:
    """
    Represents the complete Helm values.yaml structure for operator-olmv1 chart.
    
    This is the top-level data structure that mirrors the operator-olmv1 Helm chart's
    values.yaml format for RBAC resources.
    """
    operator: HelmOperator = field(default_factory=HelmOperator)
    serviceAccount: HelmServiceAccount = field(default_factory=HelmServiceAccount)
    permissions: HelmPermissions = field(default_factory=HelmPermissions)
    
    # to_dict() method removed - now uses dataclasses.asdict() in to_yaml()

    def to_yaml(self, security_header: str = "") -> str:
        """Convert to YAML string with optional security header and flow-style RBAC rules."""
        import yaml
        from .core_utils import create_flow_style_yaml_dumper
        
        # Use the flow-style dumper for RBAC rules
        FlowStyleDumper = create_flow_style_yaml_dumper()
        
        yaml_content = yaml.dump(asdict(self), Dumper=FlowStyleDumper, 
                               default_flow_style=False, indent=2, sort_keys=False)
        
        if security_header:
            return security_header + "\n" + yaml_content
        return yaml_content

    # from_dict() method removed - use generic from_dict() function instead


# =============================================================================
# Execution Context - Decouples business logic from CLI interface
# =============================================================================

@dataclass
class ExecutionContext:
    """
    Execution context for a single run of the RBAC Manager tool.
    
    This dataclass decouples business logic from the CLI interface by providing
    a clean, typed context object instead of passing around argparse.Namespace.
    All configuration and parameters for a single execution are contained here.
    """
    # Operation mode flags
    opm_mode: bool = False
    catalogd_mode: bool = False
    list_catalogs_mode: bool = False
    
    # Core operation parameters
    bundle_image: Optional[str] = None
    package_name: Optional[str] = None
    catalog_name: Optional[str] = None
    
    # OpenShift/Kubernetes connection
    openshift_url: Optional[str] = None
    openshift_token: Optional[str] = None
    openshift_namespace: Optional[str] = None
    
    # Catalogd service configuration
    catalogd_namespace: str = "openshift-catalogd"
    catalogd_service: str = "catalogd"
    local_port: int = 8080
    
    # Output configuration
    output_mode: str = "stdout"  # "stdout", "directory", "helm"
    output_directory: Optional[str] = None
    helm_mode: bool = False
    
    # Security and authentication
    insecure: bool = False
    registry_token: Optional[str] = None
    
    # Operation flags
    all_namespaces_packages: bool = False
    show_examples: bool = False
    verbose: bool = False
    least_privileges: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for serialization/debugging.
        
        Note: This method has custom logic to mask sensitive data,
        so it's preserved instead of using asdict().
        """
        return {
            'operation_mode': self.get_operation_mode(),
            'opm_mode': self.opm_mode,
            'catalogd_mode': self.catalogd_mode,
            'list_catalogs_mode': self.list_catalogs_mode,
            'bundle_image': self.bundle_image,
            'package_name': self.package_name,
            'catalog_name': self.catalog_name,
            'openshift_url': self.openshift_url,
            'openshift_token': '***' if self.openshift_token else None,
            'openshift_namespace': self.openshift_namespace,
            'catalogd_namespace': self.catalogd_namespace,
            'catalogd_service': self.catalogd_service,
            'local_port': self.local_port,
            'output_mode': self.output_mode,
            'output_directory': self.output_directory,
            'helm_mode': self.helm_mode,
            'insecure': self.insecure,
            'registry_token': '***' if self.registry_token else None,
            'all_namespaces_packages': self.all_namespaces_packages,
            'show_examples': self.show_examples,
            'verbose': self.verbose,
            'least_privileges': self.least_privileges
        }
    
    def get_operation_mode(self) -> str:
        """Get the primary operation mode as a string."""
        if self.list_catalogs_mode:
            return "list_catalogs"
        elif self.opm_mode:
            return "opm"
        elif self.catalogd_mode:
            return "catalogd"
        else:
            return "unknown"
    
    def get_target_namespace(self) -> str:
        """Get the target namespace, with fallback to 'default'."""
        return self.openshift_namespace or "default"
    
    def is_helm_output(self) -> bool:
        """Check if output should be in Helm values format."""
        return self.helm_mode or self.output_mode == "helm"
    
    def is_directory_output(self) -> bool:
        """Check if output should be saved to directory."""
        return self.output_directory is not None or self.output_mode == "directory"
    
    def validate(self) -> List[str]:
        """
        Validate the execution context and return list of validation errors.
        
        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []
        
        # Check that exactly one operation mode is selected
        modes = [self.opm_mode, self.catalogd_mode, self.list_catalogs_mode]
        active_modes = sum(modes)
        
        if active_modes == 0:
            errors.append("No operation mode specified (--opm, --catalogd, or --list-catalogs)")
        elif active_modes > 1:
            errors.append("Multiple operation modes specified - choose only one")
        
        # OPM mode validations
        if self.opm_mode and not self.bundle_image:
            errors.append("OPM mode requires --image flag with bundle image URL")
        
        # Catalogd mode validations
        if self.catalogd_mode and not self.package_name:
            errors.append("Catalogd mode requires --package flag with package name")
        
        # Output validations
        if self.is_directory_output() and self.is_helm_output():
            errors.append("Cannot specify both directory output and Helm output")
        
        # Port validation
        if not (1 <= self.local_port <= 65535):
            errors.append(f"Invalid port number: {self.local_port}")
        
        return errors
    
    @classmethod
    def from_args(cls, args: argparse.Namespace) -> 'ExecutionContext':
        """
        Create ExecutionContext from argparse.Namespace.
        
        This factory method handles the conversion from CLI arguments
        to a clean, typed execution context.
        """
        # Determine output mode
        output_mode = "stdout"  # default
        output_directory = None
        helm_mode = False
        
        if hasattr(args, 'helm') and args.helm:
            output_mode = "helm"
            helm_mode = True
        elif hasattr(args, 'output') and args.output:
            output_mode = "directory"
            output_directory = args.output
        
        return cls(
            # Operation modes
            opm_mode=getattr(args, 'opm', False),
            catalogd_mode=getattr(args, 'catalogd', False),
            list_catalogs_mode=getattr(args, 'list_catalogs', False),
            
            # Core parameters
            bundle_image=getattr(args, 'image', None),
            package_name=getattr(args, 'package', None),
            catalog_name=getattr(args, 'catalog_name', None),
            
            # OpenShift connection
            openshift_url=getattr(args, 'openshift_url', None),
            openshift_token=getattr(args, 'openshift_token', None),
            openshift_namespace=getattr(args, 'openshift_namespace', None),
            
            # Catalogd configuration
            catalogd_namespace=getattr(args, 'catalogd_namespace', 'openshift-catalogd'),
            catalogd_service=getattr(args, 'catalogd_service', 'catalogd'),
            local_port=getattr(args, 'local_port', 8080),
            
            # Output configuration
            output_mode=output_mode,
            output_directory=output_directory,
            helm_mode=helm_mode,
            
            # Security
            insecure=getattr(args, 'insecure', False),
            registry_token=getattr(args, 'registry_token', None),
            
            # Flags
            all_namespaces_packages=getattr(args, 'all_namespaces_packages', False),
            show_examples=getattr(args, 'examples', False),
            verbose=getattr(args, 'verbose', False),
            least_privileges=getattr(args, 'least_privileges', False)
        )
