# OLMv1 API Reference

This document provides comprehensive API documentation for the OLMv1 project components.

## Table of Contents

- [RBAC Manager Tool API](#rbac-manager-tool-api)
- [Helm Chart Values API](#helm-chart-values-api)
- [Kubernetes Resources API](#kubernetes-resources-api)
- [Python Library API](#python-library-api)

## RBAC Manager Tool API

### Command Line Interface

The RBAC Manager tool provides a command-line interface for managing operator RBAC permissions.

#### Global Options

| Option | Description | Type | Default |
|--------|-------------|------|---------|
| `--help`, `-h` | Show help message | flag | - |
| `--version` | Show version information | flag | - |
| `--verbose`, `-v` | Enable verbose logging | flag | false |
| `--examples` | Show usage examples | flag | - |
| `--generate-config` | Generate configuration file | flag | - |

#### OPM Workflow

```bash
python3 rbac_manager.py --opm --image <BUNDLE_IMAGE> [OPTIONS]
```

**Required Arguments:**

- `--opm`: Enable OPM workflow
- `--image <BUNDLE_IMAGE>`: Bundle image reference

**Optional Arguments:**

| Option | Description | Type | Default |
|--------|-------------|------|---------|
| `--helm` | Generate Helm values.yaml | flag | false |
| `--output <DIR>` | Output directory for files | string | stdout |
| `--namespace <NS>` | Target namespace | string | auto-detect |
| `--token <TOKEN>` | Registry authentication token | string | env:OPENSHIFT_TOKEN |
| `--least-privileges` | Apply least privilege principle | flag | false |

**Examples:**

```bash
# Generate Helm values
python3 rbac_manager.py --opm --image quay.io/operatorhubio/argocd-operator:v0.7.0 --helm

# Save to directory
python3 rbac_manager.py --opm --image registry.redhat.io/operator-bundle:latest --output ./rbac-files

# Apply least privileges
python3 rbac_manager.py --opm --image <bundle> --least-privileges
```

#### Catalogd Workflow

```bash
python3 rbac_manager.py --catalogd [OPTIONS]
```

**Required Arguments:**

- `--catalogd`: Enable catalogd workflow

**Optional Arguments:**

| Option | Description | Type | Default |
|--------|-------------|------|---------|
| `--package <NAME>` | Package name to process | string | - |
| `--catalog-name <NAME>` | Catalog name | string | - |
| `--all-packages` | Process all packages | flag | false |
| `--all-namespaces-packages` | Process all namespace packages | flag | false |
| `--helm` | Generate Helm values.yaml | flag | false |
| `--output <DIR>` | Output directory for files | string | stdout |
| `--namespace <NS>` | Target namespace | string | auto-detect |

**Examples:**

```bash
# Process specific package
python3 rbac_manager.py --catalogd --package quay-operator --catalog-name redhat-operators

# Process all packages
python3 rbac_manager.py --catalogd --all-packages --output ./all-rbac
```

#### List Catalogs

```bash
python3 rbac_manager.py --list-catalogs
```

Lists available ClusterCatalog resources in the OpenShift cluster.

### Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | Authentication error |
| 4 | Network/connectivity error |
| 5 | Resource not found |

## Helm Chart Values API

### Chart Configuration

The OLMv1 Helm chart accepts the following values:

#### Operator Configuration

```yaml
operator:
  name: string              # Operator name
  packageName: string       # Package name
  channel: string           # Channel (default: "stable")
  appVersion: string        # Application version (default: "latest")
```

#### Service Account Configuration

```yaml
serviceAccount:
  create: bool              # Create service account (default: true)
  name: string              # Service account name (default: "")
  bind: bool                # Bind to roles (default: true)
  annotations: {}           # Additional annotations
  labels: {}                # Additional labels
```

#### Permissions Configuration

```yaml
permissions:
  clusterRoles:             # Cluster-level roles
    - type: string          # Role type ("operator" or "grantor")
      create: bool          # Create the role (default: true)
      name: string          # Role name (default: "")
      customRules:          # RBAC rules
        - apiGroups: []     # API groups
          resources: []     # Resources
          verbs: []         # Verbs
          resourceNames: [] # Resource names (optional)
          nonResourceURLs: [] # Non-resource URLs (optional)
  
  roles:                    # Namespace-level roles
    - type: string          # Role type ("operator" or "grantor")
      create: bool          # Create the role (default: true)
      name: string          # Role name (default: "")
      customRules:          # RBAC rules (same structure as above)
```

#### Example Values

```yaml
operator:
  name: "quay-operator"
  packageName: "quay-operator.v3.10.13"
  channel: "stable"
  appVersion: "v3.10.13"

serviceAccount:
  create: true
  name: "quay-operator"
  bind: true
  annotations:
    description: "Service account for Quay operator"

permissions:
  clusterRoles:
    - type: "operator"
      create: true
      customRules:
        - apiGroups: [""]
          resources: ["secrets", "configmaps"]
          verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
        - apiGroups: ["apps"]
          resources: ["deployments", "replicasets"]
          verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
```

## Kubernetes Resources API

### Generated Resources

The tool generates the following Kubernetes resources:

#### ServiceAccount

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: <operator-name>
  namespace: <target-namespace>
  labels:
    app.kubernetes.io/name: <operator-name>
    app.kubernetes.io/managed-by: rbac-manager
```

#### ClusterRole

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: <operator-name>-cluster-role
  labels:
    app.kubernetes.io/name: <operator-name>
    app.kubernetes.io/managed-by: rbac-manager
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
```

#### ClusterRoleBinding

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: <operator-name>-cluster-binding
  labels:
    app.kubernetes.io/name: <operator-name>
    app.kubernetes.io/managed-by: rbac-manager
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: <operator-name>-cluster-role
subjects:
  - kind: ServiceAccount
    name: <operator-name>
    namespace: <target-namespace>
```

#### Role (Namespace-scoped)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: <operator-name>-role
  namespace: <target-namespace>
  labels:
    app.kubernetes.io/name: <operator-name>
    app.kubernetes.io/managed-by: rbac-manager
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
```

#### RoleBinding (Namespace-scoped)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: <operator-name>-binding
  namespace: <target-namespace>
  labels:
    app.kubernetes.io/name: <operator-name>
    app.kubernetes.io/managed-by: rbac-manager
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: <operator-name>-role
subjects:
  - kind: ServiceAccount
    name: <operator-name>
    namespace: <target-namespace>
```

## Python Library API

### Core Classes

#### RBACManagerApplication

Main application class that orchestrates the RBAC Manager workflow.

```python
class RBACManagerApplication:
    def __init__(
        self,
        cli_interface: Optional[CLIInterface] = None,
        catalog_ui: Optional[CatalogSelectionUI] = None,
        config_manager: Optional[ConfigManager] = None,
        rule_builder: Optional[RBACRuleBuilder] = None,
        opm_lib: Optional[OPMQueryLib] = None,
        catalog_lib: Optional[CatalogAPIQueryLib] = None,
    ):
        """Initialize the application with optional dependency injection."""
    
    def run(self) -> int:
        """Run the application and return exit code."""
```

#### Data Models

##### RBACResources

```python
@dataclass
class RBACResources:
    """Container for all generated RBAC resources."""
    service_accounts: List[Dict[str, Any]] = field(default_factory=list)
    cluster_roles: List[Dict[str, Any]] = field(default_factory=list)
    cluster_role_bindings: List[Dict[str, Any]] = field(default_factory=list)
    roles: List[Dict[str, Any]] = field(default_factory=list)
    role_bindings: List[Dict[str, Any]] = field(default_factory=list)
    
    def all_resources(self) -> List[Dict[str, Any]]:
        """Return all resources as a flat list."""
```

##### ExecutionContext

```python
@dataclass
class ExecutionContext:
    """Execution context for RBAC Manager operations."""
    opm_mode: bool = False
    catalogd_mode: bool = False
    list_catalogs_mode: bool = False
    bundle_image: Optional[str] = None
    package_name: Optional[str] = None
    catalog_name: Optional[str] = None
    namespace: Optional[str] = None
    output_directory: Optional[str] = None
    helm_mode: bool = False
    insecure: bool = False
    least_privileges: bool = False
    registry_token: Optional[str] = None
```

##### HelmChartValues

```python
@dataclass
class HelmChartValues:
    """Top-level data class for Helm values.yaml structure."""
    operator: HelmOperator
    serviceAccount: HelmServiceAccount = field(default_factory=HelmServiceAccount)
    permissions: HelmPermissions = field(default_factory=HelmPermissions)
    
    def to_yaml(self, security_header: str = "") -> str:
        """Convert to YAML string with optional security header."""
```

### Utility Functions

#### Discovery Functions

```python
def discover_bundles_via_opm(
    bundle_image: str, 
    package_name: Optional[str] = None, 
    insecure: bool = False
) -> List[str]:
    """Discover bundle URLs via OPM."""

def discover_bundles_via_catalogd(
    api_url: str,
    catalog_name: str,
    package_name: Optional[str] = None,
    insecure: bool = False
) -> List[str]:
    """Discover bundle URLs via catalogd API."""
```

#### Conversion Functions

```python
def from_dict(data_class: Type[T], data: Dict) -> T:
    """Create dataclass instance from dictionary recursively."""

def create_flow_style_yaml_dumper():
    """Create PyYAML dumper with flow-style formatting for RBAC rules."""
```

### Error Handling

#### Custom Exceptions

```python
class RBACConverterError(Exception):
    """Base exception for RBAC conversion errors."""

class BundleProcessorError(Exception):
    """Exception for bundle processing errors."""

class DiscoveryError(Exception):
    """Exception for discovery-related errors."""
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENSHIFT_TOKEN` | OpenShift authentication token | - |
| `KUBECONFIG` | Path to kubeconfig file | `~/.kube/config` |
| `OPM_CACHE_DIR` | OPM cache directory | `/tmp/opm-cache` |

## Response Formats

### JSON Output

When using programmatic interfaces, responses follow this structure:

```json
{
  "success": true,
  "data": {
    "resources": [...],
    "metadata": {
      "package_name": "operator-name",
      "namespace": "target-namespace",
      "resource_count": 5
    }
  },
  "errors": []
}
```

### Error Response

```json
{
  "success": false,
  "data": null,
  "errors": [
    {
      "code": "BUNDLE_NOT_FOUND",
      "message": "Bundle image not found",
      "details": {
        "image": "registry.example.com/bundle:latest"
      }
    }
  ]
}
```

## Version Compatibility

| Tool Version | Kubernetes | OpenShift | Python | Helm |
|--------------|------------|-----------|--------|------|
| 1.0.x | 1.24+ | 4.10+ | 3.8+ | 3.x |
| 1.1.x | 1.25+ | 4.11+ | 3.9+ | 3.x |

## Rate Limits

- **OPM Operations**: No built-in rate limiting
- **Catalogd API**: Respects standard Kubernetes API rate limits
- **Registry Operations**: Depends on registry configuration

## Security Considerations

- **Registry Authentication**: Use secure token storage
- **RBAC Permissions**: Follow least privilege principle
- **Network Security**: Use TLS for all communications
- **Secret Management**: Avoid logging sensitive information

For more detailed information, see the [README.md](../README.md) file.
