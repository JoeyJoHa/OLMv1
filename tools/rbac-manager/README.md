# RBAC Manager Tool

A comprehensive Python tool for extracting and managing RBAC permissions from operator bundles using the `opm` binary and interacting with OpenShift catalogs via `catalogd`. This tool automates the generation of secure RBAC resources and Helm values for OLMv1 operator deployments.

## Features

- **🔍 Catalog Discovery**: List and query OpenShift ClusterCatalogs for available operators
- **📡 Catalogd Integration**: Port-forward to catalogd service and fetch real-time package information
- **⚙️ Configuration Management**: Generate and reuse configuration files for consistent deployments
- **🌐 Real Cluster Integration**: Extract actual bundle images and metadata from live OpenShift clusters
- **📦 Bundle Analysis**: Extract comprehensive metadata from operator bundle images using `opm render`
- **🔐 Smart RBAC Generation**: Auto-generate secure RBAC resources with intelligent permissions logic:
  - **Both `clusterPermissions` + `permissions`**: ClusterRoles + grantor Roles (e.g., ArgoCD)
  - **Only `permissions`**: Treat as ClusterRoles (e.g., Quay operator)
  - **Only `clusterPermissions`**: ClusterRoles only
- **🧹 DRY Deduplication**: Advanced permission deduplication eliminates redundant rules:
  - Removes duplicate permissions between ClusterRoles and Roles
  - Preserves resource-specific rules with `resourceNames`
  - Handles wildcard permissions intelligently
  - Reduces RBAC complexity and improves security posture
- **🎨 Enhanced YAML Formatting**: FlowStyleList formatting for readable Helm values with channel guidance
- **🏗️ Microservice Architecture**: Clean separation with BundleProcessor orchestrator
- **🛡️ Security Best Practices**: Implements OLMv1 security patterns with comprehensive RBAC optimization
- **📋 Comprehensive Output**: ServiceAccount, ClusterRole, ClusterRoleBinding, Role, RoleBinding manifests
- **🔧 Interactive Mode**: User-friendly prompts for catalog and package selection
- **📊 Debug Logging**: Detailed logging for troubleshooting and analysis

## Prerequisites

### Required Dependencies

Install the required Python packages:

```bash
pip install -r requirements.txt
```

### Required Tools

1. **opm**: Operator Package Manager CLI tool
   - Download from [operator-framework/operator-registry releases](https://github.com/operator-framework/operator-registry/releases)
   - Or install via package manager (e.g., `brew install operator-framework/tap/opm`)

### Kubernetes Access (for catalogd features only)

- **Option 1**: Valid kubeconfig file configured for your OpenShift/Kubernetes cluster
- **Option 2**: Provide OpenShift URL and token for direct API access (`--openshift-url` and `--openshift-token`)

> **💡 Note**: Kubernetes access is only required for catalogd integration (listing catalogs, querying packages). The core `--opm` functionality works offline with just the bundle image URL.

## Tool Structure

```tree
tools/rbac-manager/
├── rbac-manager/                     # Main tool package
│   ├── help/                         # Help text files
│   │   ├── catalogd_examples_help.txt # Catalogd command examples
│   │   ├── catalogd_help.txt         # Catalogd command help
│   │   ├── config_help.txt           # Configuration help
│   │   ├── examples_help.txt         # Comprehensive examples
│   │   ├── generate_config_examples_help.txt # Config generation examples
│   │   ├── list_catalogs_examples_help.txt # List catalogs examples
│   │   ├── list_catalogs_help.txt    # List catalogs help
│   │   ├── main_help.txt             # Main command help
│   │   ├── opm_examples_help.txt     # OPM command examples
│   │   └── opm_help.txt              # OPM command help
│   └── libs/                         # Core libraries
│       ├── catalogd/                 # Catalogd integration
│       │   ├── __init__.py
│       │   ├── cache.py              # Caching functionality
│       │   ├── client.py             # Low-level catalogd client
│       │   ├── parser.py             # Response parsing
│       │   ├── service.py            # High-level service
│       │   └── session.py            # Session management
│       ├── core/                     # Core utilities
│       │   ├── __init__.py
│       │   ├── auth.py               # Authentication handling
│       │   ├── config.py             # Configuration management
│       │   ├── constants.py          # Application constants
│       │   ├── exceptions.py         # Custom exceptions
│       │   ├── protocols.py          # Type protocols
│       │   └── utils.py              # Utility functions
│       ├── opm/                      # OPM integration
│       │   ├── __init__.py
│       │   ├── base_generator.py     # Base generator with DRY deduplication logic
│       │   ├── client.py             # OPM binary client
│       │   ├── helm_generator.py     # Helm values generator (deduplicated)
│       │   ├── processor.py          # Bundle processor
│       │   └── yaml_generator.py     # YAML manifest generator (deduplicated)
│       ├── __init__.py
│       ├── help_manager.py           # Help system manager
│       └── main_app.py               # Main application logic
├── tests/                            # Test suite
│   └── test_catalogd.py              # Catalogd integration tests
├── rbac-manager.py                   # CLI entry point
├── requirements.txt                  # Python dependencies
└── README.md                         # This documentation
```

## Installation

1. Clone the repository and navigate to the tool directory:

   ```bash
   cd tools/rbac-manager
   ```

2. **Create and activate a Python virtual environment** (recommended):

   ```bash
   # Create virtual environment
   python3 -m venv rbac-manager-env
   
   # Activate virtual environment
   # On Linux/macOS:
   source rbac-manager-env/bin/activate
   
   # On Windows:
   # rbac-manager-env\Scripts\activate
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Make the script executable:

   ```bash
   chmod +x rbac-manager.py
   ```

> **💡 Tip**: Always use a virtual environment to avoid conflicts with system Python packages. To deactivate the virtual environment when done, simply run `deactivate`.

## Usage

The RBAC Manager uses a subcommand structure with three main commands: `list-catalogs`, `catalogd`, and `opm`.

### Global Help

```bash
python3 rbac-manager.py --help
```

### Commands

#### 1. List ClusterCatalogs

List all available ClusterCatalogs in your cluster:

```bash
python3 rbac-manager.py list-catalogs --openshift-url https://api.cluster.example.com:6443 --openshift-token sha256~token
```

**Available flags:**

- `--openshift-url URL`: OpenShift cluster URL
- `--openshift-token TOKEN`: OpenShift authentication token  
- `--skip-tls`: Skip TLS verification
- `--debug`: Enable debug logging
- `--examples`: Show usage examples

#### 2. Query Catalogd Service and Generate Configuration

Query the catalogd service for package information and generate configuration files:

**Basic usage with interactive catalog selection:**

```bash
python3 rbac-manager.py catalogd --package quay-operator --openshift-url https://api.cluster.example.com:6443 --openshift-token sha256~token --skip-tls
```

**Query specific catalog packages:**

```bash
python3 rbac-manager.py catalogd --catalog-name openshift-community-operators --openshift-url https://api.cluster.example.com:6443 --openshift-token sha256~token --skip-tls
```

**Query specific package channels:**

```bash
python3 rbac-manager.py catalogd --catalog-name openshift-community-operators --package argocd-operator --openshift-url https://api.cluster.example.com:6443 --openshift-token sha256~token --skip-tls
```

**Query specific channel versions:**

```bash
python3 rbac-manager.py catalogd --catalog-name openshift-community-operators --package argocd-operator --channel alpha --openshift-url https://api.cluster.example.com:6443 --openshift-token sha256~token --skip-tls
```

**Get detailed version metadata:**

```bash
python3 rbac-manager.py catalogd --catalog-name openshift-community-operators --package argocd-operator --channel alpha --version 0.8.0 --openshift-url https://api.cluster.example.com:6443 --openshift-token sha256~token --skip-tls
```

#### 3. Generate Configuration Files

**Generate config template:**

```bash
python3 rbac-manager.py catalogd --generate-config
```

**Generate config with real cluster data (to stdout):**

```bash
python3 rbac-manager.py catalogd --generate-config \
  --catalog-name openshift-community-operators \
  --package argocd-operator --channel alpha --version 0.8.0 \
  --openshift-url https://api.cluster.example.com:6443 \
  --openshift-token sha256~token --skip-tls
```

**Generate config to file:**

```bash
python3 rbac-manager.py catalogd --generate-config \
  --catalog-name openshift-community-operators \
  --package argocd-operator --channel alpha --version 0.8.0 \
  --openshift-url https://api.cluster.example.com:6443 \
  --openshift-token sha256~token --skip-tls \
  --output ./config
```

#### 4. Extract Bundle Metadata and Generate RBAC

Extract metadata from operator bundle images and generate RBAC resources:

**Using configuration file (YAML manifests):**

```bash
python3 rbac-manager.py opm --config rbac-manager-config.yaml
```

**Using configuration file (Helm values) - modify config file to set `output.type: helm`:**

```bash
python3 rbac-manager.py opm --config rbac-manager-config.yaml
```

**Direct bundle extraction (YAML manifests):**

```bash
python3 rbac-manager.py opm --image registry.redhat.io/quay/quay-operator-bundle@sha256:c431ad9dfd69c049e6d9583928630c06b8612879eeed57738fa7be206061fee2
```

**Generate Helm values:**

```bash
python3 rbac-manager.py opm --image registry.redhat.io/quay/quay-operator-bundle@sha256:c431ad9dfd69c049e6d9583928630c06b8612879eeed57738fa7be206061fee2 --helm
```

**With custom namespace:**

```bash
python3 rbac-manager.py opm --image registry.redhat.io/quay/quay-operator-bundle@sha256:c431ad9dfd69c049e6d9583928630c06b8612879eeed57738fa7be206061fee2 --namespace quay-operator
```

**Save to files:**

```bash
python3 rbac-manager.py opm --image registry.redhat.io/quay/quay-operator-bundle@sha256:c431ad9dfd69c049e6d9583928630c06b8612879eeed57738fa7be206061fee2 --output ./rbac-files
```

### Configuration-Based Workflow

```bash
# Step 1: List available catalogs
python3 rbac-manager.py list-catalogs --openshift-url https://api.cluster.example.com:6443 --openshift-token sha256~token --skip-tls

# Step 2: Generate configuration with real cluster data  
python3 rbac-manager.py catalogd --generate-config \
  --catalog-name openshift-community-operators \
  --package argocd-operator --channel alpha --version 0.8.0 \
  --openshift-url https://api.cluster.example.com:6443 \
  --openshift-token sha256~token --skip-tls \
  --output ./config

# Step 3: Extract RBAC using configuration
python3 rbac-manager.py opm --config ./config/rbac-manager-config.yaml

# Step 4: For Helm values, modify config file to set output.type: helm, then:
python3 rbac-manager.py opm --config ./config/rbac-manager-config.yaml
```

### Command-Specific Flags

#### Catalogd Command Flags

- `--catalog-name NAME`: Specify catalog name (interactive prompt if not provided)
- `--package NAME`: Show channels for specific package
- `--channel NAME`: Show versions for specific channel (requires --package)
- `--version VERSION`: Show metadata for specific version (requires --package and --channel)
- `--generate-config`: Generate configuration file (stdout by default)
- `--output DIR`: Output directory for generated config file
- `--openshift-url URL`: OpenShift cluster URL for direct API access
- `--openshift-token TOKEN`: OpenShift authentication token
- `--skip-tls`: Skip TLS verification
- `--debug`: Enable debug logging
- `--examples`: Show usage examples

#### OPM Command Flags

- `--config FILE`: Configuration file path (recommended workflow)
- `--image IMAGE`: Operator bundle image URL (alternative to config)
- `--helm`: Generate Helm values instead of YAML manifests
- `--namespace NAMESPACE`: Target namespace for generated manifests (default: default)
- `--output DIR`: Save output files to directory (default: stdout)
- `--registry-token TOKEN`: Authentication token for private registries
- `--skip-tls`: Skip TLS verification
- `--debug`: Enable debug logging
- `--examples`: Show usage examples

## DRY Deduplication

The RBAC Manager implements advanced **DRY (Don't Repeat Yourself)** deduplication logic to eliminate redundant permissions between ClusterRoles and Roles, resulting in cleaner, more secure RBAC configurations.

### How It Works

1. **Duplicate Detection**: Identifies when Role permissions are already covered by broader ClusterRole permissions
2. **Wildcard Handling**: Recognizes when ClusterRole wildcard permissions (`verbs: ['*']`) supersede specific Role permissions
3. **Resource-Specific Preservation**: Keeps Role rules with `resourceNames` even when broader ClusterRole permissions exist
4. **Multi-Stage Filtering**: Applies deduplication at multiple stages for comprehensive cleanup

### Example

**Before Deduplication** (redundant):

```yaml
# ClusterRole
- apiGroups: ['']
  resources: [configmaps, serviceaccounts, services]
  verbs: ['*']

# Role (DUPLICATES!)
- apiGroups: ['']
  resources: [configmaps]
  verbs: [create, delete, get, list, patch, update, watch]
- apiGroups: ['']  
  resources: [serviceaccounts]
  verbs: [create, list, watch]
```

**After Deduplication** (optimized):

```yaml
# ClusterRole (unchanged)
- apiGroups: ['']
  resources: [configmaps, serviceaccounts, services]
  verbs: ['*']

# Role (only resource-specific permissions remain)
- apiGroups: ['']
  resources: [serviceaccounts]
  verbs: [delete, get, patch, update]
  resourceNames: [operator-controller-manager]
```

### Benefits

- **🔒 Enhanced Security**: Eliminates permission redundancy and potential conflicts
- **📉 Reduced Complexity**: Fewer RBAC rules to manage and audit
- **🎯 Precise Permissions**: Preserves granular resource-specific access controls
- **🚀 Automatic**: No manual intervention required - works out of the box

## Output

### Generated Files

The tool generates different outputs based on the command used:

#### YAML Manifests (default `--opm` output)

- `01-serviceaccount.yaml`: ServiceAccount for the operator installer
- `02-clusterrole.yaml`: ClusterRoles for operator management and grantor permissions
- `03-clusterrolebinding.yaml`: ClusterRoleBindings linking ServiceAccount to ClusterRoles
- `04-role.yaml`: Roles for namespace-scoped permissions (when both `clusterPermissions` and `permissions` exist)
- `05-rolebinding.yaml`: RoleBindings for namespace-scoped permissions

#### Helm Values (`--helm` flag)

- **Security Notice Header**: Comprehensive post-installation hardening instructions
- **Operator Configuration**: Package name, version, channel information
- **ServiceAccount**: Configuration for installer service account
- **ClusterRoles**: Operator management + grantor permissions (from `clusterPermissions`)
- **Roles**: Grantor permissions only (from `permissions` when both types exist)
- **Mixed YAML Style**: Block style with flow arrays for clean readability

### Example Output Structure

```tree
generated-quay-operator/
├── yaml/
│   ├── 01-serviceaccount.yaml
│   ├── 02-clusterrole.yaml
│   ├── 03-clusterrolebinding.yaml
│   └── 04-clusterextension.yaml
└── helm/
    ├── rbac-only-example.yaml
    └── values-quay-operator.yaml
```

## Examples

### Direct Command Workflow

1. **List available catalogs:**

   ```bash
   python3 rbac-manager.py list-catalogs
   ```

2. **Explore a catalog interactively:**

   ```bash
   python3 rbac-manager.py catalogd
   ```

3. **Find a specific operator version:**

   ```bash
   python3 rbac-manager.py catalogd \
     --catalog-name openshift-redhat-operators \
     --package quay-operator \
     --channel stable-3.10
   ```

4. **Extract bundle and generate resources:**

   ```bash
   python3 rbac-manager.py opm \
     --image quay.io/redhat/quay-operator-bundle:v3.10.13 \
     --namespace quay-operator
   ```

### Debug Mode

Enable debug logging for troubleshooting:

```bash
python3 rbac-manager.py --debug --catalogd --catalog-name test-catalog
```

### Skip TLS Verification

For development environments with self-signed certificates:

```bash
python3 rbac-manager.py --skip-tls --catalogd \
  --openshift-url https://api.dev-cluster.local:6443 \
  --openshift-token your-token
```

## Error Handling

The tool includes comprehensive error handling for common scenarios:

- **Missing opm binary**: Clear error message with installation instructions
- **Index vs Bundle images**: Automatic detection with helpful guidance
- **Network connectivity**: Timeout and retry mechanisms
- **Authentication failures**: Clear error messages for token/certificate issues
- **Kubernetes API errors**: Detailed error reporting with suggestions

## Integration with OLMv1 Helm Chart

The generated Helm values files are designed to work with the generic OLMv1 Helm chart in this repository. The tool:

1. Extracts RBAC permissions from the operator bundle
2. Generates appropriate ClusterRole rules
3. Creates Helm values that match the chart's schema
4. Supports both RBAC-only and full operator deployments

## Troubleshooting

### Common Issues

1. **"opm binary not found"**
   - Install opm CLI tool from operator-framework releases
   - Ensure opm is in your PATH

2. **"Failed to establish port-forward"**
   - Ensure kubeconfig is configured and connected to your cluster, OR
   - Use `--openshift-url` and `--openshift-token` for direct API access
   - Check that catalogd service exists in openshift-catalogd namespace

3. **"No ClusterCatalogs found"**
   - Verify you're connected to an OpenShift cluster with OLMv1
   - Check cluster permissions for listing ClusterCatalogs
   - Try using direct API access with `--openshift-url` and `--openshift-token`

4. **"Image appears to be an index image"**
   - Use --catalogd instead of --opm for index images
   - Create a ClusterCatalog resource first

5. **"Kubernetes client not initialized"**
   - Either configure kubeconfig, OR
   - Use `--openshift-url https://api.cluster.com:6443 --openshift-token <token>`

### Detailed Logging

Use `--debug` flag to see detailed logging:

```bash
python3 rbac-manager.py --debug --opm --image your-bundle-image
```

## Contributing

This tool is part of the OLMv1 project. Please follow the project's contribution guidelines and coding standards.

## License

This tool is part of the OLMv1 project and follows the same license terms.
