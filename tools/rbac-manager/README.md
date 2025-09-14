# RBAC Manager Tool

A comprehensive Python tool for extracting and managing RBAC permissions from operator bundles using the `opm` binary and interacting with OpenShift catalogs via `catalogd`. This tool automates the generation of secure RBAC resources and Helm values for OLMv1 operator deployments.

## Features

- **🔍 Catalog Discovery**: List and query OpenShift ClusterCatalogs for available operators
- **📡 Catalogd Integration**: Port-forward to catalogd service and fetch real-time package information
- **📦 Bundle Analysis**: Extract comprehensive metadata from operator bundle images using `opm render`
- **🔐 Smart RBAC Generation**: Auto-generate secure RBAC resources with proper permissions logic:
  - **Both `clusterPermissions` + `permissions`**: ClusterRoles + grantor Roles (e.g., ArgoCD)
  - **Only `permissions`**: Treat as ClusterRoles (e.g., Quay operator)
  - **Only `clusterPermissions`**: ClusterRoles only
- **⚙️ Helm Integration**: Generate Helm values with mixed block/flow YAML style and security notices
- **🏗️ Microservice Architecture**: Clean separation with BundleProcessor orchestrator
- **🛡️ Security Best Practices**: Implements OLMv1 security patterns with least-privilege principles
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

### Global Flags

- `--skip-tls`: Make insecure requests (skip TLS verification)
- `--debug`: Enable debug logging for detailed output
- `--help`: Show comprehensive help information
- `--examples`: Show detailed usage examples

### Commands

#### 1. List ClusterCatalogs

List all available ClusterCatalogs in your cluster:

```bash
python3 rbac-manager.py --list-catalogs
```

#### 2. Query Catalogd Service

Query the catalogd service for package information. The tool can either use port-forwarding or direct API access.

**Basic usage with interactive catalog selection:**

```bash
python3 rbac-manager.py --catalogd
```

**With specific catalog:**

```bash
python3 rbac-manager.py --catalogd --catalog-name openshift-redhat-operators
```

**Using direct OpenShift API:**

```bash
python3 rbac-manager.py --catalogd \
  --catalog-name openshift-redhat-operators \
  --openshift-url https://api.cluster.example.com:6443 \
  --openshift-token sha256~your-token-here
```

**Query specific package channels:**

```bash
python3 rbac-manager.py --catalogd \
  --catalog-name openshift-redhat-operators \
  --package quay-operator
```

**Query specific channel versions:**

```bash
python3 rbac-manager.py --catalogd \
  --catalog-name openshift-redhat-operators \
  --package quay-operator \
  --channel stable-3.10
```

**Get detailed version metadata:**

```bash
python3 rbac-manager.py --catalogd \
  --catalog-name openshift-redhat-operators \
  --package quay-operator \
  --channel stable-3.10 \
  --version 3.10.13
```

#### 3. Extract Bundle Metadata

Extract metadata from operator bundle images and generate RBAC resources:

**Basic bundle extraction (YAML manifests):**

```bash
python3 rbac-manager.py --opm \
  --image registry.redhat.io/quay/quay-operator-bundle@sha256:c431ad9dfd69c049e6d9583928630c06b8612879eeed57738fa7be206061fee2
```

**Generate Helm values:**

```bash
python3 rbac-manager.py --opm \
  --image registry.redhat.io/quay/quay-operator-bundle@sha256:c431ad9dfd69c049e6d9583928630c06b8612879eeed57738fa7be206061fee2 \
  --helm
```

**With custom namespace:**

```bash
python3 rbac-manager.py --opm \
  --image registry.redhat.io/quay/quay-operator-bundle@sha256:c431ad9dfd69c049e6d9583928630c06b8612879eeed57738fa7be206061fee2 \
  --namespace quay-operator
```

**Save to files:**

```bash
python3 rbac-manager.py --opm \
  --image registry.redhat.io/quay/quay-operator-bundle@sha256:c431ad9dfd69c049e6d9583928630c06b8612879eeed57738fa7be206061fee2 \
  --output ./rbac-files
```

**With TLS skip (for development):**

```bash
python3 rbac-manager.py --opm \
  --image registry.redhat.io/quay/quay-operator-bundle@sha256:c431ad9dfd69c049e6d9583928630c06b8612879eeed57738fa7be206061fee2 \
  --skip-tls --helm
```

### Catalogd Flags

- `--catalog-name NAME`: Specify catalog name (interactive prompt if not provided)
- `--openshift-url URL`: OpenShift cluster URL for direct API access
- `--openshift-token TOKEN`: OpenShift authentication token
- `--package NAME`: Show channels for specific package
- `--channel NAME`: Show versions for specific channel (requires --package)
- `--version VERSION`: Show metadata for specific version (requires --package and --channel)

### OPM Flags

- `--image IMAGE`: Operator bundle image URL (required)
- `--helm`: Generate Helm values instead of YAML manifests
- `--namespace NAMESPACE`: Target namespace for generated manifests (default: default)
- `--output DIR`: Save output files to directory (default: stdout)
- `--registry-token TOKEN`: Authentication token for private registries

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

### Complete Workflow Example

1. **List available catalogs:**

   ```bash
   python3 rbac-manager.py --list-catalogs
   ```

2. **Explore a catalog interactively:**

   ```bash
   python3 rbac-manager.py --catalogd
   ```

3. **Find a specific operator version:**

   ```bash
   python3 rbac-manager.py --catalogd \
     --catalog-name openshift-redhat-operators \
     --package quay-operator \
     --channel stable-3.10
   ```

4. **Extract bundle and generate resources:**

   ```bash
   python3 rbac-manager.py --opm \
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
