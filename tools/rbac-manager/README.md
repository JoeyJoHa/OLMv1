# OPM Metadata Tool

A comprehensive Python tool to fetch operator bundle metadata using the `opm` binary and interact with OpenShift catalogs. This tool helps generate RBAC resources and Helm values for OLMv1 operators.

## Features

- **List ClusterCatalogs**: Query OpenShift cluster for available catalogs
- **Query Catalogd**: Port-forward to catalogd service and fetch package information
- **Extract Bundle Metadata**: Use `opm` binary to extract metadata from operator bundle images
- **Generate RBAC Resources**: Auto-generate ServiceAccount, ClusterRole, ClusterRoleBinding, and ClusterExtension YAML files
- **Generate Helm Values**: Create Helm chart values files for both RBAC-only and full operator deployments
- **Interactive Mode**: User-friendly prompts for catalog selection
- **Comprehensive Logging**: Debug mode with detailed logging

## Prerequisites

### Required Dependencies

Install the required Python packages:

```bash
pip install -r requirements.txt
```

### Required Tools

1. **kubectl**: Kubernetes command-line tool
2. **opm**: Operator Package Manager CLI tool
   - Download from [operator-framework/operator-registry releases](https://github.com/operator-framework/operator-registry/releases)
   - Or install via package manager (e.g., `brew install operator-framework/tap/opm`)

### Kubernetes Access

- Valid kubeconfig file configured for your OpenShift/Kubernetes cluster
- Or provide OpenShift URL and token for direct API access

## Installation

1. Clone the repository and navigate to the tool directory:

   ```bash
   cd tools/rbac-manager
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Make the script executable:

   ```bash
   chmod +x opm_metadata_tool.py
   ```

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
python3 opm_metadata_tool.py --list-catalogs
```

#### 2. Query Catalogd Service

Query the catalogd service for package information. The tool can either use port-forwarding or direct API access.

**Basic usage with interactive catalog selection:**

```bash
python3 opm_metadata_tool.py --catalogd
```

**With specific catalog:**

```bash
python3 opm_metadata_tool.py --catalogd --catalog-name operatorhubio-catalog
```

**Using direct OpenShift API:**

```bash
python3 opm_metadata_tool.py --catalogd \
  --catalog-name operatorhubio-catalog \
  --openshift-url https://api.cluster.example.com:6443 \
  --openshift-token sha256~your-token-here
```

**Query specific package channels:**

```bash
python3 opm_metadata_tool.py --catalogd \
  --catalog-name operatorhubio-catalog \
  --package quay-operator
```

**Query specific channel versions:**

```bash
python3 opm_metadata_tool.py --catalogd \
  --catalog-name operatorhubio-catalog \
  --package quay-operator \
  --channel stable-3.10
```

**Get detailed version metadata:**

```bash
python3 opm_metadata_tool.py --catalogd \
  --catalog-name operatorhubio-catalog \
  --package quay-operator \
  --channel stable-3.10 \
  --version 3.10.13
```

#### 3. Extract Bundle Metadata

Extract metadata from operator bundle images and generate RBAC resources:

**Basic bundle extraction:**

```bash
python3 opm_metadata_tool.py --opm \
  --image quay.io/redhat/quay-operator-bundle:v3.10.13
```

**With custom namespace:**

```bash
python3 opm_metadata_tool.py --opm \
  --image quay.io/redhat/quay-operator-bundle:v3.10.13 \
  --namespace quay-operator
```

**With private registry authentication:**

```bash
python3 opm_metadata_tool.py --opm \
  --image private-registry.com/operator-bundle:v1.0.0 \
  --namespace my-operator \
  --registry-token your-registry-token
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
- `--namespace NAMESPACE`: Target namespace for generated manifests (default: default)
- `--registry-token TOKEN`: Authentication token for private registries

## Output

### Generated Files

When using the `--opm` command, the tool generates:

#### YAML Manifests Directory (`yaml/`)

- `01-serviceaccount.yaml`: ServiceAccount for the operator installer
- `02-clusterrole.yaml`: ClusterRoles for operator and RBAC permissions
- `03-clusterrolebinding.yaml`: ClusterRoleBindings linking ServiceAccount to ClusterRoles
- `04-clusterextension.yaml`: ClusterExtension resource for OLMv1

#### Helm Values Directory (`helm/`)

- `rbac-only-example.yaml`: Helm values for RBAC-only deployment
- `values-{operator-name}.yaml`: Complete Helm values for full operator deployment

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
   python3 opm_metadata_tool.py --list-catalogs
   ```

2. **Explore a catalog interactively:**

   ```bash
   python3 opm_metadata_tool.py --catalogd
   ```

3. **Find a specific operator version:**

   ```bash
   python3 opm_metadata_tool.py --catalogd \
     --catalog-name operatorhubio-catalog \
     --package quay-operator \
     --channel stable-3.10
   ```

4. **Extract bundle and generate resources:**

   ```bash
   python3 opm_metadata_tool.py --opm \
     --image quay.io/redhat/quay-operator-bundle:v3.10.13 \
     --namespace quay-operator
   ```

### Debug Mode

Enable debug logging for troubleshooting:

```bash
python3 opm_metadata_tool.py --debug --catalogd --catalog-name test-catalog
```

### Skip TLS Verification

For development environments with self-signed certificates:

```bash
python3 opm_metadata_tool.py --skip-tls --catalogd \
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
   - Ensure kubectl is configured and connected to your cluster
   - Check that catalogd service exists in openshift-catalogd namespace

3. **"No ClusterCatalogs found"**
   - Verify you're connected to an OpenShift cluster with OLMv1
   - Check cluster permissions for listing ClusterCatalogs

4. **"Image appears to be an index image"**
   - Use --catalogd instead of --opm for index images
   - Create a ClusterCatalog resource first

### Detailed Logging

Use `--debug` flag to see detailed logging:

```bash
python3 opm_metadata_tool.py --debug --opm --image your-bundle-image
```

## Contributing

This tool is part of the OLMv1 project. Please follow the project's contribution guidelines and coding standards.

## License

This tool is part of the OLMv1 project and follows the same license terms.
