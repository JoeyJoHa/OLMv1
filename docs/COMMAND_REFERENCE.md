# Command Reference

This section provides practical commands for interacting with OLMv1 catalogs and analyzing operator bundles. Most commands use the `opm` tool, but equivalent `catalogd` interactions are also shown.

> **💡 Tip**: For easier RBAC extraction and operator analysis, consider using the [RBAC Manager Tool](../tools/rbac-manager/) which automates many of these manual processes with a user-friendly interface, configuration file support, and **comprehensive DRY architecture** that eliminates redundant RBAC rules between ClusterRoles and Roles, plus extensive code quality improvements throughout the entire codebase.

## Table of Contents

- [RBAC Manager Tool Commands](#rbac-manager-tool-commands)
- [Package Discovery](#package-discovery)
- [Channel Information](#channel-information)
- [Version Queries](#version-queries)
- [Bundle Filtering](#bundle-filtering)
- [OLMv1 Compatibility](#olmv1-compatibility)
- [Permission Analysis](#permission-analysis)
- [Advanced Queries](#advanced-queries)
- [Troubleshooting](#troubleshooting)

## RBAC Manager Tool Commands

The RBAC Manager Tool provides a streamlined interface for catalog discovery, configuration management, and RBAC extraction. The tool has been extensively refactored with DRY (Don't Repeat Yourself) principles, featuring comprehensive code quality improvements, centralized error handling, and advanced RBAC deduplication. Use these commands for the most efficient OLMv1 workflow:

### List Available Catalogs

```bash
# List all ClusterCatalogs on your cluster
python3 rbac-manager.py list-catalogs \
  --openshift-url https://api.cluster.example.com:6443 \
  --openshift-token sha256~your-token \
  --skip-tls
```

### Query Catalog Information

```bash
# List packages in a catalog
python3 rbac-manager.py catalogd \
  --catalog-name openshift-community-operators \
  --openshift-url https://api.cluster.example.com:6443 \
  --openshift-token sha256~your-token \
  --skip-tls

# List channels for a package
python3 rbac-manager.py catalogd \
  --catalog-name openshift-community-operators \
  --package argocd-operator \
  --openshift-url https://api.cluster.example.com:6443 \
  --openshift-token sha256~your-token \
  --skip-tls

# List versions for a channel
python3 rbac-manager.py catalogd \
  --catalog-name openshift-community-operators \
  --package argocd-operator --channel alpha \
  --openshift-url https://api.cluster.example.com:6443 \
  --openshift-token sha256~your-token \
  --skip-tls

# Get bundle metadata for specific version
python3 rbac-manager.py catalogd \
  --catalog-name openshift-community-operators \
  --package argocd-operator --channel alpha --version 0.8.0 \
  --openshift-url https://api.cluster.example.com:6443 \
  --openshift-token sha256~your-token \
  --skip-tls
```

### Generate Configuration Files

```bash
# Generate configuration template
python3 rbac-manager.py catalogd --generate-config

# Generate configuration with real cluster data
python3 rbac-manager.py catalogd --generate-config \
  --catalog-name openshift-community-operators \
  --package argocd-operator --channel alpha --version 0.8.0 \
  --openshift-url https://api.cluster.example.com:6443 \
  --openshift-token sha256~your-token \
  --skip-tls \
  --output ./config
```

### Extract RBAC Resources

```bash
# Using configuration file (recommended)
python3 rbac-manager.py opm --config rbac-manager-config.yaml

# Direct bundle extraction
python3 rbac-manager.py opm \
  --image quay.io/openshift-community-operators/argocd-operator@sha256:abc123... \
  --helm --skip-tls

# Save RBAC to files
python3 rbac-manager.py opm \
  --config rbac-manager-config.yaml \
  --output ./rbac-files
```

### Complete Workflow Example

```bash
# Step 1: List catalogs
python3 rbac-manager.py list-catalogs \
  --openshift-url https://api.cluster.example.com:6443 \
  --openshift-token sha256~your-token --skip-tls

# Step 2: Generate config with real data
python3 rbac-manager.py catalogd --generate-config \
  --catalog-name openshift-community-operators \
  --package argocd-operator --channel alpha --version 0.8.0 \
  --openshift-url https://api.cluster.example.com:6443 \
  --openshift-token sha256~your-token --skip-tls \
  --output ./config

# Step 3: Extract RBAC
python3 rbac-manager.py opm --config ./config/rbac-manager-config.yaml

# Step 4: Deploy RBAC resources
kubectl apply -f argocd-operator-serviceaccount-*.yaml
kubectl apply -f argocd-operator-clusterrole-*.yaml
kubectl apply -f argocd-operator-clusterrolebinding-*.yaml
kubectl apply -f argocd-operator-role-*.yaml
kubectl apply -f argocd-operator-rolebinding-*.yaml
```

---

## Manual OPM and Catalogd Commands

For advanced users or automation scenarios, these manual commands provide direct access to OPM and catalogd functionality:

## Package Discovery

**Get all available packages within a catalog:**

```bash
# Using opm with container registry
opm render registry.redhat.io/redhat/redhat-operator-index:v4.18 \
  | jq -s '.[] | select(.schema == "olm.package") | .name'

# Using catalogd via OpenShift route
curl -k https://catalogd.apps.example.com/catalogs/openshift-redhat-operators/api/v1/all \
  | jq -s '.[] | select(.schema == "olm.package") | .name'
```

**Search for packages by name pattern:**

```bash
# Find packages containing "operator" in the name
opm render registry.redhat.io/redhat/redhat-operator-index:v4.18 \
  | jq -s '.[] | select(.schema == "olm.package") | select(.name | contains("operator")) | .name'
```

**Get package details with description:**

```bash
opm render registry.redhat.io/redhat/redhat-operator-index:v4.18 \
  | jq -s '.[] | select(.schema == "olm.package") | {name: .name, description: .description}'
```

## Channel Information

**Query available channels for a specific operator:**

```bash
opm render registry.redhat.io/redhat/redhat-operator-index:v4.18 \
  | jq -s '.[] | select(.schema == "olm.channel") | select(.package == "quay-operator") | .name'
```

**Get detailed channel information:**

```bash
opm render registry.redhat.io/redhat/redhat-operator-index:v4.18 \
  | jq -s '.[] | select(.schema == "olm.channel") | select(.package == "quay-operator") | {
    channel: .name,
    package: .package,
    entries: [.entries[].name]
  }'
```

**Find default channel for a package:**

```bash
opm render registry.redhat.io/redhat/redhat-operator-index:v4.18 \
  | jq -s '.[] | select(.schema == "olm.package") | select(.name == "quay-operator") | .defaultChannel'
```

## Version Queries

**Query available versions for each channel:**

```bash
opm render registry.redhat.io/redhat/redhat-operator-index:v4.18 \
  | jq -s '.[] | select(.schema == "olm.channel") | select(.package == "quay-operator") |
  { 
    "Channel": .name,
    "Versions": [.entries[].name] | sort
  }'
```

**Get latest version in a channel:**

```bash
opm render registry.redhat.io/redhat/redhat-operator-index:v4.18 \
  | jq -s '.[] | select(.schema == "olm.channel") | select(.package == "quay-operator" and .name == "stable") | .entries[0].name'
```

**List all versions across all channels:**

```bash
opm render registry.redhat.io/redhat/redhat-operator-index:v4.18 \
  | jq -s '.[] | select(.schema == "olm.channel") | select(.package == "quay-operator") | .entries[].name' \
  | sort -u
```

## Bundle Filtering

**Query specific bundle using package and version filters:**

```bash
opm render registry.redhat.io/redhat/redhat-operator-index:v4.18 \
  | jq -s '.[] 
  | select(.schema == "olm.bundle" and any(.properties[] ; .type == "olm.package" and .value.packageName == "quay-operator" and .value.version == "3.10.13"))'
```

**Get bundle image URL for a specific version:**

```bash
opm render registry.redhat.io/redhat/redhat-operator-index:v4.18 \
  | jq -s '.[] | select(.schema == "olm.bundle" and any(.properties[] ; .type == "olm.package" and .value.packageName == "quay-operator" and .value.version == "3.10.13")) | .image'
```

**Filter bundles by capabilities:**

```bash
opm render registry.redhat.io/redhat/redhat-operator-index:v4.18 \
  | jq -s '.[] | select(.schema == "olm.bundle") | select(any(.properties[] ; .type == "olm.csv.metadata" and (.value.capabilities // "") | contains("Deep Insights"))) | {
    package: (.properties[] | select(.type == "olm.package").value.packageName),
    version: (.properties[] | select(.type == "olm.package").value.version),
    capabilities: (.properties[] | select(.type == "olm.csv.metadata").value.capabilities)
  }'
```

## OLMv1 Compatibility

**Check if operator is compatible with OLMv1 (InstallMode == AllNamespaces):**

```bash
opm render registry.redhat.io/redhat/redhat-operator-index:v4.18 \
  | jq -s '.[] | select(.schema == "olm.bundle" and any(.properties[] ; .type == "olm.package" and .value.packageName == "quay-operator" and .value.version == "3.10.13")) | {
    name,
    image,
    SupportAllNamespaces: (.properties[] | select(.type == "olm.csv.metadata").value.installModes[] | select(.type == "AllNamespaces").supported)
  }'
```

**List all OLMv1-compatible operators in a catalog:**

```bash
opm render registry.redhat.io/redhat/redhat-operator-index:v4.18 \
  | jq -s '.[] | select(.schema == "olm.bundle") | select(.properties[] | select(.type == "olm.csv.metadata").value.installModes[] | select(.type == "AllNamespaces").supported == true) | {
    package: (.properties[] | select(.type == "olm.package").value.packageName),
    version: (.properties[] | select(.type == "olm.package").value.version)
  }' \
  | jq -s 'group_by(.package) | map({package: .[0].package, versions: [.[].version]})'
```

**Check operator maturity level:**

```bash
opm render registry.redhat.io/redhat/redhat-operator-index:v4.18 \
  | jq -s '.[] | select(.schema == "olm.bundle" and any(.properties[] ; .type == "olm.package" and .value.packageName == "quay-operator")) | {
    version: (.properties[] | select(.type == "olm.package").value.version),
    maturity: (.properties[] | select(.type == "olm.csv.metadata").value.maturity // "unknown")
  }'
```

## Permission Analysis

> **Note**: When analyzing operator permissions, always review both `clusterPermissions` and `permissions` sections. The Quay operator example above only shows `permissions` as it doesn't include `clusterPermissions`.
> **⚠️ macOS/Windows Users**: When using `opm` with Podman, the `--skip-tls` flag may not work due to Podman's client-server architecture. You may need to configure insecure registries within the Podman Machine. See the [RBAC Manager documentation](../tools/rbac-manager/README.md#podman-machine-configuration-macoswindows) for detailed setup instructions.

**Query required permissions for an operator:**

```bash
# Basic permission extraction
opm render registry.redhat.io/quay/quay-operator-bundle@sha256:c431ad9dfd69c049e6d9583928630c06b8612879eeed57738fa7be206061fee2 \
  | jq -r '.properties[] | select(.type == "olm.bundle.object") | .value.data' \
  | base64 -d \
  | jq 'select(.kind == "ClusterServiceVersion") | .spec.install.spec.permissions[].rules[]' \
  | jq -s '.'
```

**Extract cluster-level permissions:**

```bash
opm render registry.redhat.io/quay/quay-operator-bundle@sha256:c431ad9dfd69c049e6d9583928630c06b8612879eeed57738fa7be206061fee2 \
  | jq -r '.properties[] | select(.type == "olm.bundle.object") | .value.data' \
  | base64 -d \
  | jq 'select(.kind == "ClusterServiceVersion") | .spec.install.spec.clusterPermissions[].rules[]' \
  | jq -s '.'
```

**Export permissions as a Kubernetes Role YAML:**

```bash
opm render registry.redhat.io/quay/quay-operator-bundle@sha256:c431ad9dfd69c049e6d9583928630c06b8612879eeed57738fa7be206061fee2 \
  | jq -r '.properties[] | select(.type == "olm.bundle.object") | .value.data' \
  | base64 -d \
  | jq -s 'map(select(.kind == "ClusterServiceVersion")) | .[].spec.install.spec.permissions[].rules[]' \
  | jq -s '.' \
  | yq -P '{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "example", "namespace": "example-ns"}, "rules": .}'
```

**Export cluster permissions as ClusterRole YAML:**

```bash
opm render registry.redhat.io/quay/quay-operator-bundle@sha256:c431ad9dfd69c049e6d9583928630c06b8612879eeed57738fa7be206061fee2 \
  | jq -r '.properties[] | select(.type == "olm.bundle.object") | .value.data' \
  | base64 -d \
  | jq -s 'map(select(.kind == "ClusterServiceVersion")) | .[].spec.install.spec.clusterPermissions[].rules[]' \
  | jq -s '.' \
  | yq -P '{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": {"name": "example-cluster-role"}, "rules": .}'
```

## Advanced Queries

**Get operator dependencies:**

```bash
opm render registry.redhat.io/redhat/redhat-operator-index:v4.18 \
  | jq -s '.[] | select(.schema == "olm.bundle" and any(.properties[] ; .type == "olm.package" and .value.packageName == "quay-operator")) | {
    version: (.properties[] | select(.type == "olm.package").value.version),
    dependencies: [.properties[] | select(.type == "olm.gvk.required") | .value]
  }'
```

**List all CRDs provided by an operator:**

```bash
opm render registry.redhat.io/quay/quay-operator-bundle@sha256:c431ad9dfd69c049e6d9583928630c06b8612879eeed57738fa7be206061fee2 \
  | jq -r '.properties[] | select(.type == "olm.bundle.object") | .value.data' \
  | base64 -d \
  | jq 'select(.kind == "CustomResourceDefinition") | {
    name: .metadata.name,
    group: .spec.group,
    version: .spec.versions[].name,
    kind: .spec.names.kind
  }'
```

**Get operator CSV metadata:**

```bash
opm render registry.redhat.io/quay/quay-operator-bundle@sha256:c431ad9dfd69c049e6d9583928630c06b8612879eeed57738fa7be206061fee2 \
  | jq -r '.properties[] | select(.type == "olm.bundle.object") | .value.data' \
  | base64 -d \
  | jq 'select(.kind == "ClusterServiceVersion") | {
    name: .metadata.name,
    displayName: .spec.displayName,
    description: .spec.description,
    version: .spec.version,
    provider: .spec.provider,
    maintainers: .spec.maintainers,
    links: .spec.links
  }'
```

## Troubleshooting

### Common Issues

**1. TLS/SSL Certificate Issues:**

```bash
# Skip TLS verification (use with caution)
opm render --skip-tls registry.example.com/catalog:latest

# Or configure proper certificates in your container runtime
```

**2. Authentication Issues:**

```bash
# Login to registry first
podman login registry.redhat.io
# or
docker login registry.redhat.io

# Then run opm commands
```

**3. Large Catalog Timeouts:**

```bash
# For large catalogs, consider filtering early in the pipeline
opm render registry.redhat.io/redhat/redhat-operator-index:v4.18 \
  | jq --stream 'select(.[0][0] == "schema" and .[1] == "olm.package") as $package | 
    if $package then . else empty end'
```

**4. Memory Issues with Large Catalogs:**

```bash
# Use streaming JSON processing for large datasets
opm render registry.redhat.io/redhat/redhat-operator-index:v4.18 \
  | jq -c '.' \
  | grep '"schema":"olm.package"' \
  | jq '.name'
```

### Performance Tips

1. **Filter Early**: Apply filters as early as possible in the pipeline
2. **Use Streaming**: For large catalogs, use `jq -c` and `grep` for streaming processing
3. **Cache Results**: Save intermediate results to files for repeated queries
4. **Parallel Processing**: Use `xargs -P` for parallel processing of multiple queries

### Debugging Commands

**Verify catalog structure:**

```bash
opm render registry.redhat.io/redhat/redhat-operator-index:v4.18 \
  | jq -s 'group_by(.schema) | map({schema: .[0].schema, count: length})'
```

**Check for malformed entries:**

```bash
opm render registry.redhat.io/redhat/redhat-operator-index:v4.18 \
  | jq -c '.' \
  | jq -s 'map(select(.schema == null or .schema == "")) | length'
```

**Validate bundle integrity:**

```bash
opm render registry.redhat.io/quay/quay-operator-bundle@sha256:c431ad9dfd69c049e6d9583928630c06b8612879eeed57738fa7be206061fee2 \
  | jq -r '.properties[] | select(.type == "olm.bundle.object") | .value.data' \
  | base64 -d \
  | jq 'select(.kind == "ClusterServiceVersion") | .spec | keys'
```

## Integration with RBAC Manager

For automated processing of these commands and more user-friendly interfaces, consider using the [RBAC Manager Tool](../tools/rbac-manager/) with **comprehensive DRY architecture and intelligent deduplication**:

### Basic Operations

```bash
# Setup (one-time)
cd tools/rbac-manager/
python3 -m venv rbac-manager-env
source rbac-manager-env/bin/activate  # Linux/macOS
pip install -r requirements.txt

# List all Available catalogs in the cluster (ClusterCatalogs API)
python3 rbac-manager.py --list-catalogs 

# Automated RBAC extraction
python3 rbac-manager.py --opm --image <bundle-image>

# Generate Helm values with security notices and DRY deduplication
python3 rbac-manager.py --opm --image <bundle-image> --helm
```

### Comprehensive DRY Architecture Benefits

The RBAC Manager has been completely refactored with **DRY (Don't Repeat Yourself)** principles applied throughout:

#### **RBAC Deduplication:**

- **🔍 Removes Duplicates**: Automatically removes Role permissions that are already covered by ClusterRole permissions
- **🎯 Preserves Specificity**: Keeps resource-specific rules with `resourceNames` even when broader permissions exist
- **⚡ Handles Wildcards**: Recognizes when wildcard verbs (`['*']`) supersede specific verb lists
- **🧹 Cleaner Output**: Results in fewer, more maintainable RBAC rules
- **🔒 Better Security**: Reduces permission conflicts and potential security issues

#### **Code Architecture Improvements:**

- **🏗️ Centralized Logic**: Single source of truth for RBAC component analysis eliminates duplicated logic
- **🎨 Consistent Formatting**: Shared FlowStyleList formatting across YAML and Helm outputs
- **🛡️ Enhanced Error Handling**: Decorator patterns and centralized error handling across 15+ classes
- **⚡ Optimized Performance**: Instance caching and atomic file operations
- **🧪 Improved Testing**: DRY test patterns eliminate 100+ lines of test code duplication

**Example**: If a ClusterRole grants `verbs: ['*']` on `resources: [configmaps, services]`, redundant Role rules for those same resources are automatically removed, keeping only resource-specific rules with `resourceNames`.

### Configuration File Generation

The RBAC Manager tool provides configuration generation capabilities for different use cases:

```bash
# Query catalogd for package information
python3 rbac-manager.py --catalogd --catalog-name openshift-redhat-operators --package quay-operator

# Query specific version metadata
python3 rbac-manager.py --catalogd \
  --catalog-name openshift-redhat-operators \
  --package quay-operator --channel stable-3.10 --version 3.10.13
```

### Using Configuration Files

Configuration files work with OPM operations to provide default values and streamline workflows:

```bash
# Generate YAML manifests (default output)
python3 rbac-manager.py --opm --image <bundle-image>

# Generate Helm values with security notices
python3 rbac-manager.py --opm --image <bundle-image> --helm

# Use custom namespace
python3 rbac-manager.py --opm --image <bundle-image> --namespace production
```

### Output Options

```bash
# Generate Helm values.yaml for GitOps workflows
python3 rbac-manager.py --opm --image <bundle-image> --helm

# Save RBAC files to directory for manual application
python3 rbac-manager.py --opm --image <bundle-image> --output ./rbac-files

# Apply RBAC directly to cluster (pipe to kubectl)
python3 rbac-manager.py --opm --image <bundle-image> --namespace production | kubectl apply -f -
```

### Generated Examples Structure

The RBAC Manager tool outputs examples in the following structure with comprehensive DRY improvements:

```tree
examples/rbac-manager/
├── generated-files/          # Fresh tool outputs with advanced DRY deduplication
│   ├── argocd-operator-*.yaml # Complete Helm values with channel guidance and flow-style arrays
│   ├── argocd-operator-clusterrole-*.yaml # Generated ClusterRole (centrally analyzed and deduplicated)
│   ├── argocd-operator-clusterrolebinding-*.yaml # Generated ClusterRoleBinding
│   ├── argocd-operator-role-*.yaml # Generated Role (DRY filtered against ClusterRole)
│   ├── argocd-operator-rolebinding-*.yaml # Generated RoleBinding
│   └── argocd-operator-serviceaccount-*.yaml # Generated ServiceAccount
└── post-installation/        # Hardened examples after deployment
    └── argocd-operator-clusterrole-*.yaml # ClusterRole with resourceNames hardening
```

**Enhanced Features:**

- **`generated-files/`**: Use these files for initial deployment with installer permissions
  - **NEW**: Consistent flow-style YAML arrays for better readability
  - **NEW**: Eliminated YAML anchors/aliases for cleaner manifests
  - **NEW**: Centralized RBAC component analysis eliminates duplication bugs
- **`post-installation/`**: Reference these examples after deployment to harden permissions with specific `resourceNames`

**DRY Architecture Benefits:**

- **Centralized Generation**: All RBAC components generated through single analysis pipeline
- **Shared Formatting**: Consistent YAML/Helm formatting eliminates code duplication
- **Atomic Operations**: File generation uses atomic write patterns for reliability
- **Enhanced Testing**: Comprehensive test coverage with DRY patterns ensures quality

The RBAC Manager tool automates many of these manual processes and provides additional features like configuration file support, automatic cluster discovery, live catalogd data extraction, integrated deployment capabilities, and a completely refactored codebase following clean architecture principles.
