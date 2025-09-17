# Command Reference

This section provides practical commands for interacting with OLMv1 catalogs and analyzing operator bundles. Most commands use the `opm` tool, but equivalent `catalogd` interactions are also shown.

> **💡 Tip**: For easier RBAC extraction and operator analysis, consider using the [RBAC Manager Tool](../tools/rbac-manager/) which automates many of these manual processes with a user-friendly interface, configuration file support, and **DRY deduplication** that eliminates redundant RBAC rules between ClusterRoles and Roles.

## Table of Contents

- [Package Discovery](#package-discovery)
- [Channel Information](#channel-information)
- [Version Queries](#version-queries)
- [Bundle Filtering](#bundle-filtering)
- [OLMv1 Compatibility](#olmv1-compatibility)
- [Permission Analysis](#permission-analysis)
- [Advanced Queries](#advanced-queries)
- [Troubleshooting](#troubleshooting)

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

For automated processing of these commands and more user-friendly interfaces, consider using the [RBAC Manager Tool](../tools/rbac-manager/) with **intelligent DRY deduplication**:

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

### DRY Deduplication Benefits

The RBAC Manager automatically applies **DRY (Don't Repeat Yourself)** deduplication to eliminate redundant permissions:

- **🔍 Removes Duplicates**: Automatically removes Role permissions that are already covered by ClusterRole permissions
- **🎯 Preserves Specificity**: Keeps resource-specific rules with `resourceNames` even when broader permissions exist
- **⚡ Handles Wildcards**: Recognizes when wildcard verbs (`['*']`) supersede specific verb lists
- **🧹 Cleaner Output**: Results in fewer, more maintainable RBAC rules
- **🔒 Better Security**: Reduces permission conflicts and potential security issues

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

The RBAC Manager tool outputs examples in the following structure:

```tree
examples/rbac-manager/
├── generated-files/          # Fresh tool outputs with DRY deduplication
│   ├── argocd-operator-*.yaml # Complete Helm values with channel guidance
│   ├── argocd-operator-clusterrole-*.yaml # Generated ClusterRole (deduplicated)
│   ├── argocd-operator-clusterrolebinding-*.yaml # Generated ClusterRoleBinding
│   ├── argocd-operator-role-*.yaml # Generated Role (deduplicated against ClusterRole)
│   ├── argocd-operator-rolebinding-*.yaml # Generated RoleBinding
│   └── argocd-operator-serviceaccount-*.yaml # Generated ServiceAccount
└── post-installation/        # Hardened examples after deployment
    └── argocd-operator-clusterrole-*.yaml # ClusterRole with resourceNames hardening
```

**Usage:**

- **`generated-files/`**: Use these files for initial deployment with installer permissions
- **`post-installation/`**: Reference these examples after deployment to harden permissions with specific `resourceNames`

The RBAC Manager tool automates many of these manual processes and provides additional features like configuration file support, automatic cluster discovery, live catalogd data extraction, and integrated deployment capabilities.
