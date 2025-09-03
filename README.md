# Operator Lifecycle Manager V1 (OLMv1)

> **Disclaimer**: This repo contains AI-generated content using Cursor / Gemini AI.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Key Components](#key-components)
- [Deployment Flow](#deployment-flow)
- [Sequence Diagram](#sequence-diagram)
- [Project Structure](#project-structure)
- [Deployment Documentation](#deployment-documentation)
- [Using Templates](#using-templates)
- [RBAC Manager Tool](#rbac-manager-tool)
- [Command Reference](#command-reference)
  - [Package Discovery](#package-discovery)
  - [Channel Information](#channel-information)
  - [Version Queries](#version-queries)
  - [Bundle Filtering](#bundle-filtering)
  - [OLMv1 Compatibility](#olmv1-compatibility)
  - [Permission Analysis](#permission-analysis)

## Overview

The Operator Lifecycle Manager V1 (OLMv1) is a declarative, pull-based system designed for managing Kubernetes operators with a focus on simplicity and security. This document provides a comprehensive guide to understanding OLMv1's architecture, deployment flow, and practical usage.

## Architecture

OLMv1 follows a declarative architecture where administrators define desired states through Custom Resources, and the system automatically orchestrates operator lifecycles. The architecture is built around several core components that work together to provide a robust operator management solution.

## Key Components

| Component | Description | Purpose |
|-----------|-------------|---------|
| **Administrator/GitOps Tool** | Human operator or automation tool | Creates ClusterExtension CRs to define desired operator states |
| **Operator Controller** | Core OLMv1 component | Watches ClusterExtension CRs and orchestrates operator lifecycle |
| **catalogd** | Metadata service | Hosts and serves operator metadata from File-Based Catalogs |
| **File-Based Catalogs (FBCs)** | Lightweight metadata collections | Source of truth for operator bundles, channels, and update graphs |
| **Installed Operator Bundle** | Deployed operator resources | Includes deployment, ServiceAccount, RBAC, and CRDs |

## Deployment Flow

The OLMv1 deployment process follows a logical sequence:

1. **Administrator Action**: Apply a declarative `ClusterExtension` manifest specifying the desired operator package, version, and target namespace
2. **Controller Detection**: The Operator Controller detects the new `ClusterExtension` CR
3. **Metadata Query**: Controller queries `catalogd` for the requested operator bundle
4. **Catalog Response**: `catalogd` provides metadata from File-Based Catalogs
5. **Bundle Deployment**: Controller pulls and deploys the operator bundle components
6. **Active Operation**: Operator begins operation with least-privilege access

## Sequence Diagram

```mermaid
sequenceDiagram
    participant Admin as Administrator/GitOps
    participant API as Kubernetes API
    participant OC as Operator Controller
    participant CD as catalogd
    participant FBC as File-Based Catalogs
    participant Registry as Container Registry
    participant NS as installNamespace

    Note over Admin,API: Admin Creates Security Resources
    Admin->>API: Create Custom Role, RoleBinding
    Admin->>API: Create ServiceAccount
    Admin->>API: Bind ServiceAccount to Role
    Admin->>API: Apply ClusterExtension Manifest

    Note over API,NS: OLMv1 Declarative Deployment Flow
    API->>OC: CR Created/Updated Event
    Note over OC: Controller Detects New CR
    OC->>CD: Query for Operator Metadata
    CD->>FBC: Process FBC Content
    FBC->>CD: Return Package Information
    CD->>OC: Provide Bundle Metadata
    OC->>Registry: Pull Operator Bundle Image
    Registry->>OC: Return Bundle Container

    Note over OC: Controller Uses ServiceAccount
    OC->>NS: Install CRDs
    OC->>NS: Deploy Operator Components
    OC->>NS: Deploy Operator Deployment

    Note over NS: Operator Bundle Active
    loop Continuous Operation
        OC->>NS: Monitor Bundle Status
        OC->>OC: Ensure Desired State
        OC->>API: Update CR Status
    end
```

## Project Structure

This project provides a structured approach for deploying OLMv1 operators with proper security and RBAC configuration:

```tree
OLMv1/
├── README.md                           # This documentation
├── requirements.txt                    # Python dependencies
├── bundle/                             # Operator bundle files
│   ├── ClusterServiceVersion.json      # Quay operator CSV
│   ├── Service.json                    # Quay operator service
│   └── CustomResourceDefinition.json   # Quay operator CRD
├── examples/                           # Example operator implementations
│   ├── values/                        # Example values files for different operators
│   │   └── values-quay-operator.yaml  # Quay operator example
│   ├── yamls/                         # Manual YAML deployment files
│   │   ├── 00-namespace.yaml           # Namespace definition
│   │   ├── 01-serviceaccount.yaml      # Service account for operator
│   │   ├── 02-clusterrole.yaml         # Cluster role with least privilege
│   │   ├── 03-clusterrolebinding.yaml  # Cluster role binding
│   │   └── 04-clusterextension.yaml    # OLMv1 ClusterExtension
│   └── DEPLOYMENT.md                   # Detailed deployment documentation
├── helm/                              # Generic Helm chart for operators
│   ├── Chart.yaml                     # Helm chart metadata
│   ├── values.yaml                    # Default Helm chart values
│   └── templates/                     # Helm chart templates
│       ├── _helpers.tpl               # Helper template functions
│       ├── clusterextension.yaml      # ClusterExtension template
│       ├── clusterrole.yaml           # ClusterRole template
│       ├── role.yaml                  # Role template
│       ├── serviceaccount.yaml        # ServiceAccount template
│       └── NOTES.txt                  # Installation notes
├── hack/                              # Developer tools and utilities
│   └── tools/
│       └── rbac-manager/              # Advanced RBAC extraction tool
│           ├── rbac_manager.py        # Main CLI tool with config support
│           ├── README.md              # Comprehensive usage guide
│           └── libs/                  # Modular library components
│               ├── openshift_auth.py    # Auto-discovery & authentication
│               ├── rbac_manager_core.py # Core RBAC processing
│               ├── config_utils.py      # Configuration file support
│               ├── logging_utils.py     # Logging configuration
│               ├── opm_query.py         # OPM image query functionality
│               ├── catalog_query.py     # ClusterCatalog API queries
│               ├── rbac_utils.py        # Shared RBAC processing utilities
│               └── port_forward_utils.py # Port-forward management
├── Templates/                          # Reusable template files
│   ├── CustomRoles/                    # Custom role templates
│   │   ├── 00-rolebinding.yaml        # Role binding template
│   │   ├── 01-clusterrole.yaml        # Cluster role template
│   │   └── 02-clusterrolebinding.yaml # Cluster role binding template
│   └── OLMv1 Resources/               # OLMv1 resource templates
│       ├── 01-clustercatalog.yaml     # ClusterCatalog example
│       └── 02-clusterextension.yaml   # ClusterExtension example
├── .git/                              # Git repository
├── .gitignore                         # Git ignore patterns
├── .cursor/                           # Cursor IDE configuration
└── .cursorignore                      # Cursor ignore patterns
```

## Deployment Documentation

For detailed deployment instructions, including step-by-step processes, cleanup procedures, and Helm chart usage, see the comprehensive [Deployment Guide](examples/DEPLOYMENT.md).

The guide covers:

- **Step-by-step deployment** of operators using YAML manifests
- **Helm chart deployment** for simplified operator installation
- **Cleanup procedures** for removing operators and resources
- **Monitoring and verification** steps for successful deployments

## Using Templates

The `Templates/CustomRoles/` directory contains reusable templates for custom RBAC configurations that can be adapted for different operators.

## RBAC Manager Tool

The project includes an advanced RBAC Manager tool (`hack/tools/rbac-manager/`) that automates the extraction and processing of RBAC permissions from OLM operators. This tool significantly simplifies the process of creating proper security configurations for OLMv1 deployments.

### Quick Start

```bash
# Navigate to the tool directory
cd hack/tools/rbac-manager/

# Generate a configuration file (optional but recommended)
python3 rbac_manager.py --generate-config ~/.rbac-manager.yaml

# Extract RBAC for an operator (auto-discovers cluster URL)
python3 rbac_manager.py --catalogd --package prometheus

# Deploy RBAC directly to your cluster
python3 rbac_manager.py --catalogd --package grafana --deploy

# Save RBAC files for later use
python3 rbac_manager.py --catalogd --package cert-manager --output ./rbac-files
```

### Benefits for OLMv1 Deployment

1. **Accurate RBAC Extraction**: Automatically extracts the exact permissions required by operators
2. **Kubernetes-Native Output**: Generates proper Kubernetes RBAC YAML with consistent naming
3. **Helm Integration**: Outputs include Helm template syntax for easy chart integration
4. **Security Best Practices**: Follows least-privilege principles and proper role separation
5. **Automation Ready**: Supports scripting and CI/CD integration with configuration files

### Integration with OLMv1 Workflow

The RBAC Manager integrates seamlessly with the OLMv1 deployment process:

1. **Extract RBAC**: Use the tool to extract required permissions for your chosen operator
2. **Review Permissions**: Examine the generated RBAC to ensure it meets security requirements
3. **Deploy RBAC**: Apply the RBAC resources before deploying the ClusterExtension
4. **Deploy Operator**: Use the generated ServiceAccount in your ClusterExtension manifest

For comprehensive usage instructions, examples, and troubleshooting guides, see the [RBAC Manager Guide](hack/tools/rbac-manager/README.md).

## Command Reference

This section provides practical commands for interacting with OLMv1 catalogs and analyzing operator bundles. Most commands use the `opm` tool, but equivalent `catalogd` interactions are also shown.

> **💡 Tip**: For easier RBAC extraction and operator analysis, consider using the [RBAC Manager Tool](#rbac-manager-tool) which automates many of these manual processes with a user-friendly interface and configuration file support.

### Package Discovery

**Get all available packages within a catalog:**

```bash
# Using opm with container registry
opm render registry.redhat.io/redhat/redhat-operator-index:v4.18 \
  | jq -s '.[] | select(.schema == "olm.package") | .name'

# Using catalogd via OpenShift route
curl -k https://catalogd.apps.example.com/catalogs/openshift-redhat-operators/api/v1/all \
  | jq -s '.[] | select(.schema == "olm.package") | .name'
```

### Channel Information

**Query available channels for a specific operator:**

```bash
opm render registry.redhat.io/redhat/redhat-operator-index:v4.18 \
  | jq -s '.[] | select(.schema == "olm.channel") | select(.package == "quay-operator") | .name'
```

### Version Queries

**Query available versions for each channel:**

```bash
opm render registry.redhat.io/redhat/redhat-operator-index:v4.18 \
  | jq -s '.[] | select(.schema == "olm.channel") | select(.package == "quay-operator") |
  { 
    "Channel": .name,
    "Versions": [.entries[].name] | sort
  }'
```

### Bundle Filtering

**Query specific bundle using package and version filters:**

```bash
opm render registry.redhat.io/redhat/redhat-operator-index:v4.18 \
  | jq -s '.[] 
  | select(.schema == "olm.bundle" and any(.properties[] ; .type == "olm.package" and .value.packageName == "quay-operator" and .value.version == "3.10.13"))'
```

### OLMv1 Compatibility

**Check if operator is compatible with OLMv1 (InstallMode == AllNamespaces):**

```bash
opm render registry.redhat.io/redhat/redhat-operator-index:v4.18 \
  | jq -s '.[] | select(.schema == "olm.bundle" and any(.properties[] ; .type == "olm.package" and .value.packageName == "quay-operator" and .value.version == "3.10.13")) | {
    name,
    image,
    SupportAllNamespaces: (.properties[] | select(.type == "olm.csv.metadata").value.installModes[] | select(.type == "AllNamespaces").supported)
  }'
```

### Permission Analysis

**Note**: When analyzing operator permissions, always review both `clusterPermissions` and `permissions` sections. The Quay operator example above only shows `permissions` as it doesn't include `clusterPermissions`.

> **⚠️ macOS/Windows Users**: When using `opm` with Podman, the `--skip-tls` flag may not work due to Podman's client-server architecture. You may need to configure insecure registries within the Podman Machine. See the [RBAC Manager documentation](hack/tools/rbac-manager/README.md#podman-machine-configuration-macoswindows) for detailed setup instructions.

**Query required permissions for an operator:**

```bash
# Basic permission extraction
opm render registry.redhat.io/quay/quay-operator-bundle@sha256:c431ad9dfd69c049e6d9583928630c06b8612879eeed57738fa7be206061fee2 \
  | jq -r '.properties[] | select(.type == "olm.bundle.object") | .value.data' \
  | base64 -d \
  | jq 'select(.kind == "ClusterServiceVersion") | .spec.install.spec.permissions[].rules[]' \
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
