# Operator Lifecycle Manager V1 (OLMv1)

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Key Components](#key-components)
- [Deployment Flow](#deployment-flow)
- [Sequence Diagram](#sequence-diagram)
- [Project Structure](#project-structure)
- [Deployment Process](#deployment-process)
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
├── bundle/                             # Operator bundle files
│   ├── ClusterServiceVersion.json      # Quay operator CSV
│   ├── Service.json                    # Quay operator service
│   └── CustomResourceDefinition.json   # Quay operator CRD
├── Manifests/                          # Manual deployment YAML files
│   ├── 00-namespace.yaml               # Namespace definition
│   ├── 01-serviceaccount.yaml          # Service account for operator
│   ├── 02-clusterrole.yaml             # Cluster role with least privilege
│   ├── 03-clusterrolebinding.yaml      # Cluster role binding
│   └── 04-clusterextension.yaml        # OLMv1 ClusterExtension
├── .git/                               # Git repository
├── .gitignore                          # Git ignore patterns
├── .cursor/                            # Cursor IDE configuration
└── .cursorignore                       # Cursor ignore patterns
```

## Deployment Process

### Step-by-Step Deployment

#### 1. Create Project/Namespace

```bash
# Create new project for the operator or apply namespace manifest.
oc new-project quay-operator

# Or use existing project
oc project quay-operator
```

#### 2. Deploy Resources

```bash

# Deploy service account
oc apply -f Manifests/01-serviceaccount.yaml

# Deploy cluster role with least privilege
oc apply -f Manifests/02-clusterrole.yaml

# Create cluster role binding
oc apply -f Manifests/03-clusterrolebinding.yaml
```

#### 3. Deploy Operator via ClusterExtension

```bash
# Apply the ClusterExtension manifest
oc apply -f Manifests/04-clusterextension.yaml

# Verify ClusterExtension creation
oc get clusterextension quay-operator -n quay-operator

# Check ClusterExtension status
oc describe clusterextension quay-operator -n quay-operator
```

#### 4. Monitor Deployment Progress

```bash
# Watch operator deployment
oc get pods -n quay-operator -w

# Check operator logs
oc logs -n quay-operator -l app.kubernetes.io/name=quay-operator

# Monitor ClusterExtension status
oc get clusterextension quay-operator -n quay-operator -o yaml
```

#### 5. Verify Installation

```bash
# Check if CRDs are installed
oc get crd | grep quay.redhat.com

# Verify operator deployment
oc get deployment -n quay-operator
```

### Cleanup Process

#### Remove Operator

```bash
# Delete ClusterExtension
oc delete clusterextension quay-operator -n quay-operator

# Wait for operator removal
oc get pods -n quay-operator

# Remove RBAC resources
oc delete -f Manifests/03-clusterrolebinding.yaml
oc delete -f Manifests/02-clusterrole.yaml
oc delete -f Manifests/01-serviceaccount.yaml

# Remove namespace (optional)
oc delete project quay-operator
```

## Command Reference

This section provides practical commands for interacting with OLMv1 catalogs and analyzing operator bundles. Most commands use the `opm` tool, but equivalent `catalogd` interactions are also shown.

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
