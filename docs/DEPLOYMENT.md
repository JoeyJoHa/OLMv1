# Deployment Process

This guide provides step-by-step instructions for deploying operators using OLMv1 with both YAML manifests and Helm charts.

## Table of Contents

- [Deployment Methods](#deployment-methods)
- [Method 1: YAML Manifest Deployment](#method-1-yaml-manifest-deployment)
  - [Step-by-Step Deployment](#step-by-step-deployment)
    - [Create Project/Namespace](#1-create-projectnamespace)
    - [Deploy Resources](#2-deploy-resources)
    - [Deploy Operator via ClusterExtension](#3-deploy-operator-via-clusterextension)
    - [Monitor Deployment Progress](#4-monitor-deployment-progress)
    - [Verify Installation](#5-verify-installation)
  - [Cleanup Process](#cleanup-process)
- [Method 2: Helm Chart Deployment](#method-2-helm-chart-deployment)
  - [Basic Installation](#basic-installation)
  - [Customized Installation](#customized-installation)
  - [Management Operations](#management-operations)
  - [Configuration Examples](#configuration-examples)
    - [Basic Operator Configuration](#basic-operator-configuration)
    - [Quay Operator Configuration](#quay-operator-configuration)
  - [Resource Naming Convention](#resource-naming-convention)
  - [Permission Types](#permission-types)
    - [Type: "operator"](#type-operator)
    - [Type: "grantor"](#type-grantor)
  - [Enterprise Usage Examples](#enterprise-usage-examples)
    - [Scenario 1: Using Admin-Provided Resources](#scenario-1-using-admin-provided-resources)
    - [Scenario 2: Full Admin with Custom Naming](#scenario-2-full-admin-with-custom-naming)
  - [Key Benefits of the New Approach](#key-benefits-of-the-new-approach)
  - [Advanced Configuration Options](#advanced-configuration-options)
    - [Custom Resource Names](#custom-resource-names)
    - [Using Existing Resources](#using-existing-resources)
    - [Multiple Permission Types](#multiple-permission-types)
  - [Testing and Validation](#testing-and-validation)
    - [Template Rendering Test](#template-rendering-test)
    - [Chart Validation](#chart-validation)
  - [Troubleshooting](#troubleshooting)
    - [Common Issues](#common-issues)
    - [Debug Commands](#debug-commands)

## Deployment Methods

Two deployment methods are available:

- **YAML Manifests**: Direct application of Kubernetes resources
- **Helm Chart**: Template-based deployment with configuration management (recommended)

---

## Method 1: YAML Manifest Deployment

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
oc apply -f examples/yamls/01-serviceaccount.yaml

# Deploy cluster role with optimized permissions
oc apply -f examples/yamls/02-clusterrole.yaml

# Create cluster role binding
oc apply -f examples/yamls/03-clusterrolebinding.yaml
```

#### 3. Deploy Operator via ClusterExtension

```bash
# Apply the ClusterExtension manifest
oc apply -f examples/yamls/04-clusterextension.yaml

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

```bash
# Delete ClusterExtension
oc delete clusterextension quay-operator -n quay-operator

# Wait for operator removal
oc get pods -n quay-operator

# Remove RBAC resources
oc delete -f examples/yamls/03-clusterrolebinding.yaml
oc delete -f examples/yamls/02-clusterrole.yaml
oc delete -f examples/yamls/01-serviceaccount.yaml

# Remove namespace (optional)
oc delete project quay-operator
```

---

## Method 2: Helm Chart Deployment

The project includes a generic Helm chart that can deploy any operator using OLMv1. This is the recommended approach for production deployments.

### Basic Installation

```bash
# Install any operator using the generic chart
helm install my-operator examples/helm/ \
  --namespace my-operator \
  --create-namespace
```

### Customized Installation

```bash
# Use custom values file
helm install my-operator examples/helm/ \
  --namespace my-operator \
  --create-namespace \
  --values examples/helm/values.yaml

# Use operator-specific values (e.g., Quay operator)
helm install quay-operator examples/helm/ \
  --namespace quay-operator \
  --create-namespace \
  --values examples/values/values-quay-operator.yaml
```

### Management Operations

```bash
# Upgrade existing installation
helm upgrade my-operator examples/helm/ \
  --namespace my-operator

# Check release status
helm status my-operator -n my-operator

# List releases
helm list -n my-operator

# Uninstall
helm uninstall my-operator -n my-operator
```

### Configuration Examples

#### Basic Operator Configuration

```yaml
# examples/helm/values.yaml
operator:
  name: "my-operator"
  namespace: "my-operator"
  appVersion: "latest"
  channel: "stable"
  packageName: "my-operator-package"

permissions:
  clusterRoles:
    - name: ""  # Empty = auto-generate: <release>-<chart>-installer
      type: "operator"  # Type: "operator" for operator permissions, "grantor" for RBAC permissions
      create: true
      customRules:    
        - apiGroups: [olm.operatorframework.io]
          resources: [clusterextensions/finalizers]
          verbs: [update]
```

#### Quay Operator Configuration

```yaml
# examples/values/values-quay-operator.yaml
operator:
  name: "quay-operator"
  namespace: "quay-operator"
  appVersion: "3.10.13"
  channel: "stable-3.10"
  packageName: "quay-operator"

permissions:
  clusterRoles:
    # Operator permissions (type: "operator")
    - name: ""  # Auto-generate: <release>-<chart>-installer
      type: "operator"
      create: true
      customRules:    
        - apiGroups: [olm.operatorframework.io]
          resources: [clusterextensions/finalizers]
          verbs: [update]
          resourceNames: [quay-operator]
        - apiGroups: [apiextensions.k8s.io]
          resources: [customresourcedefinitions]
          verbs: [create, list, watch]
    
    # RBAC permissions (type: "grantor")
    - name: ""  # Auto-generate: <release>-<chart>-installer-grantor
      type: "grantor"
      create: true
      customRules:    
        - apiGroups: ["quay.redhat.com"]
          resources: ["quayregistries", "quayregistries/status"]
          verbs: ["*"]
        - apiGroups: ["apps"]
          resources: ["deployments"]
          verbs: ["*"]
```

### Resource Naming Convention

The Helm chart uses a consistent naming pattern for all resources:

- **ServiceAccount**: `<release>-<chart>-installer`
- **ClusterRole (operator)**: `<release>-<chart>-installer`
- **ClusterRole (grantor)**: `<release>-<chart>-installer-grantor`
- **ClusterRoleBinding**: `<release>-<chart>-installer-crb`
- **ClusterExtension**: Uses `operator.name` if specified, otherwise `<release>`

Example with release `quay-test` and chart `operator-olm-v1`:

- ServiceAccount: `quay-test-operator-olm-v1-installer`
- ClusterRole: `quay-test-operator-olm-v1-installer`
- ClusterExtension: `quay-operator` (if `operator.name: "quay-operator"`)

### Permission Types

#### Type: "operator"

- Purpose: Permissions needed by the operator to function
- Examples: CRD management, finalizer updates, operator-specific resources
- Naming: `-installer` suffix

#### Type: "grantor"

- Purpose: RBAC permissions to manage other resources
- Examples: Managing deployments, services, roles, rolebindings
- Naming: `-installer-grantor` suffix

### Enterprise Usage Examples

#### Scenario 1: Using Admin-Provided Resources

When cluster administrators provide pre-configured RBAC resources, you can configure the Helm chart to use them:

```yaml
operator:
  name: "quay-operator"
  namespace: "quay-operator"

serviceAccount:
  create: false
  name: "admin-provided-operator-sa"
  bind: false

permissions: {}  # No resources created
```

#### Scenario 2: Full Admin with Custom Naming

When you have full administrative access and need specific resource names:

```yaml
operator:
  name: "quay-operator"
  namespace: "quay-operator"

serviceAccount:
  create: true
  name: "quay-operator-installer"
  bind: true

permissions:
  clusterRoles:
    - name: "quay-operator-admin"
      type: "operator"
      create: true
      customRules:
        - apiGroups: [olm.operatorframework.io]
          resources: [clusterextensions/finalizers]
          verbs: [update]
```

### Key Benefits of the New Approach

- **Reusable**: Deploy any operator available in OLM catalogs
- **Configurable**: Flexible RBAC with type-based permission management
- **Consistent**: Standardized deployment pattern for all operators
- **Production Ready**: Designed for enterprise environments
- **Resource Management**: Support for using pre-existing RBAC resources
- **Clear Permissions**: Distinction between operator and grantor permissions

### Advanced Configuration Options

#### Custom Resource Names

When you need specific resource names:

```yaml
operator:
  name: "quay-operator"
  namespace: "quay-operator"

serviceAccount:
  create: true
  name: "quay-operator-installer"
  bind: true

permissions:
  clusterRoles:
    - name: "quay-operator-admin"
      type: "operator"
      create: true
      customRules: [...]
```

#### Using Existing Resources

When cluster admins provide pre-configured RBAC resources:

```yaml
permissions:
  clusterRoles:
    - name: "admin-provided-role"
      type: "operator"
      create: false  # Use existing resource
```

#### Multiple Permission Types

```yaml
permissions:
  clusterRoles:
    # Operator permissions
    - type: "operator"
      create: true
      customRules: [...]
    
    # RBAC permissions
    - type: "grantor"
      create: true
      customRules: [...]
```

### Testing and Validation

#### Template Rendering Test

```bash
# Test template rendering without deployment
helm template <release-name> helm/ --values <values-file>
```

#### Chart Validation

```bash
# Lint the chart for best practices
helm lint helm/

# Validate against Kubernetes schemas
helm template <release-name> helm/ | kubeval
```

### Troubleshooting

#### Common Issues

| Issue | Solution |
|-------|----------|
| Permission Denied | Ensure `serviceAccount.bind: true` when creating RBAC resources |
| Resource Naming Conflicts | Use custom names or ensure unique release names |
| Missing Type Field | Always specify `type: "operator"` or `type: "grantor"` |

#### Debug Commands

```bash
# Check generated resources
helm get manifest <release-name> -n <namespace>

# Verify RBAC bindings
kubectl get clusterrolebinding | grep <operator-name>

# Check operator status
kubectl get clusterextension -n <namespace>
```
