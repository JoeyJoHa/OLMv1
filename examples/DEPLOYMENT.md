# Deployment Process

## Step-by-Step Deployment

### 1. Create Project/Namespace

```bash
# Create new project for the operator or apply namespace manifest.
oc new-project quay-operator

# Or use existing project
oc project quay-operator
```

### 2. Deploy Resources

```bash

# Deploy service account
oc apply -f examples/quay-operator/yamls/01-serviceaccount.yaml

# Deploy cluster role with least privilege
oc apply -f examples/quay-operator/yamls/02-clusterrole.yaml

# Create cluster role binding
oc apply -f examples/quay-operator/yamls/03-clusterrolebinding.yaml
```

### 3. Deploy Operator via ClusterExtension

```bash
# Apply the ClusterExtension manifest
oc apply -f examples/quay-operator/yamls/04-clusterextension.yaml

# Verify ClusterExtension creation
oc get clusterextension quay-operator -n quay-operator

# Check ClusterExtension status
oc describe clusterextension quay-operator -n quay-operator
```

### 4. Monitor Deployment Progress

```bash
# Watch operator deployment
oc get pods -n quay-operator -w

# Check operator logs
oc logs -n quay-operator -l app.kubernetes.io/name=quay-operator

# Monitor ClusterExtension status
oc get clusterextension quay-operator -n quay-operator -o yaml
```

### 5. Verify Installation

```bash
# Check if CRDs are installed
oc get crd | grep quay.redhat.com

# Verify operator deployment
oc get deployment -n quay-operator
```

## Cleanup Process

### Remove Operator

```bash
# Delete ClusterExtension
oc delete clusterextension quay-operator -n quay-operator

# Wait for operator removal
oc get pods -n quay-operator

# Remove RBAC resources
oc delete -f examples/quay-operator/yamls/03-clusterrolebinding.yaml
oc delete -f examples/quay-operator/yamls/02-clusterrole.yaml
oc delete -f examples/quay-operator/yamls/01-serviceaccount.yaml

# Remove namespace (optional)
oc delete project quay-operator
```

## Helm Chart Deployment

The project provides a **generic Helm chart** that can deploy any operator using OLMv1:

```bash
# Install any operator using the generic chart
helm install my-operator examples/helm/ \
  --namespace my-operator \
  --create-namespace

# Customize values
helm install my-operator examples/helm/ \
  --namespace my-operator \
  --create-namespace \
  --values examples/helm/values.yaml

# Upgrade existing installation
helm upgrade my-operator examples/helm/ \
  --namespace my-operator

# Uninstall
helm uninstall my-operator -n my-operator
```

**Key Benefits of the Generic Chart:**

- **Reusable**: Deploy any operator available in OLM catalogs
- **Configurable**: Flexible RBAC and service account configuration
- **Best Practices**: Follows Helm and Kubernetes best practices
- **Consistent**: Standardized deployment pattern for all operators
