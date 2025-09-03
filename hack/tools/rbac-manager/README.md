# RBAC Manager for OLM Operators

A unified tool for extracting RBAC (Role-Based Access Control) permissions from OLM (Operator Lifecycle Manager) operators with modern features like configuration file support and automatic cluster discovery.

**Query Methods:**

1. **ClusterCatalog API Queries** - Query via OpenShift ClusterCatalog API using secure port-forward *(Recommended)*
2. **OPM Image Queries** - Query operator images directly using the `opm` tool

**Output Modes:**

1. **Print to Stdout** (default) - Display RBAC YAML in terminal
2. **Deploy to Cluster** (`--deploy`) - Apply RBAC directly using `oc apply -f -`
3. **Save to Files** (`--output DIR`) - Save YAML files to specified directory

## 🚀 Quick Start

### First Time Setup

```bash
# Generate a sample configuration file (recommended for frequent use)
python3 rbac_manager.py --generate-config ~/.rbac-manager.yaml

# Edit the configuration to set your defaults
nano ~/.rbac-manager.yaml

# Now you can use simplified commands!
python3 rbac_manager.py --catalogd --package prometheus
```

### Simple Usage (with auto-discovery)

```bash
# Make sure you're logged into your OpenShift cluster
oc login https://api.your-cluster.com:6443

# Extract RBAC - cluster URL will be auto-discovered!
python3 rbac_manager.py --catalogd --package prometheus

# Deploy directly to cluster
python3 rbac_manager.py --catalogd --package grafana --deploy

# Save RBAC files for later use
python3 rbac_manager.py --catalogd --package cert-manager --output ./rbac-files
```

## 🛠️ Prerequisites

### For ClusterCatalog API Queries (Recommended)

- `oc` (OpenShift CLI) installed and accessible
- OpenShift cluster access with authentication credentials
- Permissions to access `services` in `openshift-catalogd` namespace

### For OPM Queries

- `opm` tool installed and accessible
- Access to operator catalog images
- Container runtime (Docker or Podman) properly configured
  - **macOS/Windows Users**: See [Podman Machine Configuration](#podman-machine-configuration-macoswindows) section for insecure registry setup

## 🔧 Configuration File Support

The RBAC Manager supports configuration files to set default values for frequently used options.

### Configuration File Locations

The tool searches for configuration files in this order:

1. `./rbac-manager.yaml` (current directory)
2. `~/.rbac-manager.yaml` (home directory)
3. `~/.config/rbac-manager.yaml` (XDG config directory)
4. Custom path via `--config /path/to/config.yaml`

### Generate Sample Configuration

```bash
# Generate in default location
python3 rbac_manager.py --generate-config ~/.rbac-manager.yaml

# Generate in custom location  
python3 rbac_manager.py --generate-config /path/to/my-config.yaml
```

### Sample Configuration File

```yaml
# Default catalog settings
catalog:
  name: operatorhubio
  image: quay.io/operatorhubio/catalog:latest

# Default OpenShift settings
openshift:
  url: https://api.my-cluster.com:6443  # Optional - auto-discovered if omitted
  token: ${OPENSHIFT_TOKEN}             # Environment variable expansion
  insecure: false

# Default catalogd settings  
catalogd:
  namespace: openshift-catalogd
  service: catalogd-service
  local_port: 8080

# Default output settings
output:
  directory: ./rbac-output  # Uncomment to set default output directory
  deploy: false

# Default logging settings
logging:
  verbose: false

# Default package (uncomment if you frequently work with specific operator)
# package: prometheus-operator
```

> **💡 Pro Tip**: For macOS/Windows users working with private registries, consider using the ClusterCatalog API method (`--catalogd`) instead of OPM queries to avoid Podman Machine configuration complexities.

### Environment Variable Expansion

Configuration files support environment variable expansion using `${VAR_NAME}` syntax:

```yaml
openshift:
  token: ${OPENSHIFT_TOKEN}
  url: ${CLUSTER_URL}
  
output:
  directory: ${HOME}/rbac-exports
```

## 📚 Usage Examples

### 1. Basic Usage (Auto-Discovery)

```bash
# Print prometheus operator RBAC to terminal (auto-discovers cluster URL)
python3 rbac_manager.py --catalogd --package prometheus

# Using environment variable for token
export OPENSHIFT_TOKEN=sha256~your-token-here
python3 rbac_manager.py --catalogd --package grafana --catalog-name operatorhubio

# With verbose logging
python3 rbac_manager.py --catalogd --package jaeger --verbose
```

### 2. Deploy RBAC Directly to Cluster

```bash
# Deploy prometheus operator RBAC immediately
python3 rbac_manager.py --catalogd --package prometheus --deploy

# Deploy with custom catalog
python3 rbac_manager.py --catalogd --package cluster-logging --catalog-name openshift-redhat-operators --deploy

# Deploy with explicit token
python3 rbac_manager.py --catalogd --openshift-token sha256~your-token --package cert-manager --deploy
```

### 3. Save RBAC Files to Directory

```bash
# Save to custom directory
python3 rbac_manager.py --catalogd --package jaeger --output ./rbac-files

# Save multiple operators
python3 rbac_manager.py --catalogd --output ./all-operators-rbac --verbose

# Save with specific config file
python3 rbac_manager.py --config ~/prod-cluster.yaml --catalogd --package prometheus --output ./prod-rbac
```

### 4. List Available Packages

```bash
# List packages from default catalog (auto-discovers cluster)
python3 rbac_manager.py --catalogd --list-packages

# List packages from specific catalog
python3 rbac_manager.py --catalogd --catalog-name openshift-redhat-operators --list-packages

# List packages supporting AllNamespaces install mode (no webhooks)
python3 rbac_manager.py --catalogd --all-namespaces-packages
```

### 5. Configuration File Usage

```bash
# Use custom configuration file
python3 rbac_manager.py --config ./dev-cluster.yaml --catalogd --package prometheus

# Override config file defaults
python3 rbac_manager.py --config ~/.rbac-manager.yaml --catalogd --package grafana --deploy --verbose

# Generate and use configuration for different environments
python3 rbac_manager.py --generate-config ~/prod-config.yaml
python3 rbac_manager.py --generate-config ~/dev-config.yaml

python3 rbac_manager.py --config ~/prod-config.yaml --catalogd --package cert-manager --deploy
python3 rbac_manager.py --config ~/dev-config.yaml --catalogd --package jaeger --output ./dev-rbac
```

### 6. OPM Image Queries (Alternative Method)

```bash
# List packages from OPM image
python3 rbac_manager.py --opm --image quay.io/operatorhubio/catalog:latest --list-packages

# Extract specific operator via OPM
python3 rbac_manager.py --opm --image quay.io/operatorhubio/catalog:latest --package cert-manager

# Save OPM results to files
python3 rbac_manager.py --opm --image quay.io/operatorhubio/catalog:latest --package prometheus --output ./opm-rbac

# Using insecure registries (see Podman Machine Configuration section for macOS/Windows)
python3 rbac_manager.py --opm --image private-registry.com/catalog:latest --package my-operator --insecure
```

> **⚠️ macOS/Windows Users**: The `--insecure` flag may not work as expected with Podman due to the client-server architecture. If you encounter certificate issues, see the [Podman Machine Configuration](#podman-machine-configuration-macoswindows) section for proper setup instructions.

### 7. Automation & Scripting

```bash
# Using service account token in automation
export OPENSHIFT_TOKEN=$(oc serviceaccounts get-token my-automation-sa -n automation)
python3 rbac_manager.py --catalogd --package prometheus --deploy --verbose

# Batch processing with configuration
cat <<EOF > batch-config.yaml
catalog:
  name: operatorhubio
output:
  directory: ./batch-rbac
logging:
  verbose: true
EOF

# Process multiple operators
for operator in prometheus grafana jaeger cert-manager; do
  python3 rbac_manager.py --config batch-config.yaml --catalogd --package $operator
done
```

## 📁 Architecture

```tree
rbac-manager/
├── rbac_manager.py                    # Main CLI tool
├── libs/                             # Modular library components
│   ├── openshift_auth.py             # Authentication & auto-discovery
│   ├── rbac_manager_core.py          # Core RBAC processing logic
│   ├── config_utils.py               # Configuration file handling
│   ├── opm_query.py                  # OPM image queries
│   ├── catalog_query.py              # ClusterCatalog API queries
│   ├── rbac_utils.py                 # Shared RBAC utilities
│   ├── port_forward_utils.py         # Port-forward management
│   └── logging_utils.py              # Logging configuration
└── README.md                         # This file
```

## 🎯 Output Formats

### Stdout Output (Default)

YAML is printed to terminal with separators:

```yaml
# RBAC Resources for Operator: prometheus
# Generated by RBAC Manager
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: prometheus-cluster-role
rules:
- apiGroups: [""]
  resources: ["nodes", "pods", "services"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: prometheus-cluster-role-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: prometheus-cluster-role
subjects:
- kind: ServiceAccount
  name: prometheus-sa
  namespace: "{{ .Release.Namespace }}"  # Helm template ready
```

### File Output (`--output DIR`)

YAML files are organized by operator in the specified directory:

```tree
specified-directory/
└── prometheus/
    ├── clusterrole.yaml           # ClusterRole definitions
    ├── role.yaml                  # Role definitions (if any)
    ├── clusterrolebinding.yaml    # ClusterRoleBinding templates
    └── rolebinding.yaml           # RoleBinding templates (if any)
```

**Template Features:**

- Uses Helm template syntax: `{{ .Release.Namespace }}`
- Consistent resource naming: `{operator-name}-{resource-type}`
- Ready for Helm chart integration

### Deploy Output (`--deploy`)

RBAC resources are applied directly to the cluster using `oc apply -f -`. No files are created.

## 📘 Common Catalogs

- `operatorhubio` - Community operators from OperatorHub.io (default)
- `openshift-redhat-operators` - Red Hat operators  
- `openshift-certified-operators` - Red Hat certified operators
- `openshift-redhat-marketplace` - OpenShift marketplace operators
- `openshift-community-operators` - Community operators for OpenShift

## 🔧 Troubleshooting

### Configuration Issues

```bash
# Check which config file is being used
python3 rbac_manager.py --catalogd --list-packages --verbose

# Test configuration loading
python3 -c "
from libs.config_utils import ConfigManager
config = ConfigManager()
data = config.load_config()
print(f'Config loaded: {config.config_file_used}')
print(f'Config data: {data}')
"
```

### Cluster Discovery Issues

```bash
# Check if you're logged in
oc whoami

# Check current cluster context
oc config current-context

# Test cluster connectivity
oc cluster-info

# Force explicit URL if auto-discovery fails
python3 rbac_manager.py --catalogd --openshift-url https://api.cluster.com:6443 --package prometheus
```

### Port-Forward Issues

```bash
# Check if oc is available
oc version --client

# Test OpenShift connectivity
oc login https://api.your-cluster.com:6443

# Verify catalogd service access
oc get services -n openshift-catalogd

# Try different local port
python3 rbac_manager.py --catalogd --local-port 9090 --package prometheus
```

### Permission Issues

- Ensure your user/service account has access to `services` in `openshift-catalogd` namespace
- Check if the catalogd service exists: `oc get svc -n openshift-catalogd catalogd-service`
- Verify authentication: `oc auth can-i get services -n openshift-catalogd`

### Token Issues

```bash
# Generate a new token
oc whoami -t

# Use service account tokens for automation
oc serviceaccounts get-token my-sa -n my-namespace

# Verify token validity
oc --token=sha256~your-token whoami
```

### OPM Issues

```bash
# Verify opm installation
opm version

# Test image accessibility
podman pull quay.io/operatorhubio/catalog:latest

# Use insecure flag for self-signed registries
python3 rbac_manager.py --opm --image my-registry.com/catalog:latest --insecure --package prometheus
```

### Podman Machine Configuration (macOS/Windows)

**Important Note**: When using Podman on macOS or Windows, the `--insecure` flag may not work as expected because Podman operates in a client-server model. The actual container operations happen inside a Linux virtual machine (the "Podman Machine"), so registry configuration must be applied within the VM.

#### Symptoms

- `--insecure` flag doesn't resolve certificate issues
- Errors like: `x509: certificate signed by unknown authority`
- OPM commands fail even with insecure flags

#### Solution: Configure Podman Machine

##### **Step 1: SSH into the Podman Machine**

```bash
# This opens a shell inside the Linux VM where containers actually run
podman machine ssh
```

##### **Step 2: Edit Registry Configuration (Inside VM)**

```bash
# Inside the podman machine ssh session
# Use vi or another available editor to add your insecure registry
sudo vi /etc/containers/registries.conf

# Add the following configuration for your private registry:
[[registry]]
location = "your-private-registry.com"
insecure = true

# For multiple registries, add additional blocks:
[[registry]]
location = "another-registry.example.com"  
insecure = true

# Save and exit the editor (:wq in vi)
```

###### **Step 3: Restart Podman Machine (if necessary)**

```bash
# Exit the ssh session
exit

# Stop and start the podman machine from your host (macOS/Windows)
podman machine stop
podman machine start
```

###### **Step 4: Test Configuration**

```bash
# Test that the registry is now accessible
podman pull your-private-registry.com/some-image:latest

# Test with OPM
python3 rbac_manager.py --opm --image your-private-registry.com/catalog:latest --package test-operator
```

#### Alternative: Use Docker Desktop

If you're using Docker Desktop instead of Podman, you can configure insecure registries through the GUI:

1. Open Docker Desktop Settings
2. Go to "Docker Engine" tab
3. Add your registry to the `insecure-registries` array
4. Click "Apply & Restart"

```json
{
  "builder": {
    "gc": {
      "defaultKeepStorage": "20GB",
      "enabled": true
    }
  },
  "experimental": false,
  "features": {
    "buildkit": true
  },
  "insecure-registries": [
    "your-private-registry.com:5000",
    "another-registry.example.com"
  ]
}
```

#### Troubleshooting Podman Machine Issues

```bash
# Check Podman machine status
podman machine list

# View machine logs
podman machine logs

# Reset machine if configuration issues persist
podman machine stop
podman machine rm
podman machine init
podman machine start

# Verify registry configuration is applied
podman machine ssh
cat /etc/containers/registries.conf
```

## 🌍 Environment Variables

- `OPENSHIFT_TOKEN` - OpenShift authentication token (alternative to --openshift-token)
- `CLUSTER_URL` - Can be used in configuration files via `${CLUSTER_URL}`
- `HOME` - Used for default config file locations
