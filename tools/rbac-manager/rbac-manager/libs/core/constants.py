"""
Constants Module

Centralized constants for the RBAC Manager tool to eliminate magic strings
and improve maintainability.
"""


class KubernetesConstants:
    """Kubernetes-related constants"""
    
    # Namespaces
    DEFAULT_NAMESPACE = "default"
    OPENSHIFT_CATALOGD_NAMESPACE = "openshift-catalogd"
    
    # API Groups
    OLM_API_GROUP = "olm.operatorframework.io"
    RBAC_API_GROUP = "rbac.authorization.k8s.io"
    APIEXTENSIONS_API_GROUP = "apiextensions.k8s.io"
    CORE_API_GROUP = ""  # Core API group (empty string)
    
    # Labels
    MANAGED_BY_LABEL = "app.kubernetes.io/managed-by"
    NAME_LABEL = "app.kubernetes.io/name"
    
    # Label Values
    RBAC_MANAGER_COMPONENT = "rbac-manager"
    OLM_COMPONENT = "olm"
    
    # Ports
    HTTPS_PORT = 443
    CATALOGD_TARGET_PORT = 8443
    
    # Channels and Versions
    DEFAULT_CHANNEL = "stable"
    LATEST_VERSION = "latest"
    
    # Resource Names
    CLUSTER_EXTENSIONS_RESOURCE = "clusterextensions"
    CLUSTER_ROLES_RESOURCE = "clusterroles"
    CLUSTER_ROLE_BINDINGS_RESOURCE = "clusterrolebindings"
    CUSTOM_RESOURCE_DEFINITIONS_RESOURCE = "customresourcedefinitions"
    ROLES_RESOURCE = "roles"
    ROLE_BINDINGS_RESOURCE = "rolebindings"
    SERVICE_ACCOUNTS_RESOURCE = "serviceaccounts"
    
    # RBAC Verbs
    CREATE_VERB = "create"
    GET_VERB = "get"
    LIST_VERB = "list"
    WATCH_VERB = "watch"
    UPDATE_VERB = "update"
    PATCH_VERB = "patch"
    DELETE_VERB = "delete"
    WILDCARD_VERB = "*"


class OPMConstants:
    """OPM-related constants"""
    
    # Bundle schemas
    OLM_BUNDLE_SCHEMA = "olm.bundle"
    OLM_PACKAGE_SCHEMA = "olm.package"
    OLM_CHANNEL_SCHEMA = "olm.channel"
    
    # Property types
    OLM_GVK_PROPERTY = "olm.gvk"
    OLM_BUNDLE_OBJECT_PROPERTY = "olm.bundle.object"
    OLM_PACKAGE_PROPERTY = "olm.package"
    
    # Manifest kinds
    CLUSTER_SERVICE_VERSION_KIND = "ClusterServiceVersion"
    CUSTOM_RESOURCE_DEFINITION_KIND = "CustomResourceDefinition"
    DEPLOYMENT_KIND = "Deployment"
    SERVICE_KIND = "Service"
    CONFIG_MAP_KIND = "ConfigMap"
    SECRET_KIND = "Secret"
    
    # CSV Sections
    CSV_SPEC_SECTION = "spec"
    CSV_METADATA_SECTION = "metadata"
    CSV_INSTALL_SECTION = "install"
    CSV_PERMISSIONS_SECTION = "permissions"
    CSV_CLUSTER_PERMISSIONS_SECTION = "clusterPermissions"
    CSV_CRD_SECTION = "customresourcedefinitions"
    CSV_OWNED_CRDS_SECTION = "owned"
    
    # Bundle metadata keys (internal storage)
    BUNDLE_PERMISSIONS_KEY = "permissions"
    BUNDLE_CLUSTER_PERMISSIONS_KEY = "cluster_permissions"


class NetworkConstants:
    """Network-related constants"""
    
    # Timeouts (seconds)
    DEFAULT_TIMEOUT = 30
    BUNDLE_EXTRACTION_TIMEOUT = 300
    PORT_FORWARD_TIMEOUT = 60
    SSL_HANDSHAKE_TIMEOUT = 10
    
    # Buffer sizes
    DEFAULT_BUFFER_SIZE = 8192
    LARGE_BUFFER_SIZE = 65536
    LARGE_RESPONSE_THRESHOLD = 1000000  # 1MB
    
    # HTTP Status Codes
    HTTP_OK = 200
    HTTP_NOT_FOUND = 404
    HTTP_UNAUTHORIZED = 401
    HTTP_FORBIDDEN = 403
    HTTP_INTERNAL_SERVER_ERROR = 500
    HTTP_SERVICE_UNAVAILABLE = 503
    
    # Content Types
    CONTENT_TYPE_JSON = "application/json"
    CONTENT_TYPE_YAML = "application/yaml"
    
    # Headers
    AUTHORIZATION_HEADER = "Authorization"
    CONTENT_TYPE_HEADER = "Content-Type"
    CONTENT_LENGTH_HEADER = "Content-Length"
    CONTENT_ENCODING_HEADER = "Content-Encoding"
    USER_AGENT_HEADER = "User-Agent"
    
    # User Agent
    USER_AGENT = "rbac-manager/1.0"


class ErrorMessages:
    """Centralized error message templates"""
    
    # SSL-related errors
    SSL_CERT_VERIFICATION_FAILED = (
        "SSL certificate verification failed. The OpenShift cluster is using self-signed certificates.\n"
        "To resolve this issue, add the --skip-tls flag to your command.\n"
        "Example: python3 rbac-manager.py --catalogd --skip-tls [other options]"
    )
    
    SSL_CONNECTION_ERROR = (
        "SSL connection error occurred. If using self-signed certificates, add --skip-tls flag.\n"
        "Original error: {error}"
    )
    
    # Authentication errors
    AUTH_NOT_CONFIGURED = "Authentication not configured. Configure authentication first."
    AUTH_TOKEN_EXPIRED = "Authentication token has expired or is invalid."
    AUTH_INSUFFICIENT_PERMISSIONS = "Insufficient permissions to access the requested resource."
    
    # Catalogd errors
    CATALOGD_SERVICE_NOT_FOUND = "No catalogd service found in openshift-catalogd namespace"
    CATALOGD_SERVICE_NOT_INITIALIZED = "Catalogd service not initialized. Configure authentication first."
    CATALOG_NOT_FOUND = (
        "Catalog '{catalog_name}' not found on the cluster.\n"
        "This could mean:\n"
        "  • The catalog name is misspelled\n"
        "  • The catalog is not installed on this cluster\n"
        "  • The catalog is not in 'Serving' state\n\n"
        "Available catalogs: {available_catalogs}\n\n"
        "To list all available catalogs, run:\n"
        "  python3 rbac-manager.py --list-catalogs"
    )
    
    # OPM errors
    OPM_BINARY_NOT_FOUND = (
        "OPM binary not found. Please install the OPM CLI tool and ensure it's in your PATH. "
        "Visit: https://github.com/operator-framework/operator-registry/releases"
    )
    
    # Network errors
    CONNECTION_TIMEOUT = (
        "Connection timeout or network error occurred.\n"
        "This could mean:\n"
        "  • The catalogd service is not responding\n"
        "  • Network connectivity issues to the cluster\n"
        "  • The port-forward connection was interrupted\n\n"
        "Try:\n"
        "  • Checking cluster connectivity: kubectl get pods -n openshift-catalogd\n"
        "  • Retrying the command\n"
        "  • Using --debug flag for more detailed logs"
    )
    
    CONNECTION_REFUSED = (
        "Connection refused to catalogd service.\n"
        "This usually means:\n"
        "  • The catalogd service is not running\n"
        "  • Port-forward failed to establish\n"
        "  • Firewall or network policy blocking connection\n\n"
        "Try:\n"
        "  • Checking catalogd status: kubectl get pods -n openshift-catalogd\n"
        "  • Verifying service: kubectl get svc -n openshift-catalogd\n"
        "  • Retrying with --debug for detailed logs"
    )
    
    # Configuration errors
    INVALID_IMAGE_URL = "Invalid container image URL format: {image}"
    INVALID_NAMESPACE = "Invalid Kubernetes namespace format: {namespace}"
    INVALID_OPENSHIFT_URL = "Invalid OpenShift URL format: {url}"
    CONFIG_FILE_NOT_FOUND = "Configuration file not found: {config_path}"


class FileConstants:
    """File and directory related constants"""
    
    # Configuration files
    DEFAULT_CONFIG_FILE = "rbac-manager-config.yaml"
    AUTH_FILE_NAME = "auth.json"
    
    # Cache directories
    CACHE_DIR_NAME = "rbac-manager-cache"
    
    # Output file prefixes
    SERVICE_ACCOUNT_PREFIX = "01-serviceaccount"
    CLUSTER_ROLE_PREFIX = "02-clusterrole"
    CLUSTER_ROLE_BINDING_PREFIX = "03-clusterrolebinding"
    ROLE_PREFIX = "04-role"
    ROLE_BINDING_PREFIX = "05-rolebinding"
    
    # File extensions
    YAML_EXTENSION = ".yaml"
    JSON_EXTENSION = ".json"
    
    # Helm files
    HELM_VALUES_FILE = "values.yaml"


class RoleConstants:
    """RBAC role related constants"""
    
    # Role types
    OPERATOR_ROLE_TYPE = "operator"
    GRANTOR_ROLE_TYPE = "grantor"
    
    # Role name suffixes
    INSTALLER_SUFFIX = "-installer"
    CLUSTERROLE_SUFFIX = "-clusterrole"
    RBAC_CLUSTERROLE_SUFFIX = "-rbac-clusterrole"
    CLUSTERROLEBINDING_SUFFIX = "-clusterrolebinding"
    RBAC_CLUSTERROLEBINDING_SUFFIX = "-rbac-clusterrolebinding"
    ROLE_SUFFIX = "-role"
    ROLEBINDING_SUFFIX = "-rolebinding"
    
    # Service account naming
    SERVICE_ACCOUNT_SUFFIX = "-installer"


class LoggingConstants:
    """Logging related constants"""
    
    # Log levels
    DEBUG_LEVEL = "DEBUG"
    INFO_LEVEL = "INFO"
    WARNING_LEVEL = "WARNING"
    ERROR_LEVEL = "ERROR"
    
    # Log formats
    DEFAULT_LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
    DEBUG_LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
