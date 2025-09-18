"""
Constants Module

Centralized constants for the RBAC Manager tool to eliminate magic strings
and improve maintainability.
"""


class KubernetesConstants:
    """Kubernetes-related constants with improved enum-based structure"""
    
    from enum import Enum
    
    # Namespace constants - simple attributes for configurable values
    DEFAULT_NAMESPACE = "default"
    OPENSHIFT_CATALOGD_NAMESPACE = "openshift-catalogd"
    
    # API Group constants - simple attributes for extensible values
    OLM_API_GROUP = "olm.operatorframework.io"
    RBAC_API_GROUP = "rbac.authorization.k8s.io"
    APIEXTENSIONS_API_GROUP = "apiextensions.k8s.io"
    CORE_API_GROUP = ""  # Core API group (empty string)
    APPS_API_GROUP = "apps"
    
    # Label constants - simple attributes for standard Kubernetes labels
    MANAGED_BY_LABEL = "app.kubernetes.io/managed-by"
    NAME_LABEL = "app.kubernetes.io/name"
    
    # Component constants - simple attributes for configurable values
    RBAC_MANAGER_COMPONENT = "rbac-manager"
    OLM_COMPONENT = "olm"
    
    # Channel constants - simple attributes for configurable values
    DEFAULT_CHANNEL = "stable"
    
    class RBACVerb(str, Enum):
        """RBAC verbs used in Kubernetes role definitions"""
        CREATE = "create"
        GET = "get"
        LIST = "list"
        WATCH = "watch"
        UPDATE = "update"
        PATCH = "patch"
        DELETE = "delete"
        WILDCARD = "*"
        
        def __str__(self) -> str:
            """Return the verb value for use in RBAC rules"""
            return self.value
        
        @classmethod
        def get_read_verbs(cls) -> list:
            """Get all read-only RBAC verbs"""
            return [cls.GET, cls.LIST, cls.WATCH]
        
        @classmethod
        def get_write_verbs(cls) -> list:
            """Get all write RBAC verbs"""
            return [cls.CREATE, cls.UPDATE, cls.PATCH, cls.DELETE]
        
        @classmethod
        def get_all_verbs(cls) -> list:
            """Get all RBAC verbs except wildcard"""
            return [cls.CREATE, cls.GET, cls.LIST, cls.WATCH, cls.UPDATE, cls.PATCH, cls.DELETE]
    
    class ResourceName(str, Enum):
        """Kubernetes resource names used in the RBAC Manager tool"""
        # Core RBAC resources
        CLUSTER_ROLES = "clusterroles"
        CLUSTER_ROLE_BINDINGS = "clusterrolebindings"
        ROLES = "roles"
        ROLE_BINDINGS = "rolebindings"
        SERVICE_ACCOUNTS = "serviceaccounts"
        
        # OLM resources
        CLUSTER_EXTENSIONS = "clusterextensions"
        CUSTOM_RESOURCE_DEFINITIONS = "customresourcedefinitions"
        
        # Application resources
        DEPLOYMENTS = "deployments"
        
        def __str__(self) -> str:
            """Return the resource name for use in Kubernetes API calls"""
            return self.value
        
        @classmethod
        def get_rbac_resources(cls) -> list:
            """Get all RBAC-related resource names"""
            return [
                cls.CLUSTER_ROLES, 
                cls.CLUSTER_ROLE_BINDINGS, 
                cls.ROLES, 
                cls.ROLE_BINDINGS,
                cls.SERVICE_ACCOUNTS
            ]
        
        @classmethod
        def get_olm_resources(cls) -> list:
            """Get all OLM-related resource names"""
            return [cls.CLUSTER_EXTENSIONS, cls.CUSTOM_RESOURCE_DEFINITIONS]


class OPMConstants:
    """OPM-related constants with improved enum-based structure"""
    
    from enum import Enum
    
    # Bundle metadata keys (internal storage) - simple attributes for configurable values
    BUNDLE_PERMISSIONS_KEY = "permissions"
    BUNDLE_CLUSTER_PERMISSIONS_KEY = "cluster_permissions"
    
    class BundleSchema(str, Enum):
        """OLM bundle schema types"""
        BUNDLE = "olm.bundle"
        PACKAGE = "olm.package"
        CHANNEL = "olm.channel"
        
        def __str__(self) -> str:
            """Return the schema value for use in bundle metadata"""
            return self.value
    
    class PropertyType(str, Enum):
        """OLM property types used in bundle metadata"""
        GVK = "olm.gvk"
        BUNDLE_OBJECT = "olm.bundle.object"
        PACKAGE = "olm.package"
        
        def __str__(self) -> str:
            """Return the property type value for use in bundle processing"""
            return self.value
    
    class ManifestKind(str, Enum):
        """Kubernetes manifest kinds used in operator bundles"""
        CLUSTER_SERVICE_VERSION = "ClusterServiceVersion"
        CUSTOM_RESOURCE_DEFINITION = "CustomResourceDefinition"
        
        def __str__(self) -> str:
            """Return the manifest kind for use in Kubernetes API calls"""
            return self.value
        
        @classmethod
        def get_operator_kinds(cls) -> list:
            """Get all operator-related manifest kinds"""
            return [cls.CLUSTER_SERVICE_VERSION, cls.CUSTOM_RESOURCE_DEFINITION]
    
    class CSVSection(str, Enum):
        """ClusterServiceVersion (CSV) sections used in operator manifests"""
        SPEC = "spec"
        METADATA = "metadata"
        INSTALL = "install"
        PERMISSIONS = "permissions"
        CLUSTER_PERMISSIONS = "clusterPermissions"
        CRD = "customresourcedefinitions"
        OWNED_CRDS = "owned"
        DEPLOYMENTS = "deployments"
        
        def __str__(self) -> str:
            """Return the CSV section name for use in manifest parsing"""
            return self.value
        
        @classmethod
        def get_permission_sections(cls) -> list:
            """Get CSV sections related to permissions"""
            return [cls.PERMISSIONS, cls.CLUSTER_PERMISSIONS]
        
        @classmethod
        def get_install_sections(cls) -> list:
            """Get CSV sections related to installation"""
            return [cls.INSTALL, cls.DEPLOYMENTS]


class NetworkConstants:
    """Network-related constants with improved enum-based structure"""
    
    from enum import Enum, IntEnum
    
    # Timeout constants (seconds) - simple attributes for configurable values
    DEFAULT_TIMEOUT = 30
    BUNDLE_EXTRACTION_TIMEOUT = 300
    PORT_FORWARD_TIMEOUT = 60
    SSL_HANDSHAKE_TIMEOUT = 10
    
    # Buffer size constants - simple attributes for configurable values
    DEFAULT_BUFFER_SIZE = 8192
    
    # User Agent - simple attribute for configurable value
    USER_AGENT = "rbac-manager/1.0"
    
    class HTTPStatus(IntEnum):
        """HTTP status codes used in the RBAC Manager tool"""
        OK = 200
        UNAUTHORIZED = 401
        FORBIDDEN = 403
        NOT_FOUND = 404
        INTERNAL_SERVER_ERROR = 500
        SERVICE_UNAVAILABLE = 503
        
        def __str__(self) -> str:
            """Return a human-readable description of the status code"""
            descriptions = {
                200: "OK",
                401: "Unauthorized", 
                403: "Forbidden",
                404: "Not Found",
                500: "Internal Server Error",
                503: "Service Unavailable"
            }
            return f"{self.value} {descriptions.get(self.value, 'Unknown')}"
    
    class ContentType(Enum):
        """Content-Type header values"""
        JSON = "application/json"
        YAML = "application/yaml"
        TEXT_PLAIN = "text/plain"
        
        def __str__(self) -> str:
            """Return the content type value for use in headers"""
            return self.value
    
    class HTTPHeader(Enum):
        """Standard HTTP header names"""
        AUTHORIZATION = "Authorization"
        CONTENT_TYPE = "Content-Type"
        CONTENT_LENGTH = "Content-Length"
        CONTENT_ENCODING = "Content-Encoding"
        USER_AGENT = "User-Agent"
        ACCEPT = "Accept"
        
        def __str__(self) -> str:
            """Return the header name for use in HTTP requests"""
            return self.value


class ErrorMessages:
    """Centralized error message templates with improved enum-based structure"""
    
    from enum import Enum
    
    class SSLError(str, Enum):
        """SSL-related error message templates"""
        CERT_VERIFICATION_FAILED = (
            "SSL certificate verification failed. The OpenShift cluster is using self-signed certificates.\n"
            "To resolve this issue, add the --skip-tls flag to your command.\n"
            "Example: python3 rbac-manager.py --catalogd --skip-tls [other options]"
        )
        
        CONNECTION_ERROR = (
            "SSL connection error occurred. If using self-signed certificates, add --skip-tls flag.\n"
            "Original error: {error}"
        )
        
        def __str__(self) -> str:
            """Return the error message template"""
            return self.value
    
    class AuthError(str, Enum):
        """Authentication-related error message templates"""
        NOT_CONFIGURED = "Authentication not configured. Configure authentication first."
        TOKEN_EXPIRED = "Authentication token has expired or is invalid."
        INSUFFICIENT_PERMISSIONS = "Insufficient permissions to access the requested resource."
        
        def __str__(self) -> str:
            """Return the error message template"""
            return self.value
    
    class CatalogdError(str, Enum):
        """Catalogd service error message templates"""
        SERVICE_NOT_FOUND = "No catalogd service found in openshift-catalogd namespace"
        SERVICE_NOT_INITIALIZED = "Catalogd service not initialized. Configure authentication first."
        
        CATALOG_NOT_FOUND = (
            "Catalog '{catalog_name}' not found on the cluster.\n"
            "This could mean:\n"
            "  • The catalog name is misspelled\n"
            "  • The catalog is not installed on this cluster\n"
            "  • The catalog is not in 'Serving' state\n\n"
            "Available catalogs: {available_catalogs}\n\n"
            "To list all available catalogs, run:\n"
            "  python3 rbac-manager.py list-catalogs"
        )
        
        def __str__(self) -> str:
            """Return the error message template"""
            return self.value
    
    class OPMError(str, Enum):
        """OPM tool error message templates"""
        BINARY_NOT_FOUND = (
            "OPM binary not found. Please install the OPM CLI tool and ensure it's in your PATH. "
            "Visit: https://github.com/operator-framework/operator-registry/releases"
        )
        
        def __str__(self) -> str:
            """Return the error message template"""
            return self.value
    
    class NetworkError(str, Enum):
        """Network-related error message templates"""
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
        
        def __str__(self) -> str:
            """Return the error message template"""
            return self.value
    
    class ConfigError(str, Enum):
        """Configuration-related error message templates"""
        INVALID_IMAGE_URL = "Invalid container image URL format: {image}"
        INVALID_NAMESPACE = "Invalid Kubernetes namespace format: {namespace}"
        INVALID_OPENSHIFT_URL = "Invalid OpenShift URL format: {url}"
        CONFIG_FILE_NOT_FOUND = "Configuration file not found: {config_path}"
        
        def __str__(self) -> str:
            """Return the error message template"""
            return self.value
        
        @classmethod
        def get_validation_errors(cls) -> list:
            """Get all validation-related error templates"""
            return [cls.INVALID_IMAGE_URL, cls.INVALID_NAMESPACE, cls.INVALID_OPENSHIFT_URL]


class FileConstants:
    """File and directory related constants with improved enum-based structure"""
    
    from enum import Enum
    
    # Configuration file constants - simple attributes for configurable values
    DEFAULT_CONFIG_FILE = "rbac-manager-config.yaml"
    AUTH_FILE_NAME = "auth.json"
    HELM_VALUES_FILE = "values.yaml"
    
    # Directory constants - simple attributes for configurable values
    CACHE_DIR_NAME = "rbac-manager-cache"
    
    class OutputFilePrefix(str, Enum):
        """Output file prefixes for generated RBAC manifests"""
        SERVICE_ACCOUNT = "01-serviceaccount"
        CLUSTER_ROLE = "02-clusterrole"
        CLUSTER_ROLE_BINDING = "03-clusterrolebinding"
        ROLE = "04-role"
        ROLE_BINDING = "05-rolebinding"
        
        def __str__(self) -> str:
            """Return the prefix value for use in file naming"""
            return self.value
        
        @classmethod
        def get_rbac_prefixes(cls) -> list:
            """Get all RBAC-related file prefixes in order"""
            return [
                cls.SERVICE_ACCOUNT,
                cls.CLUSTER_ROLE,
                cls.CLUSTER_ROLE_BINDING,
                cls.ROLE,
                cls.ROLE_BINDING
            ]
        
        @classmethod
        def get_cluster_prefixes(cls) -> list:
            """Get cluster-scoped RBAC file prefixes"""
            return [cls.CLUSTER_ROLE, cls.CLUSTER_ROLE_BINDING]
        
        @classmethod
        def get_namespace_prefixes(cls) -> list:
            """Get namespace-scoped RBAC file prefixes"""
            return [cls.SERVICE_ACCOUNT, cls.ROLE, cls.ROLE_BINDING]
    
    class FileExtension(str, Enum):
        """File extensions used in the RBAC Manager tool"""
        YAML = ".yaml"
        JSON = ".json"
        YML = ".yml"
        
        def __str__(self) -> str:
            """Return the extension value for use in file operations"""
            return self.value
        
        @classmethod
        def get_config_extensions(cls) -> list:
            """Get file extensions for configuration files"""
            return [cls.YAML, cls.YML, cls.JSON]
        
        @classmethod
        def get_manifest_extensions(cls) -> list:
            """Get file extensions for Kubernetes manifests"""
            return [cls.YAML, cls.YML]


