#!/usr/bin/env python3
"""
Shared Test Constants

Common constants used across all test suites to follow DRY principle.
"""

from typing import Dict


class CommonTestConstants:
    """Constants shared across all test suites"""
    
    # Timeouts
    DEFAULT_TIMEOUT = 120
    SHORT_TIMEOUT = 60
    LONG_TIMEOUT = 300
    
    # URLs and tokens
    EXAMPLE_URL = "https://api.example.com:6443"
    MASKED_TOKEN = "***MASKED***"
    TEMP_DIR_PLACEHOLDER = "/tmp/placeholder-output-dir"
    
    # Test results directory
    RESULTS_DIR = "tests/results"
    
    # Common validation keywords
    ERROR_KEYWORDS = ["image", "bundle", "failed", "error"]
    SUCCESS_KEYWORDS = ["success", "completed", "finished"]


class CatalogdTestConstants(CommonTestConstants):
    """Constants specific to catalogd tests"""
    
    # Default test values
    DEFAULT_CATALOG = "openshift-redhat-operators"
    DEFAULT_PACKAGE = "quay-operator"
    DEFAULT_CHANNEL = "stable-3.10"
    DEFAULT_VERSION = "3.10.0"


class OPMTestConstants(CommonTestConstants):
    """Constants specific to OPM tests"""
    
    # Override timeout for OPM tests (typically faster)
    DEFAULT_TIMEOUT = 60
    
    # Namespaces
    DEFAULT_NAMESPACE = "test-namespace"
    PRODUCTION_NAMESPACE = "production"
    OUTPUT_SUBDIR = "test-output"
    
    # Test bundle images - Real operator bundles for comprehensive testing
    ARGOCD_BUNDLE = "quay.io/openshift-community-operators/argocd-operator@sha256:3edc4f132ee4ac9378e331f8eba14a3371132e3274295bfa99c554631e38e8b5"
    GITOPS_BUNDLE = "registry.redhat.io/openshift-gitops-1/gitops-operator-bundle@sha256:53daa863b16b421cc1d9bc7e042cf1ecce9de9913b978561145b319c2a1a8ae5"
    QUAY_BUNDLE = "registry.redhat.io/quay/quay-operator-bundle@sha256:c431ad9dfd69c049e6d9583928630c06b8612879eeed57738fa7be206061fee2"
    INVALID_BUNDLE = "invalid-registry.com/nonexistent/bundle:latest"
    
    # Expected document types
    EXPECTED_YAML_DOCS = ["ServiceAccount", "ClusterRole", "ClusterRoleBinding"]
    EXPECTED_HELM_KEYS = ["operator", "serviceAccount", "permissions"]
    EXPECTED_FILE_PATTERNS = ["serviceaccount", "clusterrole", "clusterrolebinding"]
    
    # Test channels and versions
    STABLE_CHANNEL = "stable"
    ALPHA_CHANNEL = "alpha"
    TEST_VERSION = "1.0.0"
    
    # Validation keywords (extends base class)
    DEDUP_KEYWORDS = ["deduplicated", "dry", "filtered"]
    
    # Formatting patterns
    FLOW_STYLE_PATTERNS = ["apiGroups: [", "resources: [", "verbs: ["]
    RESOURCE_PLACEHOLDER = "#<ADD_CREATED_RESOURCE_NAMES_HERE>"
    CHANNEL_PLACEHOLDER = "#<VERIFY_WITH_CATALOGD_AND_SET_CHANNEL>"
    CHANNEL_GUIDANCE = "IMPORTANT: Verify Correct Channel"


class TestUtilities:
    """Shared test utility methods"""
    
    @staticmethod
    def setup_test_path():
        """Setup Python path for test imports"""
        import sys
        from pathlib import Path
        
        # Add the rbac-manager directory to Python path
        rbac_manager_path = Path(__file__).parent.parent / "rbac-manager"
        if str(rbac_manager_path) not in sys.path:
            sys.path.insert(0, str(rbac_manager_path))
    
    @staticmethod
    def mask_sensitive_data(text: str, url: str = None, token: str = None) -> str:
        """
        Mask sensitive data in text for test output

        Args:
            text: Text to mask
            url: URL to mask (optional)
            token: Token to mask (optional)

        Returns:
            Text with sensitive data masked
        """
        # Use the centralized masking utility from core.utils
        import sys
        from pathlib import Path
        
        # Add rbac-manager to path if not already there
        rbac_manager_path = Path(__file__).parent.parent / "rbac-manager"
        if str(rbac_manager_path) not in sys.path:
            sys.path.insert(0, str(rbac_manager_path))
        
        try:
            from libs.core.utils import mask_sensitive_info
            return mask_sensitive_info(text, url, token)
        except ImportError:
            # Fallback to original implementation if import fails
            masked_text = text

            if token and token in masked_text:
                # Extract the token prefix (e.g., "sha256~") and mask the rest
                if '~' in token:
                    prefix = token.split('~')[0] + '~'
                    masked_token = prefix + CommonTestConstants.MASKED_TOKEN
                else:
                    masked_token = CommonTestConstants.MASKED_TOKEN
                masked_text = masked_text.replace(token, masked_token)

            if url and url in masked_text:
                masked_text = masked_text.replace(url, CommonTestConstants.EXAMPLE_URL)

            return masked_text
    
    @staticmethod
    def create_test_result(test_name: str, success: bool, details: Dict, duration: float = 0.0) -> Dict:
        """
        Create standardized test result structure
        
        Args:
            test_name: Name of the test
            success: Whether the test passed
            details: Test details dictionary
            duration: Test duration in seconds
            
        Returns:
            Standardized test result dictionary
        """
        return {
            "test": test_name,
            "success": success,
            "duration": duration,
            "details": details
        }
    
    @staticmethod
    def get_results_dir() -> str:
        """
        Get the full path to the test results directory, creating it if needed
        
        Returns:
            Full path to the results directory
        """
        from pathlib import Path
        
        # Get the directory where this file is located (tests/)
        tests_dir = Path(__file__).parent
        results_dir = tests_dir / "results"
        
        # Create the directory if it doesn't exist
        results_dir.mkdir(exist_ok=True)
        
        return str(results_dir)
