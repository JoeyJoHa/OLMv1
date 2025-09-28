#!/usr/bin/env python3
"""
Shared Test Constants

Common constants used across all test suites.
"""

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Any


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
    """
    Shared test utility methods for all test suites.
    
    Provides common functionality for test execution, data masking,
    and result formatting across catalogd, OPM, and workflow tests.
    
    This class centralizes common test
    operations and ensuring consistent behavior across all test suites.
    """
    
    @staticmethod
    def setup_test_path():
        """Setup Python path for test imports"""
        
        # Add the rbac-manager directory to Python path
        rbac_manager_path = Path(__file__).parent / "tools" / "rbac-manager"
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
        # Assumes setup_test_path() has already been called to set up sys.path
        try:
            from libs.core.utils import mask_sensitive_info  # pyright: ignore[reportMissingImports]
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
        
        # Get the directory where this file is located (tests/)
        tests_dir = Path(__file__).parent
        results_dir = tests_dir / "results"
        
        # Create the directory if it doesn't exist
        results_dir.mkdir(exist_ok=True)
        
        return str(results_dir)


class BaseTestSuite:
    """
    Base test suite class providing shared functionality for all test suites.
    
    This class centralizes common test operations
    like command execution, JSON parsing, and result management.
    """
    
    def __init__(self):
        """Initialize base test suite"""
        self.test_results = []
    
    def run_command(self, cmd: List[str], input_data: str = None, 
                   timeout: int = CommonTestConstants.DEFAULT_TIMEOUT) -> Dict[str, Any]:
        """
        Execute a command and return structured results.
        
        This is the single source of truth for running subprocess commands across all test suites.
        
        Args:
            cmd: Command to execute as list of strings
            input_data: Optional stdin input
            timeout: Command timeout in seconds
            
        Returns:
            Dictionary with command results including:
            - success: bool indicating if command succeeded
            - returncode: Process return code
            - stdout: Standard output
            - stderr: Standard error
            - command: Masked command string for logging
            - json_data: Parsed JSON if available
        """
        try:
            result = subprocess.run(
                cmd,
                input=input_data,
                text=True,
                capture_output=True,
                timeout=timeout
            )
            
            # Try to parse JSON from stdout using centralized helper
            json_data = self._parse_json_from_stdout(result.stdout)
            
            return {
                "success": result.returncode == 0,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "command": ' '.join(cmd),
                "json_data": json_data
            }
            
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "returncode": -1,
                "stdout": "",
                "stderr": f"Command timed out after {timeout} seconds",
                "command": ' '.join(cmd),
                "json_data": None
            }
        except Exception as e:
            return {
                "success": False,
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
                "command": ' '.join(cmd),
                "json_data": None
            }
    
    def _parse_json_from_stdout(self, stdout: str) -> Dict[str, Any]:
        """
        Parse JSON object from command stdout stream.
        
        This method consolidates the complex logic for extracting and parsing JSON
        from command output that was previously duplicated across test suites.
        
        Args:
            stdout: Standard output string from command
            
        Returns:
            Parsed JSON dictionary or None if parsing fails
        """
        if not stdout or not stdout.strip():
            return None
        
        stdout_lines = stdout.strip().split('\n')
        
        # Strategy 1: Look for complete JSON block (opening to closing brace)
        json_data = self._parse_json_block(stdout_lines)
        if json_data is not None:
            return json_data
        
        # Strategy 2: Look for single-line JSON
        json_data = self._parse_single_line_json(stdout_lines)
        if json_data is not None:
            return json_data
        
        # Strategy 3: Try parsing entire output as JSON array
        json_data = self._parse_full_output_json(stdout)
        if json_data is not None:
            return json_data
        
        # Strategy 4: Line-by-line JSON parsing (for NDJSON-like output)
        json_data = self._parse_line_by_line_json(stdout_lines)
        if json_data is not None:
            return json_data
        
        return None
    
    def _parse_json_block(self, stdout_lines: List[str]) -> Dict[str, Any]:
        """Parse JSON block by finding opening and closing braces"""
        # Find the end of JSON (closing brace)
        json_end = -1
        for i in range(len(stdout_lines) - 1, -1, -1):
            if stdout_lines[i].strip() == '}':
                json_end = i
                break
        
        if json_end < 0:
            return None
        
        # Find the start of JSON (opening brace)
        for i in range(json_end, -1, -1):
            line = stdout_lines[i]
            if '{' in line:
                # Extract JSON part from the line (after the '{')
                json_start_pos = line.find('{')
                if json_start_pos >= 0:
                    # Create a copy of lines and modify the first line
                    temp_lines = stdout_lines[:]
                    temp_lines[i] = line[json_start_pos:]
                    json_text = '\n'.join(temp_lines[i:json_end+1])
                    try:
                        return json.loads(json_text)
                    except json.JSONDecodeError:
                        continue
        
        return None
    
    def _parse_single_line_json(self, stdout_lines: List[str]) -> Dict[str, Any]:
        """Parse single-line JSON from output lines"""
        for i in range(len(stdout_lines) - 1, -1, -1):
            line = stdout_lines[i].strip()
            if line.startswith('{') and line.endswith('}'):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
            elif line.startswith('{'):
                # Multi-line JSON starting from this line
                json_text = '\n'.join(stdout_lines[i:])
                try:
                    return json.loads(json_text)
                except json.JSONDecodeError:
                    continue
        
        return None
    
    def _parse_full_output_json(self, stdout: str) -> Dict[str, Any]:
        """Try parsing entire output as JSON"""
        try:
            return json.loads(stdout.strip())
        except json.JSONDecodeError:
            return None
    
    def _parse_line_by_line_json(self, stdout_lines: List[str]) -> Dict[str, Any]:
        """Parse line-by-line JSON (NDJSON style)"""
        for line in stdout_lines:
            line = line.strip()
            if line and line.startswith('{') and line.endswith('}'):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        
        return None
    
    def create_test_result(self, test_name: str, success: bool, details: Dict[str, Any], 
                          duration: float = 0.0) -> Dict[str, Any]:
        """
        Create standardized test result structure.
        
        Args:
            test_name: Name of the test
            success: Whether the test passed
            details: Test details dictionary
            duration: Test duration in seconds
            
        Returns:
            Standardized test result dictionary
        """
        return TestUtilities.create_test_result(test_name, success, details, duration)
    
    def print_test_status(self, test_name: str, success: bool, message: str = "") -> None:
        """Print test status with consistent formatting"""
        status = "✅" if success else "❌"
        print(f"   {status} {test_name}: {message}")
    
    def _mask_token_in_command(self, command: str, openshift_url: str = None, openshift_token: str = None) -> str:
        """
        Mask the authentication token, OpenShift URL, and temp directories in command strings.
        
        This method provides a centralized way to mask sensitive data in command strings
        across all test suites.
        
        Args:
            command: Command string to mask
            openshift_url: OpenShift URL to mask (optional)
            openshift_token: OpenShift token to mask (optional)
            
        Returns:
            Command string with sensitive data masked
        """
        # Use shared utility for basic masking
        masked_command = TestUtilities.mask_sensitive_data(command, openshift_url, openshift_token)
        
        # Mask temporary directories with placeholders
        import re
        temp_patterns = [
            r'/var/folders/[a-zA-Z0-9_/]+/tmp[a-zA-Z0-9_]+',
            r'/tmp/tmp[a-zA-Z0-9_]+'
        ]
        for pattern in temp_patterns:
            masked_command = re.sub(pattern, CommonTestConstants.TEMP_DIR_PLACEHOLDER, masked_command)
        
        return masked_command
    
    def save_results(self, filename: str, test_suite_name: str, 
                    configuration: Dict[str, Any] = None) -> None:
        """
        Save test results to JSON file in results directory.
        
        Args:
            filename: Name of the results file
            test_suite_name: Name of the test suite
            configuration: Optional configuration dictionary
        """
        results_dir = TestUtilities.get_results_dir()
        results_file = Path(results_dir) / filename
        
        summary = {
            "test_suite": test_suite_name,
            "timestamp": time.time(),
            "configuration": configuration or {},
            "results": self.test_results
        }
        
        with open(results_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"📄 Test results saved to: {results_file}")
