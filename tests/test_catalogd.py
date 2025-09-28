#!/usr/bin/env python3
"""
Catalogd Test Suite

Comprehensive tests for catalogd functionality including:
- Authentication and port-forwarding
- Catalog listing and selection
- Package, channel, and version queries
- Error handling and edge cases
- Output formatting and truncation handling
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

try:
    import yaml
except ImportError:
    print("Error: PyYAML is required but not installed.")
    print("Install it with: pip install PyYAML")
    sys.exit(1)
from typing import Dict, List, Any, NamedTuple

# Import shared test constants and setup path
from test_constants import CatalogdTestConstants as TestConstants, TestUtilities, BaseTestSuite
TestUtilities.setup_test_path()


class TestResult(NamedTuple):
    """Structured test result"""
    test_name: str
    success: bool
    details: Dict[str, Any]


class CommandBuilder:
    """Builder for test commands to eliminate duplication"""
    
    def __init__(self, base_args: List[str]):
        self.base_args = base_args.copy()
    
    def add_auth(self, url: str, token: str, skip_tls: bool = False) -> 'CommandBuilder':
        """Add authentication arguments"""
        self.base_args.extend(["--openshift-url", url, "--openshift-token", token])
        if skip_tls:
            self.base_args.append("--skip-tls")
        return self
    
    def add_catalog(self, catalog: str) -> 'CommandBuilder':
        """Add catalog name argument"""
        self.base_args.extend(["--catalog-name", catalog])
        return self
    
    def add_package(self, package: str) -> 'CommandBuilder':
        """Add package argument"""
        self.base_args.extend(["--package", package])
        return self
    
    def add_channel(self, channel: str) -> 'CommandBuilder':
        """Add channel argument"""
        self.base_args.extend(["--channel", channel])
        return self
    
    def add_version(self, version: str) -> 'CommandBuilder':
        """Add version argument"""
        self.base_args.extend(["--version", version])
        return self
    
    def add_output(self, output_path: str) -> 'CommandBuilder':
        """Add output directory argument"""
        self.base_args.extend(["--output", output_path])
        return self
    
    def add_flag(self, flag: str) -> 'CommandBuilder':
        """Add a flag argument"""
        self.base_args.append(flag)
        return self
    
    def build(self) -> List[str]:
        """Build the final command"""
        return self.base_args.copy()

class CatalogdTestSuite(BaseTestSuite):
    """Test suite for catalogd functionality"""
    
    def __init__(self, openshift_url: str, openshift_token: str, skip_tls: bool = False):
        """
        Initialize test suite
        
        Args:
            openshift_url: OpenShift cluster URL
            openshift_token: Authentication token
            skip_tls: Whether to skip TLS verification (default: False)
        """
        super().__init__()  # Initialize BaseTestSuite
        
        self.openshift_url = openshift_url
        self.openshift_token = openshift_token
        self.skip_tls = skip_tls
        
        # Build commands using CommandBuilder to eliminate duplication
        self.base_cmd = (CommandBuilder(["python3", "tools/rbac-manager/rbac-manager.py", "catalogd"])
                        .add_auth(openshift_url, openshift_token, skip_tls)
                        .build())
        
        self.list_catalogs_cmd = (CommandBuilder(["python3", "tools/rbac-manager/rbac-manager.py", "list-catalogs"])
                                 .add_auth(openshift_url, openshift_token, skip_tls)
                                 .build())
        
        # Use constants instead of magic strings
        self.test_catalog = TestConstants.DEFAULT_CATALOG
        self.test_package = TestConstants.DEFAULT_PACKAGE
        self.test_channel = TestConstants.DEFAULT_CHANNEL
        self.test_version = TestConstants.DEFAULT_VERSION
    
    
    def _create_test_result(self, test_name: str, success: bool, details: Dict[str, Any]) -> None:
        """Create and append a test result using inherited method"""
        result = self.create_test_result(test_name, success, details)
        self.test_results.append(result)
    
    def _print_test_status(self, test_name: str, success: bool, message: str = "") -> None:
        """Print test status with consistent formatting using inherited method"""
        self.print_test_status(test_name, success, message)
    
    def _filter_ssl_warnings_from_stdout(self, stdout: str) -> str:
        """
        Filter SSL verification warnings from stdout to keep test results clean.
        
        Args:
            stdout: Original stdout content
            
        Returns:
            Cleaned stdout with SSL warnings removed
        """
        if not stdout:
            return stdout
        
        lines = stdout.split('\n')
        filtered_lines = []
        
        for line in lines:
            # Skip SSL verification warning lines
            if 'SSL verification disabled' in line and 'WARNING' in line:
                continue
            filtered_lines.append(line)
        
        return '\n'.join(filtered_lines)
    
    def _run_catalogd_test(self, test_name: str, description: str, args: List[str], 
                          success_condition, input_data: str = None) -> bool:
        """Generic method for running catalogd tests to eliminate duplication"""
        print(f"🧪 Testing {description}...")
        
        result = self.run_catalogd_command(args, input_data)
        success = success_condition(result)
        
        self._create_test_result(test_name, success, result)
        return success
    
    def run_catalogd_command(self, additional_args: List[str], input_data: str = None, 
                            timeout: int = TestConstants.DEFAULT_TIMEOUT) -> Dict[str, Any]:
        """
        Run a catalogd command using the inherited run_command method
        
        Args:
            additional_args: Additional command arguments
            input_data: Input to pipe to the command
            timeout: Command timeout in seconds
            
        Returns:
            Dict containing command results with masked sensitive data
        """
        cmd = self.base_cmd + additional_args
        result = super().run_command(cmd, input_data, timeout)
        
        # Filter SSL warnings from stdout to keep test results clean
        result["stdout"] = self._filter_ssl_warnings_from_stdout(result["stdout"])
        
        # Mask sensitive data in command for logging
        result["command"] = self._mask_token_in_command(result["command"], self.openshift_url, self.openshift_token)
        
        # Map new field names to old field names for backward compatibility
        result["exit_code"] = result["returncode"]
        
        return result
    
    def run_generate_config_command(self, additional_args: List[str], input_data: str = None, 
                                   timeout: int = TestConstants.DEFAULT_TIMEOUT) -> Dict[str, Any]:
        """
        Run a generate-config command using the inherited run_command method
        
        Args:
            additional_args: Additional command arguments
            input_data: Input to pipe to the command
            timeout: Command timeout in seconds
            
        Returns:
            Dict containing command results with masked sensitive data
        """
        # Build generate-config command
        cmd = [
            "python3", "tools/rbac-manager/rbac-manager.py", "generate-config",
            "--openshift-url", self.openshift_url,
            "--openshift-token", self.openshift_token
        ]
        if self.skip_tls:
            cmd.append("--skip-tls")
        
        cmd.extend(additional_args)
        
        result = super().run_command(cmd, input_data, timeout)
        
        # Filter SSL warnings from stdout to keep test results clean
        result["stdout"] = self._filter_ssl_warnings_from_stdout(result["stdout"])
        
        # Mask sensitive data in command for logging
        result["command"] = self._mask_token_in_command(result["command"], self.openshift_url, self.openshift_token)
        
        # Map new field names to old field names for backward compatibility
        result["exit_code"] = result["returncode"]
        
        return result
    
    def run_data_driven_tests(self, test_cases: List[Dict[str, Any]]) -> List[bool]:
        """
        Run multiple test cases using a data-driven approach.
        
        This method eliminates duplication by running similar tests with different parameters.
        
        Args:
            test_cases: List of test case dictionaries with keys:
                - name: Test name
                - description: Test description  
                - args: Command arguments
                - success_condition: Function to check success
                - input_data: Optional stdin input
                
        Returns:
            List of boolean results for each test case
        """
        results = []
        
        for test_case in test_cases:
            success = self._run_catalogd_test(
                test_case["name"],
                test_case["description"],
                test_case["args"],
                test_case["success_condition"],
                test_case.get("input_data")
            )
            results.append(success)
            
            # Print status for each test
            result = self.test_results[-1]["details"]
            message = self._get_status_message(test_case["name"], result)
            self._print_test_status(test_case["name"], success, message)
        
        return results
    
    def _get_status_message(self, test_name: str, result: Dict[str, Any]) -> str:
        """Get appropriate status message for different test types"""
        if "list_packages" in test_name:
            package_count = len(result["json_data"]["data"]) if result["json_data"] else 0
            return f"{package_count} packages found"
        elif "list_channels" in test_name:
            channel_count = len(result["json_data"]["data"]) if result["json_data"] else 0
            return f"{channel_count} channels found"
        elif "list_versions" in test_name:
            version_count = len(result["json_data"]["data"]) if result["json_data"] else 0
            return f"{version_count} versions found"
        elif "get_metadata" in test_name:
            bundle_image = result["json_data"]["data"].get("bundle_image") if result["json_data"] else "N/A"
            return bundle_image
        else:
            return str(result["exit_code"])
    
    def test_basic_catalogd_help(self) -> bool:
        """Test basic catalogd command without arguments"""
        def success_condition(result):
            return (result["exit_code"] == 0 and 
                   "No catalogd operation specified" in result["stdout"])
        
        success = self._run_catalogd_test(
            "basic_catalogd_help",
            "basic catalogd help",
            [],
            success_condition
        )
        
        # Get the result for status message
        result = self.test_results[-1]["details"]
        self._print_test_status("Basic help", success, str(result["exit_code"]))
        return success
    
    def test_catalogd_operations_data_driven(self) -> List[bool]:
        """
        Test catalogd operations using data-driven approach to eliminate duplication.
        
        This method consolidates test_list_packages, test_list_channels, test_list_versions,
        and test_get_metadata into a single, parameterized test method.
        
        Returns:
            List of boolean results for each test case
        """
        test_cases = [
            {
                "name": "list_packages",
                "description": "package listing",
                "args": ["--catalog-name", self.test_catalog],
                "success_condition": lambda result: (
                    result["exit_code"] == 0 and
                    result["json_data"] is not None and
                    result["json_data"].get("type") == "packages" and
                    isinstance(result["json_data"].get("data"), list) and
                    len(result["json_data"]["data"]) > 0
                )
            },
            {
                "name": "list_channels",
                "description": "channel listing",
                "args": ["--catalog-name", self.test_catalog, "--package", self.test_package],
                "success_condition": lambda result: (
                    result["exit_code"] == 0 and
                    result["json_data"] is not None and
                    result["json_data"].get("type") == "channels" and
                    isinstance(result["json_data"].get("data"), list) and
                    len(result["json_data"]["data"]) > 0
                )
            },
            {
                "name": "list_versions",
                "description": "version listing",
                "args": ["--catalog-name", self.test_catalog, "--package", self.test_package, "--channel", self.test_channel],
                "success_condition": lambda result: (
                    result["exit_code"] == 0 and
                    result["json_data"] is not None and
                    result["json_data"].get("type") == "versions" and
                    isinstance(result["json_data"].get("data"), list) and
                    len(result["json_data"]["data"]) > 0
                )
            },
            {
                "name": "get_metadata",
                "description": "metadata retrieval",
                "args": ["--catalog-name", self.test_catalog, "--package", self.test_package, 
                        "--channel", self.test_channel, "--version", self.test_version],
                "success_condition": lambda result: (
                    result["exit_code"] == 0 and
                    result["json_data"] is not None and
                    result["json_data"].get("type") == "metadata" and
                    isinstance(result["json_data"].get("data"), dict) and
                    "bundle_image" in result["json_data"]["data"] and
                    "olmv1_compatible" in result["json_data"]["data"] and
                    "install_modes" in result["json_data"]["data"] and
                    "webhooks" in result["json_data"]["data"]
                )
            }
        ]
        
        return self.run_data_driven_tests(test_cases)
    
    def test_error_handling_data_driven(self) -> List[bool]:
        """
        Test error handling scenarios using data-driven approach.
        
        This method consolidates test_invalid_catalog, test_misspelled_catalog,
        and test_invalid_characters_catalog into a single, parameterized test method.
        
        Returns:
            List of boolean results for each test case
        """
        test_cases = [
            {
                "name": "invalid_catalog",
                "description": "invalid catalog error handling",
                "args": ["--catalog-name", "invalid-catalog-name", "--package", self.test_package],
                "success_condition": lambda result: (
                    ("not found" in result["stderr"].lower() or 
                     "invalid" in result["stderr"].lower() or
                     "error" in result["stderr"].lower())
                )
            },
            {
                "name": "misspelled_catalog",
                "description": "misspelled catalog error handling",
                "args": ["--catalog-name", "openshiftredhatoperators", "--package", self.test_package],  # Missing hyphens
                "success_condition": lambda result: (
                    ("not found" in result["stderr"].lower() or 
                     "invalid" in result["stderr"].lower() or
                     "error" in result["stderr"].lower())
                )
            },
            {
                "name": "invalid_characters_catalog",
                "description": "invalid characters in catalog name",
                "args": ["--catalog-name", "openshift redhat operators", "--package", self.test_package],  # Spaces
                "success_condition": lambda result: (
                    ("not found" in result["stderr"].lower() or 
                     "invalid" in result["stderr"].lower() or
                     "error" in result["stderr"].lower())
                )
            }
        ]
        
        return self.run_data_driven_tests(test_cases)
    
    def test_interactive_catalog_selection(self) -> bool:
        """Test interactive catalog selection"""
        print("🧪 Testing interactive catalog selection...")
        
        # Simulate selecting catalog #4 (openshift-redhat-operators)
        result = self.run_catalogd_command([
            "--package", self.test_package
        ], input_data="4\n")
        
        # Debug output removed - JSON parsing is now working correctly
        
        success = (
            result["exit_code"] == 0 and
            result["json_data"] is not None and
            result["json_data"].get("type") == "channels" and
            result["json_data"].get("catalog") == self.test_catalog and
            isinstance(result["json_data"].get("data"), list) and
            len(result["json_data"]["data"]) > 0
        )
        
        self.test_results.append({
            "test": "interactive_catalog_selection",
            "success": success,
            "details": result
        })
        
        catalog_name = result["json_data"].get("catalog") if result["json_data"] else "None"
        print(f"   {'✅' if success else '❌'} Interactive selection: {catalog_name}")
        return success
    
    def test_ssl_error_handling(self) -> bool:
        """Test SSL error handling without --skip-tls"""
        print("🧪 Testing SSL error handling...")
        
        # Run command without --skip-tls to trigger SSL error
        cmd = [
            "python3", "tools/rbac-manager/rbac-manager.py", "catalogd",
            "--catalog-name", self.test_catalog,
            "--openshift-url", self.openshift_url,
            "--openshift-token", self.openshift_token
        ]
        
        try:
            result = subprocess.run(
                cmd,
                text=True,
                capture_output=True,
                timeout=60  # Increased timeout for SSL errors
            )
            
            stderr_lower = result.stderr.lower()
            
            # Check for SSL certificate verification errors with enhanced patterns
            ssl_error_detected = any(ssl_indicator in stderr_lower for ssl_indicator in [
                'ssl certificate verify failed',
                'certificate verify failed', 
                'ssl: certificate_verify_failed',
                'ssl verification failed',
                'self-signed certificate',
                'certificate_verify_failed'
            ])
            
            # Check for helpful error message suggesting --skip-tls
            helpful_message = any(help_indicator in result.stderr for help_indicator in [
                "--skip-tls",
                "skip-tls",
                "TLS verification"
            ])
            
            # SSL error handling is successful if:
            # 1. SSL error was detected, AND
            # 2. Helpful message is provided (or command exits gracefully)
            success = ssl_error_detected and (helpful_message or result.returncode == 0)
            
            error_type = "SSL_CERTIFICATE_ERROR" if ssl_error_detected else "UNKNOWN_ERROR"
            error_message = "SSL certificate verification failed as expected" if ssl_error_detected else "No SSL error detected"
            
            self.test_results.append({
                "test": "ssl_error_handling",
                "success": success,
                "details": {
                    "exit_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "ssl_error_detected": ssl_error_detected,
                    "helpful_message_shown": helpful_message,
                    "error_type": error_type,
                    "error_message": error_message,
                    "command": self._mask_token_in_command(' '.join(cmd), self.openshift_url, self.openshift_token)
                }
            })
            
        except subprocess.TimeoutExpired:
            self.test_results.append({
                "test": "ssl_error_handling",
                "success": False,
                "details": {
                    "exit_code": -1,
                    "error": "SSL error test timed out after 60 seconds",
                    "error_type": "TIMEOUT_ERROR",
                    "command": self._mask_token_in_command(' '.join(cmd), self.openshift_url, self.openshift_token)
                }
            })
            success = False
            print("   ❌ SSL error: Test timed out")
            return success
            
        except Exception as e:
            self.test_results.append({
                "test": "ssl_error_handling",
                "success": False,
                "details": {
                    "exit_code": -1,
                    "error": str(e),
                    "error_type": "EXCEPTION_ERROR",
                    "command": self._mask_token_in_command(' '.join(cmd), self.openshift_url, self.openshift_token)
                }
            })
            success = False
            print(f"   ❌ SSL error: Exception occurred - {str(e)}")
            return success
        
        print(f"   {'✅' if success else '❌'} SSL error: user-friendly message shown")
        return success
    
    def test_output_truncation_handling(self) -> bool:
        """Test handling of large JSON output that might be truncated"""
        print("🧪 Testing output truncation handling...")
        
        # Get metadata which produces large output
        result = self.run_catalogd_command([
            "--catalog-name", self.test_catalog,
            "--package", self.test_package,
            "--channel", self.test_channel,
            "--version", self.test_version
        ])
        
        # Check if we can parse the JSON despite potential truncation
        success = (
            result["exit_code"] == 0 and
            result["json_data"] is not None and
            "data" in result["json_data"] and
            isinstance(result["json_data"]["data"], dict)
        )
        
        # Additional check: ensure we have the complete minimal metadata structure
        if success and result["json_data"]:
            data = result["json_data"]["data"]
            success = (
                "bundle_image" in data and
                "olmv1_compatible" in data and
                "install_modes" in data and
                "webhooks" in data and
                isinstance(data["install_modes"], dict) and
                isinstance(data["webhooks"], dict)
            )
        
        self.test_results.append({
            "test": "output_truncation_handling",
            "success": success,
            "details": result
        })
        
        print(f"   {'✅' if success else '❌'} Output truncation: JSON parsed correctly")
        return success
    
    def test_generate_config_template(self) -> bool:
        """Test generating config template without parameters"""
        print("🧪 Testing config template generation...")
        
        result = self.run_generate_config_command([])
        
        # Check if YAML config is generated to stdout
        success = (
            result["exit_code"] == 0 and
            "operator:" in result["stdout"] and
            "image:" in result["stdout"] and
            "channel:" in result["stdout"] and
            "output:" in result["stdout"] and
            "global:" in result["stdout"]
        )
        
        self.test_results.append({
            "test": "generate_config_template",
            "success": success,
            "details": {
                "exit_code": result["exit_code"],
                "stdout_contains_yaml": success,
                "command": result["command"],  # Use actual command from result
                "stdout": result["stdout"],
                "stderr": result["stderr"]
            }
        })
        
        print(f"   {'✅' if success else '❌'} Config template: generated to stdout")
        return success
    
    def test_generate_config_with_params(self) -> bool:
        """Test generating config with package parameters"""
        print("🧪 Testing config generation with parameters...")
        
        result = self.run_generate_config_command([
            "--catalog-name", self.test_catalog,
            "--package", self.test_package,
            "--channel", self.test_channel,
            "--version", self.test_version
        ])
        
        # Check if config with real bundle data is generated
        success = (
            result["exit_code"] == 0 and
            "operator:" in result["stdout"] and
            f'packageName: {self.test_package}' in result["stdout"] and
            f'channel: {self.test_channel}' in result["stdout"] and
            f'version: {self.test_version}' in result["stdout"]
        )
        
        # Check if real bundle image was extracted (not placeholder)
        has_real_bundle = "bundle-image-from-catalogd" not in result["stdout"]
        
        self.test_results.append({
            "test": "generate_config_with_params",
            "success": success,
            "details": {
                "exit_code": result["exit_code"],
                "has_package_info": success,
                "has_real_bundle_image": has_real_bundle,
                "command": result["command"],  # Use actual command from result
                "stdout": result["stdout"],
                "stderr": result["stderr"]
            }
        })
        
        print(f"   {'✅' if success else '❌'} Config with params: package info included")
        print(f"   {'✅' if has_real_bundle else '❌'} Real bundle image: extracted from catalogd")
        return success
    
    def test_generate_config_file_output(self) -> bool:
        """Test generating config file to output directory"""
        print("🧪 Testing config file generation...")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.run_generate_config_command([
                "--package", self.test_package,
                "--channel", self.test_channel,
                "--output", temp_dir
            ])
            
            # Check if config file was created
            config_files = list(Path(temp_dir).glob("*-rbac-config.yaml"))
            success = (
                result["exit_code"] == 0 and
                len(config_files) == 1 and
                "Configuration" in result["stdout"]
            )
            
            # Validate config file content
            config_content_valid = False
            if config_files:
                try:
                    with open(config_files[0], 'r') as f:
                        config_data = yaml.safe_load(f)
                    config_content_valid = (
                        "operator" in config_data and
                        "output" in config_data and
                        "global" in config_data and
                        config_data["operator"]["packageName"] == self.test_package
                    )
                except Exception:
                    pass
            
            self.test_results.append({
                "test": "generate_config_file_output",
                "success": success and config_content_valid,
                "details": {
                    "exit_code": result["exit_code"],
                    "file_created": len(config_files) == 1,
                    "config_valid": config_content_valid,
                    "command": result["command"],  # Use actual command from result
                    "stdout": result["stdout"],
                    "stderr": result["stderr"]
                }
            })
            
            print(f"   {'✅' if success else '❌'} Config file: created in output directory")
            print(f"   {'✅' if config_content_valid else '❌'} Config content: valid YAML structure")
            return success and config_content_valid
    
    def test_list_catalogs_command(self) -> bool:
        """Test list-catalogs subcommand"""
        print("🧪 Testing list-catalogs command...")
        
        # Use subprocess directly for list-catalogs since it's a different subcommand
        try:
            result = subprocess.run(
                self.list_catalogs_cmd,
                text=True,
                capture_output=True,
                timeout=120
            )
            
            # Enhanced error handling for SSL and other common issues
            if result.returncode != 0:
                stderr_lower = result.stderr.lower()
                
                # Check for SSL certificate verification errors
                if any(ssl_indicator in stderr_lower for ssl_indicator in [
                    'ssl certificate verify failed',
                    'certificate verify failed', 
                    'ssl: certificate_verify_failed',
                    'ssl verification failed',
                    'self-signed certificate'
                ]):
                    success = False
                    error_type = "SSL_CERTIFICATE_ERROR"
                    error_message = "SSL certificate verification failed. Use --skip-tls flag for self-signed certificates."
                
                # Check for network connectivity issues
                elif any(net_indicator in stderr_lower for net_indicator in [
                    'connection refused',
                    'connection timed out',
                    'network unreachable',
                    'no route to host'
                ]):
                    success = False
                    error_type = "NETWORK_ERROR"
                    error_message = "Network connectivity issue. Check OpenShift URL and network access."
                
                # Check for authentication errors
                elif any(auth_indicator in stderr_lower for auth_indicator in [
                    'unauthorized',
                    'authentication failed',
                    'invalid token',
                    'forbidden'
                ]):
                    success = False
                    error_type = "AUTHENTICATION_ERROR"
                    error_message = "Authentication failed. Check OpenShift token validity."
                
                # Generic error
                else:
                    success = False
                    error_type = "COMMAND_ERROR"
                    error_message = f"Command failed with exit code {result.returncode}"
                
                self.test_results.append({
                    "test": "list_catalogs_command",
                    "success": success,
                    "details": {
                        "exit_code": result.returncode,
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                        "error_type": error_type,
                        "error_message": error_message,
                        "command": self._mask_token_in_command(' '.join(self.list_catalogs_cmd), self.openshift_url, self.openshift_token)
                    }
                })
                
                print(f"   ❌ List catalogs: {error_message}")
                return success
            
            # Success case: Check if catalogs are listed (expecting JSON format)
            success = (
                result.returncode == 0 and
                ('"serving": true' in result.stdout or '"status": "Serving"' in result.stdout) and
                ("openshift-redhat-operators" in result.stdout or
                 "openshift-community-operators" in result.stdout)
            )
            
            self.test_results.append({
                "test": "list_catalogs_command",
                "success": success,
                "details": {
                    "exit_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "has_catalog_output": success,
                    "command": self._mask_token_in_command(' '.join(self.list_catalogs_cmd), self.openshift_url, self.openshift_token)
                }
            })
            
        except subprocess.TimeoutExpired:
            self.test_results.append({
                "test": "list_catalogs_command", 
                "success": False,
                "details": {
                    "exit_code": -1,
                    "error": "Command timed out after 120 seconds",
                    "error_type": "TIMEOUT_ERROR",
                    "command": self._mask_token_in_command(' '.join(self.list_catalogs_cmd), self.openshift_url, self.openshift_token)
                }
            })
            success = False
            print("   ❌ List catalogs: Command timed out after 120 seconds")
            
        except Exception as e:
            self.test_results.append({
                "test": "list_catalogs_command", 
                "success": False,
                "details": {
                    "exit_code": -1,
                    "error": str(e),
                    "error_type": "EXCEPTION_ERROR",
                    "command": self._mask_token_in_command(' '.join(self.list_catalogs_cmd), self.openshift_url, self.openshift_token)
                }
            })
            success = False
            print(f"   ❌ List catalogs: Exception occurred - {str(e)}")
        
        if success:
            print(f"   ✅ List catalogs: command executed successfully")
        
        return success
    
    def get_available_tests(self) -> Dict[str, str]:
        """Get dictionary of available test methods and their descriptions"""
        return {
            "basic_catalogd_help": "Test basic catalogd command without arguments",
            "list_catalogs_command": "Test list-catalogs subcommand",
            "catalogd_operations_data_driven": "Test catalogd operations (packages, channels, versions, metadata) using data-driven approach",
            "generate_config_template": "Test generating config template without parameters",
            "generate_config_with_params": "Test generating config with package parameters",
            "generate_config_file_output": "Test generating config file to output directory",
            "interactive_catalog_selection": "Test interactive catalog selection",
            "error_handling_data_driven": "Test error handling scenarios (invalid catalog, misspelled catalog, invalid characters) using data-driven approach",
            "ssl_error_handling": "Test SSL error handling without --skip-tls",
            "output_truncation_handling": "Test handling of large JSON output that might be truncated"
        }
    
    def run_specific_test(self, test_name: str) -> Dict[str, Any]:
        """Run a specific test by name"""
        start_time = time.time()
        
        # Map test names to methods
        test_methods = {
            "basic_catalogd_help": self.test_basic_catalogd_help,
            "list_catalogs_command": self.test_list_catalogs_command,
            "catalogd_operations_data_driven": self.test_catalogd_operations_data_driven,
            "generate_config_template": self.test_generate_config_template,
            "generate_config_with_params": self.test_generate_config_with_params,
            "generate_config_file_output": self.test_generate_config_file_output,
            "interactive_catalog_selection": self.test_interactive_catalog_selection,
            "error_handling_data_driven": self.test_error_handling_data_driven,
            "ssl_error_handling": self.test_ssl_error_handling,
            "output_truncation_handling": self.test_output_truncation_handling
        }
        
        if test_name not in test_methods:
            print(f"❌ Unknown test: {test_name}")
            return {"error": f"Unknown test: {test_name}"}
        
        print(f"🎯 Running specific test: {test_name}")
        print("=" * 50)
        
        try:
            # Execute the test method using the dictionary mapping
            result = test_methods[test_name]()
            end_time = time.time()
            
            # Handle data-driven methods that return List[bool]
            if isinstance(result, list):
                success = all(result)  # All sub-tests must pass
            else:
                success = result
            
            # Find the result in test_results
            test_result = None
            for result in reversed(self.test_results):
                if result["test"] == test_name:
                    test_result = result
                    break
            
            print(f"\n📊 Test '{test_name}' Results:")
            print(f"Status: {'✅ PASSED' if success else '❌ FAILED'}")
            print(f"Duration: {end_time - start_time:.2f}s")
            
            if not success and test_result:
                error_msg = test_result.get("details", {}).get("error", "Unknown error")
                print(f"Error: {error_msg}")
            
            return {
                "test_name": test_name,
                "success": success,
                "duration": end_time - start_time,
                "result": test_result
            }
            
        except Exception as e:
            end_time = time.time()
            print(f"❌ Test '{test_name}' failed with exception: {e}")
            return {
                "test_name": test_name,
                "success": False,
                "duration": end_time - start_time,
                "error": str(e)
            }
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all catalogd tests"""
        print("🚀 Starting Catalogd Test Suite")
        print("=" * 50)
        
        start_time = time.time()
        
        # Run all tests
        tests = [
            self.test_basic_catalogd_help,
            self.test_list_catalogs_command,
            self.test_catalogd_operations_data_driven,
            self.test_generate_config_template,
            self.test_generate_config_with_params,
            self.test_generate_config_file_output,
            self.test_interactive_catalog_selection,
            self.test_error_handling_data_driven,
            self.test_ssl_error_handling,
            self.test_output_truncation_handling
        ]
        
        passed = 0
        failed = 0
        
        for test in tests:
            try:
                result = test()
                # Handle data-driven methods that return List[bool]
                if isinstance(result, list):
                    success = all(result)  # All sub-tests must pass
                else:
                    success = result
                
                if success:
                    passed += 1
                else:
                    failed += 1
            except Exception as e:
                print(f"   ❌ {test.__name__}: Exception - {e}")
                failed += 1
            print()
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Summary
        print("=" * 50)
        print(f"📊 Test Summary:")
        print(f"   ✅ Passed: {passed}")
        print(f"   ❌ Failed: {failed}")
        print(f"   ⏱️  Duration: {duration:.2f}s")
        print(f"   📈 Success Rate: {(passed/(passed+failed)*100):.1f}%")
        
        return {
            "passed": passed,
            "failed": failed,
            "total": passed + failed,
            "duration": duration,
            "success_rate": (passed/(passed+failed)*100) if (passed+failed) > 0 else 0,
            "results": self.test_results
        }
    
    def save_results(self, filename: str = "catalogd_test_results.json") -> None:
        """Save test results to JSON file"""
        results_dir = TestUtilities.get_results_dir()
        results_file = Path(results_dir) / filename
        
        summary = {
            "test_suite": "catalogd",
            "timestamp": time.time(),
            "configuration": {
                "openshift_url": TestUtilities.mask_sensitive_data(self.openshift_url, self.openshift_url, self.openshift_token),
                "skip_tls": self.skip_tls,
                "test_catalog": self.test_catalog,
                "test_package": self.test_package,
                "test_channel": self.test_channel,
                "test_version": self.test_version
            },
            "results": self.test_results
        }
        
        with open(results_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"📄 Test results saved to: {results_file}")


def _parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Catalogd Test Suite")
    parser.add_argument("--unit", nargs="?", const="", help="Run specific test (use without argument to list available tests)")
    parser.add_argument("--skip-tls", action="store_true", help="Skip TLS verification")
    parser.add_argument("--openshift-url", help="OpenShift cluster URL")
    parser.add_argument("--openshift-token", help="OpenShift authentication token")
    return parser.parse_args()


def _validate_environment(args: argparse.Namespace) -> tuple[str, str]:
    """Validate and get environment configuration"""
    openshift_url = args.openshift_url or os.getenv("OPENSHIFT_URL")
    openshift_token = args.openshift_token or os.getenv("OPENSHIFT_TOKEN") or os.getenv("TOKEN")
    
    if not openshift_token or not openshift_url:
        error_messages = [
            "❌ Error: OPENSHIFT_TOKEN or TOKEN, and an OPENSHIFT_URL environment variable required",
            "   Set with: export TOKEN='your-openshift-token'",
            f"   Set with: export OPENSHIFT_URL='{TestConstants.EXAMPLE_URL}'",
            "   Or use: python3 test_catalogd.py --openshift-token 'your-token' --openshift-url 'https://api.example.com:6443'"
        ]
        print('\n'.join(error_messages))
        sys.exit(1)
    
    return openshift_url, openshift_token


def main():
    """Main test runner"""
    args = _parse_arguments()
    
    # Handle --unit flag for listing tests
    if hasattr(args, 'unit') and args.unit is not None:
        if args.unit == "":
            # List available tests
            dummy_suite = CatalogdTestSuite("https://example.com", "dummy-token")
            available_tests = dummy_suite.get_available_tests()
            print("📋 Available Catalogd Tests:")
            print("=" * 60)
            for test_name, description in available_tests.items():
                print(f"  {test_name:30} - {description}")
            print(f"\nUsage: python3 {Path(__file__).name} --unit <test_name> --openshift-url <url> --openshift-token <token>")
            sys.exit(0)
    
    openshift_url, openshift_token = _validate_environment(args)
    
    # Initialize test suite
    test_suite = CatalogdTestSuite(
        openshift_url=openshift_url,
        openshift_token=openshift_token,
        skip_tls=args.skip_tls
    )
    
    # Handle --unit flag for running specific test
    if hasattr(args, 'unit') and args.unit is not None and args.unit != "":
        available_tests = test_suite.get_available_tests()
        if args.unit not in available_tests:
            print(f"❌ Unknown test: {args.unit}")
            print(f"\nAvailable tests: {', '.join(available_tests.keys())}")
            sys.exit(1)
        
        # Run specific test
        result = test_suite.run_specific_test(args.unit)
        
        if "error" in result:
            sys.exit(1)
        
        # Save results
        test_suite.save_results(f"catalogd_test_{args.unit}_results.json")
        
        # Exit with appropriate code
        sys.exit(0 if result["success"] else 1)
    
    # Run all tests
    results = test_suite.run_all_tests()
    
    # Save results
    test_suite.save_results()
    
    # Exit with appropriate code
    sys.exit(0 if results["failed"] == 0 else 1)


if __name__ == "__main__":
    main()
