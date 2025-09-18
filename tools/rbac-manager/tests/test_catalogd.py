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
import yaml
from pathlib import Path
from typing import Dict, List, Any, NamedTuple

# Import shared test constants and setup path
from test_constants import CatalogdTestConstants as TestConstants, TestUtilities
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

class CatalogdTestSuite:
    """Test suite for catalogd functionality"""
    
    def __init__(self, openshift_url: str, openshift_token: str, skip_tls: bool = False):
        """
        Initialize test suite
        
        Args:
            openshift_url: OpenShift cluster URL
            openshift_token: Authentication token
            skip_tls: Whether to skip TLS verification (default: False)
        """
        self.openshift_url = openshift_url
        self.openshift_token = openshift_token
        self.skip_tls = skip_tls
        
        # Build commands using CommandBuilder to eliminate duplication
        self.base_cmd = (CommandBuilder(["python3", "rbac-manager.py", "catalogd"])
                        .add_auth(openshift_url, openshift_token, skip_tls)
                        .build())
        
        self.list_catalogs_cmd = (CommandBuilder(["python3", "rbac-manager.py", "list-catalogs"])
                                 .add_auth(openshift_url, openshift_token, skip_tls)
                                 .build())
        
        self.test_results = []
        # Use constants instead of magic strings
        self.test_catalog = TestConstants.DEFAULT_CATALOG
        self.test_package = TestConstants.DEFAULT_PACKAGE
        self.test_channel = TestConstants.DEFAULT_CHANNEL
        self.test_version = TestConstants.DEFAULT_VERSION
    
    def _mask_token_in_command(self, command: str) -> str:
        """Mask the authentication token, OpenShift URL, and temp directories in command strings"""
        # Use shared utility for basic masking
        masked_command = TestUtilities.mask_sensitive_data(command, self.openshift_url, self.openshift_token)
        
        # Mask temporary directories with placeholders (specific to catalogd tests)
        temp_patterns = [
            r'/var/folders/[a-zA-Z0-9_/]+/tmp[a-zA-Z0-9_]+',
            r'/tmp/tmp[a-zA-Z0-9_]+'
        ]
        for pattern in temp_patterns:
            masked_command = re.sub(pattern, TestConstants.TEMP_DIR_PLACEHOLDER, masked_command)
        
        return masked_command
    
    def _create_test_result(self, test_name: str, success: bool, details: Dict[str, Any]) -> None:
        """Create and append a test result"""
        self.test_results.append({
            "test": test_name,
            "success": success,
            "details": details
        })
    
    def _print_test_status(self, test_name: str, success: bool, message: str = "") -> None:
        """Print test status with consistent formatting"""
        status = "✅" if success else "❌"
        print(f"   {status} {test_name}: {message}")
    
    def _run_catalogd_test(self, test_name: str, description: str, args: List[str], 
                          success_condition, input_data: str = None) -> bool:
        """Generic method for running catalogd tests to eliminate duplication"""
        print(f"🧪 Testing {description}...")
        
        result = self.run_command(args, input_data)
        success = success_condition(result)
        
        self._create_test_result(test_name, success, result)
        return success
    
    def run_command(self, additional_args: List[str], input_data: str = None, 
                   timeout: int = TestConstants.DEFAULT_TIMEOUT) -> Dict[str, Any]:
        """
        Run a catalogd command and capture results
        
        Args:
            additional_args: Additional command arguments
            input_data: Input to pipe to the command
            timeout: Command timeout in seconds
            
        Returns:
            Dict containing exit_code, stdout, stderr, and parsed JSON if available
        """
        cmd = self.base_cmd + additional_args
        
        try:
            result = subprocess.run(
                cmd,
                input=input_data,
                text=True,
                capture_output=True,
                timeout=timeout,
                cwd=Path(__file__).parent.parent
            )
            
            # Try to parse JSON from stdout
            json_data = None
            stdout_lines = result.stdout.strip().split('\n')
            
            # Look for JSON output (usually at the end)
            # First, try to find the end of JSON (closing brace)
            json_end = -1
            for i in range(len(stdout_lines) - 1, -1, -1):
                if stdout_lines[i].strip() == '}':
                    json_end = i
                    break
            
            # Now look for the start of JSON (opening brace)
            if json_end >= 0:
                for i in range(json_end, -1, -1):
                    line = stdout_lines[i]
                    if '{' in line:  # Look for line containing opening brace
                        # Extract JSON part from the line (after the '{')
                        json_start_pos = line.find('{')
                        if json_start_pos >= 0:
                            # Create a copy of lines and modify the first line
                            temp_lines = stdout_lines[:]
                            temp_lines[i] = line[json_start_pos:]
                            json_text = '\n'.join(temp_lines[i:json_end+1])
                            try:
                                json_data = json.loads(json_text)
                                break
                            except json.JSONDecodeError:
                                continue
            
            # Fallback: try the old method
            if json_data is None:
                for i in range(len(stdout_lines) - 1, -1, -1):
                    line = stdout_lines[i].strip()
                    if line.startswith('{'):
                        if line.endswith('}'):
                            # Single line JSON
                            try:
                                json_data = json.loads(line)
                                break
                            except json.JSONDecodeError:
                                continue
                        else:
                            # Multi-line JSON - try to parse from this line to end
                            json_text = '\n'.join(stdout_lines[i:])
                            try:
                                json_data = json.loads(json_text)
                                break
                            except json.JSONDecodeError:
                                continue
            
            return {
                "exit_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "json_data": json_data,
                "command": self._mask_token_in_command(' '.join(cmd))
            }
            
        except subprocess.TimeoutExpired:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Command timed out after {timeout} seconds",
                "json_data": None,
                "command": self._mask_token_in_command(' '.join(cmd))
            }
        except Exception as e:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e),
                "json_data": None,
                "command": self._mask_token_in_command(' '.join(cmd))
            }
    
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
    
    def test_list_packages(self) -> bool:
        """Test listing packages in a catalog"""
        def success_condition(result):
            return (result["exit_code"] == 0 and
                   result["json_data"] is not None and
                   result["json_data"].get("type") == "packages" and
                   isinstance(result["json_data"].get("data"), list) and
                   len(result["json_data"]["data"]) > 0)
        
        success = self._run_catalogd_test(
            "list_packages",
            "package listing",
            ["--catalog-name", self.test_catalog],
            success_condition
        )
        
        # Get package count for status message
        result = self.test_results[-1]["details"]
        package_count = len(result["json_data"]["data"]) if result["json_data"] else 0
        self._print_test_status("Package listing", success, f"{package_count} packages found")
        return success
    
    def test_list_channels(self) -> bool:
        """Test listing channels for a package"""
        print("🧪 Testing channel listing...")
        
        result = self.run_command([
            "--catalog-name", self.test_catalog,
            "--package", self.test_package
        ])
        
        success = (
            result["exit_code"] == 0 and
            result["json_data"] is not None and
            result["json_data"].get("type") == "channels" and
            isinstance(result["json_data"].get("data"), list) and
            len(result["json_data"]["data"]) > 0
        )
        
        self.test_results.append({
            "test": "list_channels",
            "success": success,
            "details": result
        })
        
        channel_count = len(result["json_data"]["data"]) if result["json_data"] else 0
        print(f"   {'✅' if success else '❌'} Channel listing: {channel_count} channels found")
        return success
    
    def test_list_versions(self) -> bool:
        """Test listing versions for a package and channel"""
        print("🧪 Testing version listing...")
        
        result = self.run_command([
            "--catalog-name", self.test_catalog,
            "--package", self.test_package,
            "--channel", self.test_channel
        ])
        
        success = (
            result["exit_code"] == 0 and
            result["json_data"] is not None and
            result["json_data"].get("type") == "versions" and
            isinstance(result["json_data"].get("data"), list) and
            len(result["json_data"]["data"]) > 0
        )
        
        self.test_results.append({
            "test": "list_versions",
            "success": success,
            "details": result
        })
        
        version_count = len(result["json_data"]["data"]) if result["json_data"] else 0
        print(f"   {'✅' if success else '❌'} Version listing: {version_count} versions found")
        return success
    
    def test_get_metadata(self) -> bool:
        """Test getting metadata for a specific version"""
        print("🧪 Testing metadata retrieval...")
        
        result = self.run_command([
            "--catalog-name", self.test_catalog,
            "--package", self.test_package,
            "--channel", self.test_channel,
            "--version", self.test_version
        ])
        
        success = (
            result["exit_code"] == 0 and
            result["json_data"] is not None and
            result["json_data"].get("type") == "metadata" and
            isinstance(result["json_data"].get("data"), dict) and
            "bundle_image" in result["json_data"]["data"] and
            "olmv1_compatible" in result["json_data"]["data"] and
            "install_modes" in result["json_data"]["data"] and
            "webhooks" in result["json_data"]["data"]
        )
        
        self.test_results.append({
            "test": "get_metadata",
            "success": success,
            "details": result
        })
        
        bundle_image = result["json_data"]["data"].get("bundle_image") if result["json_data"] else "N/A"
        print(f"   {'✅' if success else '❌'} Metadata retrieval: {bundle_image}")
        return success
    
    def test_interactive_catalog_selection(self) -> bool:
        """Test interactive catalog selection"""
        print("🧪 Testing interactive catalog selection...")
        
        # Simulate selecting catalog #4 (openshift-redhat-operators)
        result = self.run_command([
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
    
    def test_invalid_catalog(self) -> bool:
        """Test error handling with invalid catalog"""
        print("🧪 Testing invalid catalog error handling...")
        
        result = self.run_command([
            "--catalog-name", "invalid-catalog-name",
            "--package", self.test_package
        ])
        
        success = (
            result["exit_code"] == 0 and  # Tool handles errors gracefully
            ("not found" in result["stderr"].lower() or "404" in result["stderr"])
        )
        
        self.test_results.append({
            "test": "invalid_catalog",
            "success": success,
            "details": result
        })
        
        print(f"   {'✅' if success else '❌'} Invalid catalog: error handled correctly")
        return success
    
    def test_misspelled_catalog(self) -> bool:
        """Test error handling with misspelled catalog name"""
        print("🧪 Testing misspelled catalog error handling...")
        
        result = self.run_command([
            "--catalog-name", "openshiftredhatoperators",  # Missing hyphens
            "--package", self.test_package
        ])
        
        success = (
            result["exit_code"] == 0 and
            "misspelled" in result["stderr"].lower() and
            "did you mean" in result["stderr"].lower()
        )
        
        self.test_results.append({
            "test": "misspelled_catalog",
            "success": success,
            "details": result
        })
        
        print(f"   {'✅' if success else '❌'} Misspelled catalog: suggestions provided")
        return success
    
    def test_invalid_characters_catalog(self) -> bool:
        """Test error handling with invalid characters in catalog name"""
        print("🧪 Testing invalid characters in catalog name...")
        
        result = self.run_command([
            "--catalog-name", "openshift redhat operators",  # Spaces
            "--package", self.test_package
        ])
        
        success = (
            result["exit_code"] == 0 and
            "invalid characters" in result["stderr"].lower()
        )
        
        self.test_results.append({
            "test": "invalid_characters_catalog",
            "success": success,
            "details": result
        })
        
        print(f"   {'✅' if success else '❌'} Invalid characters: error handled correctly")
        return success
    
    def test_ssl_error_handling(self) -> bool:
        """Test SSL error handling without --skip-tls"""
        print("🧪 Testing SSL error handling...")
        
        # Run command without --skip-tls to trigger SSL error
        cmd = [
            "python3", "rbac-manager.py", "catalogd",
            "--catalog-name", self.test_catalog,
            "--openshift-url", self.openshift_url,
            "--openshift-token", self.openshift_token
        ]
        
        result = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            timeout=30,
            cwd=Path(__file__).parent.parent
        )
        
        success = (
            result.returncode == 0 and
            "SSL certificate verification failed" in result.stderr and
            "--skip-tls" in result.stderr
        )
        
        self.test_results.append({
            "test": "ssl_error_handling",
            "success": success,
            "details": {
                "exit_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "command": self._mask_token_in_command(' '.join(cmd))
            }
        })
        
        print(f"   {'✅' if success else '❌'} SSL error: user-friendly message shown")
        return success
    
    def test_output_truncation_handling(self) -> bool:
        """Test handling of large JSON output that might be truncated"""
        print("🧪 Testing output truncation handling...")
        
        # Get metadata which produces large output
        result = self.run_command([
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
        
        result = self.run_command(["--generate-config"])
        
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
                "command": self._mask_token_in_command(' '.join(self.base_cmd + ["--generate-config"]))
            }
        })
        
        print(f"   {'✅' if success else '❌'} Config template: generated to stdout")
        return success
    
    def test_generate_config_with_params(self) -> bool:
        """Test generating config with package parameters"""
        print("🧪 Testing config generation with parameters...")
        
        result = self.run_command([
            "--generate-config",
            "--catalog-name", self.test_catalog,
            "--package", self.test_package,
            "--channel", self.test_channel,
            "--version", self.test_version
        ])
        
        # Check if config with real bundle data is generated
        success = (
            result["exit_code"] == 0 and
            "operator:" in result["stdout"] and
            f'packageName: "{self.test_package}"' in result["stdout"] and
            f'channel: "{self.test_channel}"' in result["stdout"] and
            f'version: "{self.test_version}"' in result["stdout"]
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
                "command": self._mask_token_in_command(' '.join(self.base_cmd + ["--generate-config", "--catalog-name", self.test_catalog, "--package", self.test_package, "--channel", self.test_channel, "--version", self.test_version]))
            }
        })
        
        print(f"   {'✅' if success else '❌'} Config with params: package info included")
        print(f"   {'✅' if has_real_bundle else '❌'} Real bundle image: extracted from catalogd")
        return success
    
    def test_generate_config_file_output(self) -> bool:
        """Test generating config file to output directory"""
        print("🧪 Testing config file generation...")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.run_command([
                "--generate-config",
                "--package", self.test_package,
                "--channel", self.test_channel,
                "--output", temp_dir
            ])
            
            # Check if config file was created
            config_files = list(Path(temp_dir).glob("rbac-manager-config.yaml"))
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
                    "command": self._mask_token_in_command(' '.join(self.base_cmd + ["--generate-config", "--package", self.test_package, "--channel", self.test_channel, "--output", "/tmp/placeholder-output-dir"]))
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
                timeout=120,
                cwd=Path(__file__).parent.parent
            )
            
            # Check if catalogs are listed (expecting JSON format)
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
                    "command": self._mask_token_in_command(' '.join(self.list_catalogs_cmd))
                }
            })
            
        except Exception as e:
            self.test_results.append({
                "test": "list_catalogs_command", 
                "success": False,
                "details": {
                    "exit_code": -1,
                    "error": str(e),
                    "command": self._mask_token_in_command(' '.join(self.list_catalogs_cmd))
                }
            })
            success = False
        
        print(f"   {'✅' if success else '❌'} List catalogs: command executed successfully")
        return success
    
    def get_available_tests(self) -> Dict[str, str]:
        """Get dictionary of available test methods and their descriptions"""
        return {
            "basic_catalogd_help": "Test basic catalogd command without arguments",
            "list_catalogs_command": "Test list-catalogs subcommand",
            "list_packages": "Test listing packages in a catalog",
            "list_channels": "Test listing channels for a package",
            "list_versions": "Test listing versions for a package and channel",
            "get_metadata": "Test getting metadata for a specific version",
            "generate_config_template": "Test generating config template without parameters",
            "generate_config_with_params": "Test generating config with package parameters",
            "generate_config_file_output": "Test generating config file to output directory",
            "interactive_catalog_selection": "Test interactive catalog selection",
            "invalid_catalog": "Test error handling with invalid catalog",
            "misspelled_catalog": "Test error handling with misspelled catalog name",
            "invalid_characters_catalog": "Test error handling with invalid characters in catalog name",
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
            "list_packages": self.test_list_packages,
            "list_channels": self.test_list_channels,
            "list_versions": self.test_list_versions,
            "get_metadata": self.test_get_metadata,
            "generate_config_template": self.test_generate_config_template,
            "generate_config_with_params": self.test_generate_config_with_params,
            "generate_config_file_output": self.test_generate_config_file_output,
            "interactive_catalog_selection": self.test_interactive_catalog_selection,
            "invalid_catalog": self.test_invalid_catalog,
            "misspelled_catalog": self.test_misspelled_catalog,
            "invalid_characters_catalog": self.test_invalid_characters_catalog,
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
            success = test_methods[test_name]()
            end_time = time.time()
            
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
            self.test_list_packages,
            self.test_list_channels,
            self.test_list_versions,
            self.test_get_metadata,
            self.test_generate_config_template,
            self.test_generate_config_with_params,
            self.test_generate_config_file_output,
            self.test_interactive_catalog_selection,
            self.test_invalid_catalog,
            self.test_misspelled_catalog,
            self.test_invalid_characters_catalog,
            self.test_ssl_error_handling,
            self.test_output_truncation_handling
        ]
        
        passed = 0
        failed = 0
        
        for test in tests:
            try:
                if test():
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
