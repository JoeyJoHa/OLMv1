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

import json
import os
import sys
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add the rbac-manager directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "rbac-manager"))

class CatalogdTestSuite:
    """Test suite for catalogd functionality"""
    
    def __init__(self, openshift_url: str, openshift_token: str, skip_tls: bool = True):
        """
        Initialize test suite
        
        Args:
            openshift_url: OpenShift cluster URL
            openshift_token: Authentication token
            skip_tls: Whether to skip TLS verification
        """
        self.openshift_url = openshift_url
        self.openshift_token = openshift_token
        self.skip_tls = skip_tls
        self.base_cmd = [
            "python3", "rbac-manager.py", "--catalogd",
            "--openshift-url", self.openshift_url,
            "--openshift-token", self.openshift_token
        ]
        if self.skip_tls:
            self.base_cmd.append("--skip-tls")
        
        self.test_results = []
        self.test_catalog = "openshift-redhat-operators"
        self.test_package = "quay-operator"
        self.test_channel = "stable-3.10"
        self.test_version = "3.10.0"
    
    def run_command(self, additional_args: List[str], input_data: str = None, 
                   timeout: int = 120) -> Dict[str, Any]:
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
            for i in range(len(stdout_lines) - 1, -1, -1):
                line = stdout_lines[i].strip()
                if line.startswith('{') and line.endswith('}'):
                    try:
                        json_data = json.loads(line)
                        break
                    except json.JSONDecodeError:
                        continue
                elif line.startswith('{'):
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
                "command": ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Command timed out after {timeout} seconds",
                "json_data": None,
                "command": ' '.join(cmd)
            }
        except Exception as e:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e),
                "json_data": None,
                "command": ' '.join(cmd)
            }
    
    def test_basic_catalogd_help(self) -> bool:
        """Test basic catalogd command without arguments"""
        print("🧪 Testing basic catalogd help...")
        
        result = self.run_command([])
        
        success = (
            result["exit_code"] == 0 and
            "No catalogd operation specified" in result["stdout"]
        )
        
        self.test_results.append({
            "test": "basic_catalogd_help",
            "success": success,
            "details": result
        })
        
        print(f"   {'✅' if success else '❌'} Basic help: {result['exit_code']}")
        return success
    
    def test_list_packages(self) -> bool:
        """Test listing packages in a catalog"""
        print("🧪 Testing package listing...")
        
        result = self.run_command([
            "--catalog-name", self.test_catalog
        ])
        
        success = (
            result["exit_code"] == 0 and
            result["json_data"] is not None and
            result["json_data"].get("type") == "packages" and
            isinstance(result["json_data"].get("data"), list) and
            len(result["json_data"]["data"]) > 0
        )
        
        self.test_results.append({
            "test": "list_packages",
            "success": success,
            "details": result
        })
        
        package_count = len(result["json_data"]["data"]) if result["json_data"] else 0
        print(f"   {'✅' if success else '❌'} Package listing: {package_count} packages found")
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
            "name" in result["json_data"]["data"] and
            "image" in result["json_data"]["data"]
        )
        
        self.test_results.append({
            "test": "get_metadata",
            "success": success,
            "details": result
        })
        
        bundle_name = result["json_data"]["data"].get("name") if result["json_data"] else "N/A"
        print(f"   {'✅' if success else '❌'} Metadata retrieval: {bundle_name}")
        return success
    
    def test_interactive_catalog_selection(self) -> bool:
        """Test interactive catalog selection"""
        print("🧪 Testing interactive catalog selection...")
        
        # Simulate selecting catalog #4 (openshift-redhat-operators)
        result = self.run_command([
            "--package", self.test_package
        ], input_data="4\n")
        
        success = (
            result["exit_code"] == 0 and
            result["json_data"] is not None and
            result["json_data"].get("type") == "channels" and
            result["json_data"].get("catalog") == self.test_catalog
        )
        
        self.test_results.append({
            "test": "interactive_catalog_selection",
            "success": success,
            "details": result
        })
        
        print(f"   {'✅' if success else '❌'} Interactive selection: catalog selected")
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
            "404" in result["stderr"]  # Should get 404 error
        )
        
        self.test_results.append({
            "test": "invalid_catalog",
            "success": success,
            "details": result
        })
        
        print(f"   {'✅' if success else '❌'} Invalid catalog: error handled correctly")
        return success
    
    def test_ssl_error_handling(self) -> bool:
        """Test SSL error handling without --skip-tls"""
        print("🧪 Testing SSL error handling...")
        
        # Run command without --skip-tls to trigger SSL error
        cmd = [
            "python3", "rbac-manager.py", "--catalogd",
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
                "command": ' '.join(cmd)
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
        
        # Additional check: ensure we have the complete metadata structure
        if success and result["json_data"]:
            data = result["json_data"]["data"]
            success = (
                "name" in data and
                "image" in data and
                "properties" in data and
                isinstance(data["properties"], list)
            )
        
        self.test_results.append({
            "test": "output_truncation_handling",
            "success": success,
            "details": result
        })
        
        print(f"   {'✅' if success else '❌'} Output truncation: JSON parsed correctly")
        return success
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all catalogd tests"""
        print("🚀 Starting Catalogd Test Suite")
        print("=" * 50)
        
        start_time = time.time()
        
        # Run all tests
        tests = [
            self.test_basic_catalogd_help,
            self.test_list_packages,
            self.test_list_channels,
            self.test_list_versions,
            self.test_get_metadata,
            self.test_interactive_catalog_selection,
            self.test_invalid_catalog,
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
        results_file = Path(__file__).parent / filename
        
        summary = {
            "test_suite": "catalogd",
            "timestamp": time.time(),
            "configuration": {
                "openshift_url": self.openshift_url,
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


def main():
    """Main test runner"""
    # Get configuration from environment or command line
    openshift_url = os.getenv("OPENSHIFT_URL", "https://api.opslab-joe.rh-igc.com:6443")
    openshift_token = os.getenv("OPENSHIFT_TOKEN") or os.getenv("TOKEN")
    
    if not openshift_token:
        print("❌ Error: OPENSHIFT_TOKEN or TOKEN environment variable required")
        print("   Set with: export TOKEN='your-openshift-token'")
        sys.exit(1)
    
    # Initialize and run test suite
    test_suite = CatalogdTestSuite(
        openshift_url=openshift_url,
        openshift_token=openshift_token,
        skip_tls=True
    )
    
    # Run tests
    results = test_suite.run_all_tests()
    
    # Save results
    test_suite.save_results()
    
    # Exit with appropriate code
    sys.exit(0 if results["failed"] == 0 else 1)


if __name__ == "__main__":
    main()
