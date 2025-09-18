#!/usr/bin/env python3
"""
Complete Workflow Test Suite

Tests the complete workflow of:
1. catalogd --generate-config (with real cluster data)
2. opm --config (using generated config)

This test requires cluster authentication and validates the entire
end-to-end user experience.
"""

import json
import os
import sys
import subprocess
import tempfile
import time
import yaml
from pathlib import Path
from typing import Dict, List, Any

# Import shared test constants and setup path
from test_constants import CommonTestConstants, TestUtilities
TestUtilities.setup_test_path()

class WorkflowTestSuite:
    """Test suite for complete catalogd -> opm workflow"""
    
    def __init__(self, openshift_url: str, openshift_token: str, skip_tls: bool = True, debug: bool = False):
        """
        Initialize workflow test suite
        
        Args:
            openshift_url: OpenShift cluster URL
            openshift_token: Authentication token
            skip_tls: Whether to skip TLS verification
            debug: Enable debug output        """
        self.openshift_url = openshift_url
        self.openshift_token = openshift_token
        self.skip_tls = skip_tls
        self.debug = debug
        
        # Base commands
        self.catalogd_cmd = [
            "python3", "rbac-manager.py", "catalogd",
            "--openshift-url", self.openshift_url,
            "--openshift-token", self.openshift_token
        ]
        if self.skip_tls:
            self.catalogd_cmd.append("--skip-tls")
        if self.debug:
            self.catalogd_cmd.append("--debug")
        
        self.opm_cmd = ["python3", "rbac-manager.py", "opm"]
        if self.skip_tls:
            self.opm_cmd.append("--skip-tls")
        if self.debug:
            self.opm_cmd.append("--debug")
        
        self.test_results = []
        
        # Test parameters (will be discovered from cluster)
        self.test_catalog = None
        self.test_package = None
        self.test_channel = None
        self.test_version = None
    
    def run_command(self, cmd: List[str], timeout: int = CommonTestConstants.DEFAULT_TIMEOUT) -> Dict[str, Any]:
        """Run a command and return results"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return {
                "success": result.returncode == 0,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "command": ' '.join(cmd)
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "returncode": -1,
                "stdout": "",
                "stderr": f"Command timed out after {timeout} seconds",
                "command": ' '.join(cmd)
            }
        except Exception as e:
            return {
                "success": False,
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
                "command": ' '.join(cmd)
            }
    
    def _mask_token_in_command(self, command: str) -> str:
        """Mask token in command for logging"""
        return TestUtilities.mask_sensitive_data(command, self.openshift_url, self.openshift_token)
    
    def get_available_tests(self) -> Dict[str, str]:
        """Get dictionary of available test methods and their descriptions"""
        return {
            "complete_yaml_workflow": "Test complete workflow: catalogd generate-config -> opm config (YAML)",
            "complete_helm_workflow": "Test complete workflow: catalogd generate-config -> opm config (Helm)",
            "config_validation_workflow": "Test config validation with invalid config file"
        }
    
    def run_specific_test(self, test_name: str) -> Dict[str, Any]:
        """Run a specific test by name"""
        start_time = time.time()
        
        # Map test names to methods
        test_methods = {
            "complete_yaml_workflow": self.test_complete_yaml_workflow,
            "complete_helm_workflow": self.test_complete_helm_workflow,
            "config_validation_workflow": self.test_config_validation_workflow
        }
        
        if test_name not in test_methods:
            print(f"❌ Unknown test: {test_name}")
            return {"error": f"Unknown test: {test_name}"}
        
        # Discover test parameters first
        if not self.discover_test_parameters():
            return {
                "test_name": test_name,
                "success": False,
                "duration": 0,
                "error": "Failed to discover test parameters from cluster"
            }
        
        print(f"🎯 Running specific test: {test_name}")
        print("=" * 50)
        
        try:
            # Execute the test method
            result = test_methods[test_name]()
            end_time = time.time()
            
            result["duration"] = end_time - start_time
            
            print(f"\n📊 Test '{test_name}' Results:")
            print(f"Status: {'✅ PASSED' if result['success'] else '❌ FAILED'}")
            print(f"Duration: {result['duration']:.2f}s")
            
            if not result["success"] and "details" in result:
                print(f"Details: {result['details']}")
            
            return result
            
        except Exception as e:
            end_time = time.time()
            print(f"❌ Test '{test_name}' failed with exception: {e}")
            return {
                "test_name": test_name,
                "success": False,
                "duration": end_time - start_time,
                "error": str(e)
            }
    
    def discover_test_parameters(self) -> bool:
        """Discover test parameters from the cluster"""
        print("🔍 Discovering test parameters from cluster...")
        
        # List catalogs
        cmd = ["python3", "rbac-manager.py", "list-catalogs"] + self.catalogd_cmd[3:]  # Skip catalogd subcommand
        if self.debug:
            # Import the core utility for masking (use TestUtilities for consistency)
            masked_cmd = TestUtilities.mask_sensitive_data(' '.join(cmd), self.openshift_url, self.openshift_token)
            print(f"   Running command: {masked_cmd}")
        result = self.run_command(cmd)
        
        if not result["success"]:
            print(f"❌ Failed to list catalogs: {result['stderr']}")
            return False
        
        # Parse catalog output to find a serving catalog
        serving_catalogs = []
        
        if self.debug:
            print(f"   Raw catalog output: {result['stdout'][:500]}...")
        
        # Try to parse as JSON first (new format)
        try:
            if result["stdout"].strip():
                stdout_content = result["stdout"].strip()
                
                # Try parsing entire output as JSON array first
                try:
                    catalog_list = json.loads(stdout_content)
                    if isinstance(catalog_list, list):
                        for catalog_data in catalog_list:
                            if isinstance(catalog_data, dict):
                                catalog_name = catalog_data.get("name", "")
                                status = catalog_data.get("status", "")
                                if catalog_name and (status == "Serving" or catalog_data.get("serving") == True):
                                    serving_catalogs.append(catalog_name)
                except json.JSONDecodeError:
                    # Try line-by-line parsing
                    lines = stdout_content.split('\n')
                    for line in lines:
                        line = line.strip()
                        if line and line.startswith('{') and line.endswith('}'):
                            try:
                                catalog_data = json.loads(line)
                                if isinstance(catalog_data, dict):
                                    catalog_name = catalog_data.get("name", "")
                                    status = catalog_data.get("status", "")
                                    if catalog_name and (status == "Serving" or catalog_data.get("serving") == True):
                                        serving_catalogs.append(catalog_name)
                            except json.JSONDecodeError:
                                continue
        except Exception:
            pass
        
        # Fallback to text parsing (old format)
        if not serving_catalogs:
            for line in result["stdout"].split('\n'):
                line = line.strip()
                if "✓ Serving" in line or "Serving" in line:
                    # Extract catalog name (first column)
                    parts = line.split()
                    if parts:
                        catalog_name = parts[0]
                        serving_catalogs.append(catalog_name)
        
        # If still no catalogs, try to extract any catalog names for debugging
        if not serving_catalogs:
            print(f"❌ No serving catalogs found. Raw output:")
            print(f"   stdout: {result['stdout'][:200]}...")
            print(f"   stderr: {result['stderr'][:200]}...")
            
            # Try to find any catalog names for fallback
            all_catalogs = []
            
            # First try JSON parsing for any catalogs (regardless of status)
            try:
                stdout_content = result["stdout"].strip()
                try:
                    catalog_list = json.loads(stdout_content)
                    if isinstance(catalog_list, list):
                        for catalog_data in catalog_list:
                            if isinstance(catalog_data, dict):
                                catalog_name = catalog_data.get("name", "")
                                if catalog_name:
                                    all_catalogs.append(catalog_name)
                except json.JSONDecodeError:
                    # Try line-by-line JSON parsing
                    lines = stdout_content.split('\n')
                    for line in lines:
                        line = line.strip()
                        if line and line.startswith('{') and line.endswith('}'):
                            try:
                                catalog_data = json.loads(line)
                                if isinstance(catalog_data, dict):
                                    catalog_name = catalog_data.get("name", "")
                                    if catalog_name:
                                        all_catalogs.append(catalog_name)
                            except json.JSONDecodeError:
                                continue
            except Exception:
                pass
            
            # Fallback to text parsing for catalog names
            if not all_catalogs:
                for line in result["stdout"].split('\n'):
                    line = line.strip()
                    if line and not line.startswith('NAME') and not line.startswith('---') and not line.startswith('{'):
                        parts = line.split()
                        if parts and not parts[0].startswith('#') and len(parts[0]) > 2:
                            all_catalogs.append(parts[0])
            
            if all_catalogs:
                print(f"   Found catalogs (any status): {all_catalogs}")
                print(f"   Using first available catalog as fallback: {all_catalogs[0]}")
                serving_catalogs = [all_catalogs[0]]
            else:
                return False
        
        # Use the first serving catalog
        self.test_catalog = serving_catalogs[0]
        print(f"   Using catalog: {self.test_catalog}")
        
        # Find a package with multiple versions
        cmd = self.catalogd_cmd + ["--catalog-name", self.test_catalog]
        result = self.run_command(cmd)
        
        if not result["success"]:
            print(f"❌ Failed to list packages: {result['stderr']}")
            return False
        
        try:
            packages_data = json.loads(result["stdout"])
            packages = packages_data.get("data", [])
            
            if not packages:
                print("❌ No packages found in catalog")
                return False
            
            # Use the first package
            self.test_package = packages[0]
            print(f"   Using package: {self.test_package}")
            
        except json.JSONDecodeError:
            print("❌ Failed to parse packages JSON")
            return False
        
        # Get channels for the package
        cmd = self.catalogd_cmd + [
            "--catalog-name", self.test_catalog,
            "--package", self.test_package
        ]
        result = self.run_command(cmd)
        
        if not result["success"]:
            print(f"❌ Failed to list channels: {result['stderr']}")
            return False
        
        try:
            channels_data = json.loads(result["stdout"])
            channels = channels_data.get("data", [])
            
            if not channels:
                print("❌ No channels found for package")
                return False
            
            # Use the first channel
            self.test_channel = channels[0]
            print(f"   Using channel: {self.test_channel}")
            
        except json.JSONDecodeError:
            print("❌ Failed to parse channels JSON")
            return False
        
        # Get versions for the channel
        cmd = self.catalogd_cmd + [
            "--catalog-name", self.test_catalog,
            "--package", self.test_package,
            "--channel", self.test_channel
        ]
        result = self.run_command(cmd)
        
        if not result["success"]:
            print(f"❌ Failed to list versions: {result['stderr']}")
            return False
        
        try:
            versions_data = json.loads(result["stdout"])
            versions = versions_data.get("data", [])
            
            if not versions:
                print("❌ No versions found for channel")
                return False
            
            # Use the latest version
            self.test_version = versions[-1]
            print(f"   Using version: {self.test_version}")
            
        except json.JSONDecodeError:
            print("❌ Failed to parse versions JSON")
            return False
        
        print("✅ Test parameters discovered successfully")
        return True
    
    def test_complete_yaml_workflow(self) -> Dict[str, Any]:
        """Test complete workflow: catalogd generate-config -> opm config (YAML)"""
        print("🔄 Testing complete YAML workflow...")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Step 1: Generate config with catalogd
            config_file = os.path.join(temp_dir, "workflow-config.yaml")
            
            cmd = self.catalogd_cmd + [
                "--generate-config",
                "--catalog-name", self.test_catalog,
                "--package", self.test_package,
                "--channel", self.test_channel,
                "--version", self.test_version,
                "--output", temp_dir
            ]
            
            step1_result = self.run_command(cmd)
            
            test_result = TestUtilities.create_test_result(
                "complete_yaml_workflow", 
                step1_result["success"], 
                {
                    "step1_generate_config": {
                        "success": step1_result["success"],
                        "command": self._mask_token_in_command(step1_result["command"]),
                        "returncode": step1_result["returncode"]
                    }
                }
            )
            test_result["description"] = "Complete workflow: catalogd generate-config -> opm config (YAML)"
            
            if not step1_result["success"]:
                test_result["details"]["step1_generate_config"]["error"] = step1_result["stderr"]
                return test_result
            
            # Check if config file was created
            config_files = list(Path(temp_dir).glob("rbac-manager-config.yaml"))
            if not config_files:
                test_result["success"] = False
                test_result["details"]["step1_generate_config"]["error"] = "Config file not created"
                return test_result
            
            config_file = str(config_files[0])
            test_result["details"]["step1_generate_config"]["config_file"] = config_file
            
            # Validate config file content
            try:
                with open(config_file, 'r') as f:
                    config_data = yaml.safe_load(f)
                
                # Check for real bundle image (not placeholder)
                bundle_image = config_data.get("operator", {}).get("image", "")
                has_real_bundle = bundle_image and "bundle-image-from-catalogd" not in bundle_image
                test_result["details"]["step1_generate_config"]["has_real_bundle_image"] = has_real_bundle
                
                if not has_real_bundle:
                    test_result["details"]["step1_generate_config"]["warning"] = "Using placeholder bundle image"
                
            except Exception as e:
                test_result["success"] = False
                test_result["details"]["step1_generate_config"]["error"] = f"Failed to parse config: {e}"
                return test_result
            
            # Step 2: Use config with opm
            cmd = self.opm_cmd + ["--config", config_file]
            step2_result = self.run_command(cmd)
            
            test_result["details"]["step2_opm_config"] = {
                "success": step2_result["success"],
                "command": step2_result["command"],
                "returncode": step2_result["returncode"]
            }
            
            if step2_result["success"]:
                # Check if YAML files were created
                yaml_files = list(Path(temp_dir).glob("*-serviceaccount-*.yaml"))
                yaml_files.extend(list(Path(temp_dir).glob("*-clusterrole-*.yaml")))
                yaml_files.extend(list(Path(temp_dir).glob("*-role-*.yaml")))
                
                test_result["details"]["step2_opm_config"]["yaml_files_created"] = len(yaml_files)
                test_result["details"]["step2_opm_config"]["files_created"] = len(yaml_files) > 0
                
                # Overall success
                test_result["success"] = len(yaml_files) > 0
                
            else:
                test_result["success"] = False
                test_result["details"]["step2_opm_config"]["error"] = step2_result["stderr"]
        
        return test_result
    
    def test_complete_helm_workflow(self) -> Dict[str, Any]:
        """Test complete workflow: catalogd generate-config -> opm config (Helm)"""
        print("🔄 Testing complete Helm workflow...")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Step 1: Generate config with catalogd
            cmd = self.catalogd_cmd + [
                "--generate-config",
                "--catalog-name", self.test_catalog,
                "--package", self.test_package,
                "--channel", self.test_channel,
                "--version", self.test_version,
                "--output", temp_dir
            ]
            
            step1_result = self.run_command(cmd)
            
            test_result = {
                "test": "complete_helm_workflow",
                "description": "Complete workflow: catalogd generate-config -> opm config (Helm)",
                "success": step1_result["success"],
                "duration": 0,
                "details": {
                    "step1_generate_config": {
                        "success": step1_result["success"],
                        "command": self._mask_token_in_command(step1_result["command"]),
                        "returncode": step1_result["returncode"]
                    }
                }
            }
            
            if not step1_result["success"]:
                test_result["details"]["step1_generate_config"]["error"] = step1_result["stderr"]
                return test_result
            
            # Modify config file to use Helm output
            config_files = list(Path(temp_dir).glob("rbac-manager-config.yaml"))
            if not config_files:
                test_result["success"] = False
                test_result["details"]["step1_generate_config"]["error"] = "Config file not created"
                return test_result
            
            config_file = str(config_files[0])
            
            try:
                with open(config_file, 'r') as f:
                    config_data = yaml.safe_load(f)
                
                # Change output type to helm
                config_data["output"]["type"] = "helm"
                
                with open(config_file, 'w') as f:
                    yaml.dump(config_data, f, default_flow_style=False)
                
                test_result["details"]["step1_generate_config"]["config_modified"] = True
                
            except Exception as e:
                test_result["success"] = False
                test_result["details"]["step1_generate_config"]["error"] = f"Failed to modify config: {e}"
                return test_result
            
            # Step 2: Use config with opm for Helm output
            cmd = self.opm_cmd + ["--config", config_file]
            step2_result = self.run_command(cmd)
            
            test_result["details"]["step2_opm_helm"] = {
                "success": step2_result["success"],
                "command": step2_result["command"],
                "returncode": step2_result["returncode"]
            }
            
            if step2_result["success"]:
                # Check if Helm values file was created
                helm_files = list(Path(temp_dir).glob("*-*.yaml"))
                # Filter out the config file
                helm_files = [f for f in helm_files if "rbac-manager-config" not in str(f)]
                
                test_result["details"]["step2_opm_helm"]["helm_files_created"] = len(helm_files)
                test_result["details"]["step2_opm_helm"]["file_created"] = len(helm_files) > 0
                
                # Check if real channel appears in Helm output
                if helm_files:
                    try:
                        with open(helm_files[0], 'r') as f:
                            helm_content = f.read()
                        
                        has_real_channel = f'channel: {self.test_channel}' in helm_content
                        test_result["details"]["step2_opm_helm"]["has_real_channel"] = has_real_channel
                        
                        # Check for flow-style arrays
                        has_flow_arrays = "apiGroups: [" in helm_content
                        test_result["details"]["step2_opm_helm"]["has_flow_arrays"] = has_flow_arrays
                        
                    except Exception:
                        pass
                
                # Overall success
                test_result["success"] = len(helm_files) > 0
                
            else:
                test_result["success"] = False
                test_result["details"]["step2_opm_helm"]["error"] = step2_result["stderr"]
        
        return test_result
    
    def test_config_validation_workflow(self) -> Dict[str, Any]:
        """Test workflow with config validation"""
        print("🔍 Testing config validation workflow...")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create invalid config file
            invalid_config = os.path.join(temp_dir, "invalid-config.yaml")
            with open(invalid_config, 'w') as f:
                f.write("""
operator:
  image: "test-image"
  namespace: "test-namespace"
output:
  mode: "invalid-mode"  # Invalid value
  type: "yaml"
global:
  skip_tls: "not-boolean"  # Invalid type
""")
            
            # Try to use invalid config
            cmd = self.opm_cmd + ["--config", invalid_config]
            result = self.run_command(cmd)
            
            test_result = {
                "test": "config_validation_workflow",
                "description": "Test config validation with invalid config file",
                "success": not result["success"],  # Should fail gracefully
                "duration": 0,
                "details": {
                    "command": result["command"],
                    "returncode": result["returncode"],
                    "failed_as_expected": not result["success"],
                    "config_file": invalid_config
                }
            }
            
            if not result["success"]:
                test_result["details"]["error_message"] = result["stderr"]
                # Check if error message is helpful
                error_helpful = any(word in result["stderr"].lower() for word in ["config", "invalid", "validation"])
                test_result["details"]["error_helpful"] = error_helpful
            
            return test_result
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all workflow tests"""
        print("🚀 Starting Complete Workflow Test Suite")
        print("=" * 60)
        
        # Discover test parameters
        if not self.discover_test_parameters():
            print("⚠️  Parameter discovery failed - this may be due to:")
            print("   - No catalogs are currently serving")
            print("   - Cluster connectivity issues")
            print("   - Authentication problems")
            print("   - Different output format than expected")
            return {
                "passed": 0,
                "failed": 1,
                "total": 1,
                "success_rate": 0.0,
                "duration": 0,
                "results": [{
                    "test": "parameter_discovery",
                    "success": False,
                    "details": {
                        "error": "Failed to discover test parameters from cluster",
                        "cluster_url": self.openshift_url,
                        "suggestions": [
                            "Check if cluster has serving catalogs",
                            "Verify authentication credentials",
                            "Ensure cluster is accessible"
                        ]
                    }
                }]
            }
        
        start_time = time.time()
        
        # Run workflow tests
        tests = [
            self.test_complete_yaml_workflow,
            self.test_complete_helm_workflow,
            self.test_config_validation_workflow
        ]
        
        passed = 0
        failed = 0
        
        for test in tests:
            try:
                result = test()
                self.test_results.append(result)
                
                if result["success"]:
                    passed += 1
                    print(f"   ✅ {result['test']}: PASSED")
                else:
                    failed += 1
                    print(f"   ❌ {result['test']}: FAILED")
                    
            except Exception as e:
                failed += 1
                error_result = {
                    "test": test.__name__,
                    "success": False,
                    "details": {"exception": str(e)}
                }
                self.test_results.append(error_result)
                print(f"   ❌ {test.__name__}: ERROR - {e}")
        
        duration = time.time() - start_time
        total = passed + failed
        success_rate = (passed / total * 100) if total > 0 else 0
        
        print("\n" + "=" * 60)
        print(f"📊 Workflow Test Results:")
        print(f"   Total Tests: {total}")
        print(f"   Passed: {passed}")
        print(f"   Failed: {failed}")
        print(f"   Success Rate: {success_rate:.1f}%")
        print(f"   Duration: {duration:.2f}s")
        
        return {
            "passed": passed,
            "failed": failed,
            "total": total,
            "success_rate": success_rate,
            "duration": duration,
            "results": self.test_results
        }
    
    def save_results(self) -> str:
        """Save test results to JSON file"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        results_dir = TestUtilities.get_results_dir()
        results_file = Path(results_dir) / f"workflow_test_results_{timestamp}.json"
        
        summary = {
            "test_suite": "complete_workflow",
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
        return str(results_file)


def main():
    """Main test runner"""
    import argparse
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Complete Workflow Test Suite")
    parser.add_argument("--unit", nargs="?", const="", help="Run specific test (use without argument to list available tests)")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--skip-tls", action="store_true", help="Skip TLS verification")
    args = parser.parse_args()
    
    print("🧪 Complete Workflow Test Suite")
    print("Testing RBAC Manager complete workflow functionality")
    print("=" * 60)
    
    # Check if we're in the right directory
    if not Path("rbac-manager.py").exists():
        print("❌ Error: rbac-manager.py not found")
        print("   Please run this test from the tools/rbac-manager directory")
        sys.exit(1)
    
    # Get authentication from environment
    openshift_url = os.getenv("OPENSHIFT_URL")
    openshift_token = os.getenv("TOKEN")
    
    # Handle --unit flag for listing tests (doesn't require authentication)
    if args.unit is not None and args.unit == "":
        dummy_suite = WorkflowTestSuite("https://example.com", "dummy-token")
        available_tests = dummy_suite.get_available_tests()
        print("\n📋 Available Workflow Tests:")
        print("=" * 60)
        for test_name, description in available_tests.items():
            print(f"  {test_name:30} - {description}")
        print(f"\nUsage: python3 {Path(__file__).name} --unit <test_name>")
        print("Note: Workflow tests require OPENSHIFT_URL and TOKEN environment variables")
        sys.exit(0)
    
    if not openshift_url or not openshift_token:
        print("❌ Error: Missing authentication")
        print("   Please set OPENSHIFT_URL and TOKEN environment variables")
        print("   Example:")
        print("     export OPENSHIFT_URL='https://api.cluster.example.com:6443'")
        print("     export TOKEN='your-openshift-token'")
        sys.exit(1)
    
    # Initialize test suite
    test_suite = WorkflowTestSuite(
        openshift_url=openshift_url,
        openshift_token=openshift_token,
        skip_tls=args.skip_tls if hasattr(args, 'skip_tls') else True,
        debug=args.debug
    )
    
    # Handle --unit flag for running specific test
    if args.unit is not None and args.unit != "":
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
        test_suite.test_results = [result]
        test_suite.save_results()
        
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
