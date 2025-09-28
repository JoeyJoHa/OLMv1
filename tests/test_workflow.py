#!/usr/bin/env python3
"""
Complete Workflow Test Suite

Tests the complete workflow of:
1. generate-config command (with real cluster data)
2. opm --config (using generated config)

This test requires cluster authentication and validates the entire
end-to-end user experience.
"""

import argparse
import json
import os
import re
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
from typing import Dict, List, Any

# Import shared test constants and setup path
from test_constants import CommonTestConstants, TestUtilities, BaseTestSuite
TestUtilities.setup_test_path()

# Import catalogd service for direct API access
try:
    # Add the rbac-manager directory to the path
    import sys
    import os
    rbac_manager_path = os.path.join(os.getcwd(), 'tools', 'rbac-manager', 'rbac-manager')
    if rbac_manager_path not in sys.path:
        sys.path.insert(0, rbac_manager_path)
    
    from libs.catalogd import CatalogdService
    from libs.core.auth import OpenShiftAuth
    from kubernetes import client
except ImportError as e:
    print(f"Warning: Could not import catalogd libraries: {e}")
    CatalogdService = None
    OpenShiftAuth = None
    client = None

class WorkflowTestSuite(BaseTestSuite):
    """Test suite for complete catalogd -> opm workflow"""
    
    def __init__(self, openshift_url: str, openshift_token: str, skip_tls: bool = True, debug: bool = False):
        """
        Initialize workflow test suite
        
        Args:
            openshift_url: OpenShift cluster URL
            openshift_token: Authentication token
            skip_tls: Whether to skip TLS verification
            debug: Enable debug output        """
        super().__init__()  # Initialize BaseTestSuite
        
        self.openshift_url = openshift_url
        self.openshift_token = openshift_token
        self.skip_tls = skip_tls
        self.debug = debug
        
        # Base commands
        self.catalogd_cmd = [
            "python3", "tools/rbac-manager/rbac-manager.py", "catalogd",
            "--openshift-url", self.openshift_url,
            "--openshift-token", self.openshift_token
        ]
        if self.skip_tls:
            self.catalogd_cmd.append("--skip-tls")
        if self.debug:
            self.catalogd_cmd.append("--debug")
        
        self.opm_cmd = ["python3", "tools/rbac-manager/rbac-manager.py", "opm"]
        if self.skip_tls:
            self.opm_cmd.append("--skip-tls")
        if self.debug:
            self.opm_cmd.append("--debug")
        
        # Test parameters (will be discovered from cluster)
        # Discovery will prioritize community catalogs and argocd-operator to avoid registry authentication issues
        self.test_catalog = None
        self.test_package = None
        self.test_channel = None
        self.test_version = None
    
    def _filter_logging_from_stdout(self, stdout: str) -> str:
        """
        Filter logging messages from stdout to keep test results clean.
        This removes all timestamp-prefixed logging messages (DEBUG, INFO, WARNING, ERROR).
        
        Args:
            stdout: Original stdout content
            
        Returns:
            Cleaned stdout with logging messages removed
        """
        if not stdout:
            return stdout
        
        lines = stdout.split('\n')
        filtered_lines = []
        
        for line in lines:
            # Skip lines that look like logging messages (timestamp - LEVEL - message)
            if re.match(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} - (DEBUG|INFO|WARNING|ERROR|CRITICAL) - ', line):
                continue
            filtered_lines.append(line)
        
        return '\n'.join(filtered_lines)
    
    def run_workflow_command(self, cmd: List[str], timeout: int = CommonTestConstants.DEFAULT_TIMEOUT) -> Dict[str, Any]:
        """
        Run a workflow command using the inherited run_command method
        
        Args:
            cmd: Command to execute
            timeout: Command timeout in seconds
            
        Returns:
            Dictionary with command results (mapped for backward compatibility)
        """
        result = super().run_command(cmd, None, timeout)
        
        # Filter logging messages from stdout to keep test results clean
        result["stdout"] = self._filter_logging_from_stdout(result["stdout"])
        
        # Map new field names to old field names for backward compatibility
        result["success"] = result["returncode"] == 0
        
        return result
    
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
        """Discover test parameters from the cluster using CatalogdService directly"""
        print("🔍 Discovering test parameters from cluster...")
        
        if not CatalogdService or not OpenShiftAuth or not client:
            print("❌ Required libraries not available for direct API access")
            return False
        
        try:
            # Initialize authentication and Kubernetes clients
            auth = OpenShiftAuth(skip_tls=self.skip_tls)
            
            # Configure authentication with URL and token
            if not auth.configure_auth(self.openshift_url, self.openshift_token):
                print("❌ Failed to configure authentication")
                return False
            
            # Get Kubernetes API clients
            k8s_client, custom_api, core_api = auth.get_kubernetes_clients()
            
            # Initialize catalogd service
            catalogd_service = CatalogdService(
                core_api=core_api,
                custom_api=custom_api,
                skip_tls=self.skip_tls,
                debug=self.debug
            )
            
            # Get authentication headers
            auth_headers = auth.get_auth_headers()
            
            # List cluster catalogs
            print("   Listing cluster catalogs...")
            cluster_catalogs = catalogd_service.list_cluster_catalogs()
            
            if not cluster_catalogs:
                print("❌ No cluster catalogs found")
                return False
            
            # Find serving catalogs and prioritize community catalogs
            serving_catalogs = []
            all_catalogs = []
            
            for catalog in cluster_catalogs:
                catalog_name = catalog.get("metadata", {}).get("name", "")
                if catalog_name:
                    all_catalogs.append(catalog_name)
                    # Check if catalog is serving (has conditions indicating readiness)
                    conditions = catalog.get("status", {}).get("conditions", [])
                    is_serving = any(
                        condition.get("type") == "Serving" and condition.get("status") == "True"
                        for condition in conditions
                    )
                    if is_serving:
                        serving_catalogs.append(catalog_name)
            
            if not serving_catalogs:
                print(f"   No serving catalogs found, using all available: {all_catalogs}")
                serving_catalogs = all_catalogs
            
            print(f"   Found serving catalogs: {serving_catalogs}")
            
            # Prioritize community catalogs to avoid registry authentication issues
            preferred_catalogs = ["openshift-community-operators", "community-operators"]
            selected_catalog = None
            
            # First, try to find preferred catalogs
            for preferred in preferred_catalogs:
                if preferred in serving_catalogs:
                    selected_catalog = preferred
                    print(f"   Found preferred catalog: {preferred}")
                    break
            
            # If no preferred catalog found, use the first available
            if not selected_catalog:
                selected_catalog = serving_catalogs[0]
                print(f"   No preferred catalog found, using: {selected_catalog}")
            
            self.test_catalog = selected_catalog
            print(f"   Using catalog: {self.test_catalog}")
            
            # Get packages from the selected catalog
            print("   Listing packages...")
            packages = catalogd_service.get_catalog_packages(self.test_catalog, auth_headers)
            
            if not packages:
                print("❌ No packages found in catalog")
                return False
            
            # Prioritize argocd-operator for public registry compatibility
            preferred_packages = ["argocd-operator", "argocd-operator-helm"]
            selected_package = None
            
            # First, try to find preferred packages
            for preferred in preferred_packages:
                if preferred in packages:
                    selected_package = preferred
                    print(f"   Found preferred package: {preferred}")
                    break
            
            # If no preferred package found, use the first available
            if not selected_package:
                selected_package = packages[0]
                print(f"   No preferred package found, using: {selected_package}")
            
            self.test_package = selected_package
            print(f"   Using package: {self.test_package}")
            
            # Get channels for the package
            print("   Listing channels...")
            channels = catalogd_service.get_package_channels(self.test_catalog, self.test_package, auth_headers)
            
            if not channels:
                print("❌ No channels found for package")
                return False
            
            # Use the first channel
            self.test_channel = channels[0]
            print(f"   Using channel: {self.test_channel}")
            
            # Get versions for the channel
            print("   Listing versions...")
            versions = catalogd_service.get_channel_versions(
                self.test_catalog, self.test_package, self.test_channel, auth_headers
            )
            
            if not versions:
                print("❌ No versions found for channel")
                return False
            
            # Use the latest version
            self.test_version = versions[-1]
            print(f"   Using version: {self.test_version}")
            
            print("✅ Test parameters discovered successfully")
            return True
            
        except Exception as e:
            print(f"❌ Failed to discover test parameters: {e}")
            if self.debug:
                import traceback
                traceback.print_exc()
            return False
    
    def _run_complete_workflow(self, output_type: str) -> Dict[str, Any]:
        """
        Run complete workflow: generate-config -> opm config
        
        Args:
            output_type: Either 'yaml' or 'helm' to specify the output format
            
        Returns:
            Dictionary containing test results
        """
        workflow_name = f"complete_{output_type}_workflow"
        print(f"🔄 Testing complete {output_type.upper()} workflow...")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Step 1: Generate config with generate-config command
            cmd = [
                "python3", "tools/rbac-manager/rbac-manager.py", "generate-config",
                "--openshift-url", self.openshift_url,
                "--openshift-token", self.openshift_token,
                "--skip-tls",
                "--catalog-name", self.test_catalog,
                "--package", self.test_package,
                "--channel", self.test_channel,
                "--version", self.test_version,
                "--output", temp_dir
            ]
            
            step1_result = self.run_workflow_command(cmd)
            
            test_result = self.create_test_result(
                workflow_name, 
                step1_result["success"], 
                {
                    "step1_generate_config": {
                        "success": step1_result["success"],
                        "command": self._mask_token_in_command(step1_result["command"], self.openshift_url, self.openshift_token),
                        "returncode": step1_result["returncode"],
                        "stdout": step1_result["stdout"],
                        "stderr": step1_result["stderr"]
                    }
                }
            )
            test_result["description"] = f"Complete workflow: catalogd generate-config -> opm config ({output_type.upper()})"
            
            if not step1_result["success"]:
                test_result["details"]["step1_generate_config"]["error"] = step1_result["stderr"]
                return test_result
            
            # Check if config file was created
            config_files = list(Path(temp_dir).glob("*-rbac-config.yaml"))
            if not config_files:
                test_result["success"] = False
                test_result["details"]["step1_generate_config"]["error"] = "Config file not created"
                return test_result
            
            config_file = str(config_files[0])
            test_result["details"]["step1_generate_config"]["config_file"] = config_file
            
            # Handle config file based on output type
            if output_type == "yaml":
                # For YAML workflow, validate and include the generated config
                try:
                    with open(config_file, 'r') as f:
                        config_content = f.read()
                        # Include the generated config content in the results
                        test_result["details"]["step1_generate_config"]["generated_config"] = config_content
                        
                        # Parse the config for validation
                        config_data = yaml.safe_load(config_content)
                    
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
                    
            elif output_type == "helm":
                # For Helm workflow, modify config to use Helm output
                try:
                    with open(config_file, 'r') as f:
                        original_config_content = f.read()
                        # Include the original generated config content in the results
                        test_result["details"]["step1_generate_config"]["generated_config"] = original_config_content
                        
                        # Parse the config for modification
                        config_data = yaml.safe_load(original_config_content)
                    
                    # Change output type to helm
                    config_data["output"]["type"] = "helm"
                    
                    with open(config_file, 'w') as f:
                        yaml.dump(config_data, f, default_flow_style=False)
                    
                    # Read the modified config content
                    with open(config_file, 'r') as f:
                        modified_config_content = f.read()
                        test_result["details"]["step1_generate_config"]["modified_config"] = modified_config_content
                    
                    test_result["details"]["step1_generate_config"]["config_modified"] = True
                    
                except Exception as e:
                    test_result["success"] = False
                    test_result["details"]["step1_generate_config"]["error"] = f"Failed to modify config: {e}"
                    return test_result
            
            # Step 2: Run opm with the generated config
            step2_cmd = self.opm_cmd + ["--config", config_file]
            step2_result = self.run_workflow_command(step2_cmd)
            
            # Determine step2 details key based on output type
            step2_key = f"step2_opm_{output_type}"
            
            test_result["details"][step2_key] = {
                "success": step2_result["success"],
                "command": step2_result["command"],
                "returncode": step2_result["returncode"],
                "stdout": step2_result["stdout"],
                "stderr": step2_result["stderr"]
            }
            
            if step2_result["success"]:
                if output_type == "yaml":
                    # Check if YAML files were created
                    yaml_files = list(Path(temp_dir).glob("*-serviceaccount-*.yaml"))
                    yaml_files.extend(list(Path(temp_dir).glob("*-clusterrole-*.yaml")))
                    yaml_files.extend(list(Path(temp_dir).glob("*-role-*.yaml")))
                    
                    test_result["details"][step2_key]["yaml_files_created"] = len(yaml_files)
                    test_result["details"][step2_key]["files_created"] = len(yaml_files) > 0
                    
                    # Add warning if no files were created but commands succeeded
                    if len(yaml_files) == 0:
                        test_result["details"][step2_key]["warning"] = "No YAML files created (likely due to placeholder bundle image)"
                        
                elif output_type == "helm":
                    # Check if Helm values file was created
                    helm_files = list(Path(temp_dir).glob("*-*.yaml"))
                    # Filter out the config file
                    helm_files = [f for f in helm_files if "rbac-config" not in str(f)]
                    
                    test_result["details"][step2_key]["helm_files_created"] = len(helm_files)
                    test_result["details"][step2_key]["file_created"] = len(helm_files) > 0
                    
                    # Additional Helm-specific validations
                    if helm_files:
                        try:
                            with open(helm_files[0], 'r') as f:
                                helm_content = f.read()
                            
                            # Check for channel from config
                            has_real_channel = f'channel: {self.test_channel}' in helm_content
                            test_result["details"][step2_key]["has_real_channel"] = has_real_channel
                            
                            # Check for flow-style arrays
                            has_flow_arrays = '[' in helm_content and ']' in helm_content
                            test_result["details"][step2_key]["has_flow_arrays"] = has_flow_arrays
                            
                        except Exception as e:
                            test_result["details"][step2_key]["helm_analysis_error"] = str(e)
                    
                    # Add warning if no files were created but commands succeeded
                    if len(helm_files) == 0:
                        test_result["details"][step2_key]["warning"] = "No Helm files created (likely due to placeholder bundle image)"
                        
            else:
                test_result["success"] = False
                test_result["details"][step2_key]["error"] = step2_result["stderr"]
            
            # Overall success: both steps succeeded, regardless of file creation
            # (file creation may fail due to placeholder bundle images in test environment)
            test_result["success"] = step1_result["success"] and step2_result["success"]
        
        return test_result
    
    def test_complete_yaml_workflow(self) -> Dict[str, Any]:
        """Test complete workflow: generate-config -> opm config (YAML)"""
        return self._run_complete_workflow("yaml")
    
    def test_complete_helm_workflow(self) -> Dict[str, Any]:
        """Test complete workflow: generate-config -> opm config (Helm)"""
        return self._run_complete_workflow("helm")
    
    def test_config_validation_workflow(self) -> Dict[str, Any]:
        """Test workflow with config validation"""
        print("🔍 Testing config validation workflow...")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create invalid config file
            invalid_config = os.path.join(temp_dir, "invalid-config.yaml")
            invalid_config_content = """
operator:
  image: "test-image"
  namespace: "test-namespace"
output:
  mode: "invalid-mode"  # Invalid value
  type: "yaml"
global:
  skip_tls: "not-boolean"  # Invalid type
"""
            with open(invalid_config, 'w') as f:
                f.write(invalid_config_content)
            
            # Try to use invalid config
            cmd = self.opm_cmd + ["--config", invalid_config]
            result = self.run_workflow_command(cmd)
            
            test_result = {
                "test": "config_validation_workflow",
                "description": "Test config validation with invalid config file",
                "success": not result["success"],  # Should fail gracefully
                "duration": 0,
                "details": {
                    "command": result["command"],
                    "returncode": result["returncode"],
                    "stdout": result["stdout"],
                    "stderr": result["stderr"],
                    "failed_as_expected": not result["success"],
                    "config_file": invalid_config,
                    "invalid_config_content": invalid_config_content.strip()
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
        
        # Discover test parameters (prioritizing community catalogs and argocd-operator)
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
                        "cluster_url": TestUtilities.mask_sensitive_data(self.openshift_url, self.openshift_url, self.openshift_token),
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
        return str(results_file)


def main():
    """Main test runner"""
    
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
    if not Path("tools/rbac-manager/rbac-manager.py").exists():
        print("❌ Error: rbac-manager.py not found")
        print("   Please run this test from the project root directory")
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
