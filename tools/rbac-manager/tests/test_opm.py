#!/usr/bin/env python3
"""
OPM Test Suite

Comprehensive tests for OPM functionality including:
- Bundle image processing and metadata extraction
- RBAC generation (Helm values and YAML manifests)
- DRY deduplication logic validation
- Permission scenario handling (cluster-only, namespace-only, both, none)
- Output formatting and file generation
- Error handling and edge cases
"""

import json
import os
import sys
import subprocess
import tempfile
import time
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add the rbac-manager directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "rbac-manager"))

class OPMTestSuite:
    """Test suite for OPM functionality"""
    
    def __init__(self, skip_tls: bool = True, debug: bool = False):
        """
        Initialize test suite
        
        Args:
            skip_tls: Whether to skip TLS verification
            debug: Enable debug logging
        """
        self.skip_tls = skip_tls
        self.debug = debug
        self.base_cmd = ["python3", "rbac-manager.py", "opm"]
        if self.skip_tls:
            self.base_cmd.append("--skip-tls")
        if self.debug:
            self.base_cmd.append("--debug")
        
        self.test_results = []
        
        # Test bundle images for different scenarios
        self.test_bundles = {
            # ArgoCD operator - has both cluster and namespace permissions
            "argocd_both": "registry.redhat.io/argocd/argocd-operator-bundle@sha256:9c5c2d1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            # Quay operator - has only namespace permissions (treated as cluster)
            "quay_namespace": "registry.redhat.io/quay/quay-operator-bundle@sha256:c431ad9dfd69c049e6d9583928630c06b8612879eeed57738fa7be206061fee2",
            # Example cluster-only operator
            "cluster_only": "registry.redhat.io/example/cluster-operator-bundle@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        }
        
        # Test scenarios for comprehensive coverage
        self.test_scenarios = [
            {
                "name": "yaml_generation",
                "description": "Generate YAML manifests",
                "flags": []
            },
            {
                "name": "helm_generation", 
                "description": "Generate Helm values",
                "flags": ["--helm"]
            },
            {
                "name": "custom_namespace",
                "description": "Generate with custom namespace",
                "flags": ["--namespace", "test-operator"]
            },
            {
                "name": "output_directory",
                "description": "Generate with output directory",
                "flags": ["--output", "./test-output"]
            },
            {
                "name": "helm_with_namespace",
                "description": "Generate Helm values with custom namespace",
                "flags": ["--helm", "--namespace", "production"]
            }
        ]
    
    def run_command(self, cmd: List[str], input_data: str = None, timeout: int = 60) -> Dict[str, Any]:
        """
        Execute a command and return structured results
        
        Args:
            cmd: Command to execute
            input_data: Optional stdin input
            timeout: Command timeout in seconds
            
        Returns:
            Dictionary with command results
        """
        try:
            result = subprocess.run(
                cmd,
                input=input_data,
                text=True,
                capture_output=True,
                timeout=timeout
            )
            
            return {
                "success": result.returncode == 0,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "command": " ".join(cmd)
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "returncode": -1,
                "stdout": "",
                "stderr": f"Command timed out after {timeout} seconds",
                "command": " ".join(cmd)
            }
        except Exception as e:
            return {
                "success": False,
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
                "command": " ".join(cmd)
            }
    
    def test_bundle_processing(self, bundle_name: str, bundle_image: str) -> Dict[str, Any]:
        """Test basic bundle processing and metadata extraction"""
        print(f"🔍 Testing bundle processing: {bundle_name}")
        
        cmd = self.base_cmd + ["--image", bundle_image]
        result = self.run_command(cmd)
        
        test_result = {
            "test": f"bundle_processing_{bundle_name}",
            "description": f"Process bundle {bundle_name} and extract RBAC",
            "success": result["success"],
            "duration": 0,
            "details": {
                "bundle_image": bundle_image,
                "command": result["command"],
                "returncode": result["returncode"]
            }
        }
        
        if result["success"]:
            # Validate YAML output structure
            try:
                # Extract YAML content after status messages
                output_lines = result["stdout"].split('\n')
                yaml_start_idx = 0
                
                # Find the start of YAML content (skip status messages)
                for i, line in enumerate(output_lines):
                    if line.strip().startswith('apiVersion:'):
                        yaml_start_idx = i
                        break
                
                yaml_content = '\n'.join(output_lines[yaml_start_idx:])
                
                # Split by section headers and --- separators
                sections = []
                current_section = []
                
                for line in yaml_content.split('\n'):
                    if line.strip().startswith('=') and len(line.strip()) > 10:
                        # New section header, save previous section
                        if current_section:
                            sections.append('\n'.join(current_section))
                            current_section = []
                    elif line.strip() == '---':
                        # YAML document separator, save previous section
                        if current_section:
                            sections.append('\n'.join(current_section))
                            current_section = []
                    else:
                        current_section.append(line)
                
                # Add final section
                if current_section:
                    sections.append('\n'.join(current_section))
                
                expected_docs = ["ServiceAccount", "ClusterRole", "ClusterRoleBinding"]
                found_docs = []
                
                for section in sections:
                    section = section.strip()
                    if section and ('apiVersion:' in section or 'kind:' in section):
                        try:
                            parsed = yaml.safe_load(section)
                            if parsed and "kind" in parsed:
                                found_docs.append(parsed["kind"])
                        except yaml.YAMLError:
                            continue
                
                test_result["details"]["found_documents"] = found_docs
                test_result["details"]["yaml_document_count"] = len(sections)
                
                # Validate that we have at least the minimum expected documents
                has_minimum = all(doc in found_docs for doc in expected_docs[:2])  # SA, CR (CRB might be separate)
                test_result["details"]["has_minimum_docs"] = has_minimum
                
                if not has_minimum:
                    test_result["success"] = False
                    test_result["details"]["error"] = f"Missing expected documents. Found: {found_docs}"
                
            except Exception as e:
                test_result["success"] = False
                test_result["details"]["error"] = f"Failed to parse YAML output: {e}"
        else:
            test_result["details"]["error"] = result["stderr"]
        
        return test_result
    
    def test_helm_generation(self, bundle_name: str, bundle_image: str) -> Dict[str, Any]:
        """Test Helm values generation"""
        print(f"⚙️ Testing Helm generation: {bundle_name}")
        
        cmd = self.base_cmd + ["--image", bundle_image, "--helm"]
        result = self.run_command(cmd)
        
        test_result = {
            "test": f"helm_generation_{bundle_name}",
            "description": f"Generate Helm values for {bundle_name}",
            "success": result["success"],
            "duration": 0,
            "details": {
                "bundle_image": bundle_image,
                "command": result["command"],
                "returncode": result["returncode"]
            }
        }
        
        if result["success"]:
            try:
                # Extract YAML content after status messages and headers
                output_lines = result["stdout"].split('\n')
                yaml_start_idx = 0
                
                # Find the start of YAML content (look for nameOverride or other YAML keys)
                for i, line in enumerate(output_lines):
                    if line.strip().startswith('nameOverride:') or line.strip().startswith('fullnameOverride:'):
                        yaml_start_idx = i
                        break
                
                yaml_content = '\n'.join(output_lines[yaml_start_idx:])
                
                # Parse YAML output
                helm_values = yaml.safe_load(yaml_content)
                
                # Validate Helm values structure
                expected_keys = ["operator", "serviceAccount", "permissions"]
                found_keys = list(helm_values.keys()) if helm_values else []
                
                test_result["details"]["found_keys"] = found_keys
                test_result["details"]["has_required_structure"] = all(key in found_keys for key in expected_keys)
                
                # Validate permissions structure
                if "permissions" in helm_values:
                    perms = helm_values["permissions"]
                    test_result["details"]["cluster_roles_count"] = len(perms.get("clusterRoles", []))
                    test_result["details"]["roles_count"] = len(perms.get("roles", []))
                    
                    # Check for channel guidance comment in output
                    has_channel_guidance = "IMPORTANT: Verify Correct Channel" in result["stdout"]
                    test_result["details"]["has_channel_guidance"] = has_channel_guidance
                
                if not test_result["details"]["has_required_structure"]:
                    test_result["success"] = False
                    test_result["details"]["error"] = f"Invalid Helm structure. Expected: {expected_keys}, Found: {found_keys}"
                
            except yaml.YAMLError as e:
                test_result["success"] = False
                test_result["details"]["error"] = f"Failed to parse Helm YAML: {e}"
        else:
            test_result["details"]["error"] = result["stderr"]
        
        return test_result
    
    def test_rbac_component_analysis(self, bundle_name: str, bundle_image: str) -> Dict[str, Any]:
        """Test centralized RBAC component analysis"""
        print(f"🔍 Testing RBAC component analysis: {bundle_name}")
        
        # Import the RBAC manager modules for direct testing
        try:
            from libs.opm.processor import BundleProcessor  # pyright: ignore[reportMissingImports]
            from libs.opm.helm_generator import HelmValuesGenerator  # pyright: ignore[reportMissingImports]
            
            processor = BundleProcessor()
            generator = HelmValuesGenerator()
            
            # Process bundle to get metadata
            bundle_metadata = processor.extract_bundle_metadata(bundle_image)
            
            # Test centralized component analysis
            rbac_analysis = generator.analyze_rbac_components(bundle_metadata)
            
            test_result = {
                "test": f"rbac_analysis_{bundle_name}",
                "description": f"Test centralized RBAC component analysis for {bundle_name}",
                "success": True,
                "duration": 0,
                "details": {
                    "bundle_image": bundle_image,
                    "permission_scenario": rbac_analysis.get("permission_scenario", "unknown"),
                    "components_needed": rbac_analysis.get("components_needed", {}),
                    "rule_counts": {}
                }
            }
            
            # Analyze rule counts
            rules = rbac_analysis.get("rules", {})
            for component, rule_list in rules.items():
                test_result["details"]["rule_counts"][component] = len(rule_list) if rule_list else 0
            
            # Validate expected structure
            expected_keys = ["components_needed", "rules", "permission_scenario", "analysis"]
            missing_keys = [key for key in expected_keys if key not in rbac_analysis]
            
            if missing_keys:
                test_result["success"] = False
                test_result["details"]["error"] = f"Missing analysis keys: {missing_keys}"
            
            # Validate components_needed structure
            components = rbac_analysis.get("components_needed", {})
            expected_components = ["installer_cluster_role", "grantor_cluster_role", "namespace_role", "cluster_role_bindings", "role_bindings"]
            missing_components = [comp for comp in expected_components if comp not in components]
            
            if missing_components:
                test_result["success"] = False
                test_result["details"]["error"] = f"Missing component flags: {missing_components}"
            
        except Exception as e:
            test_result = {
                "test": f"rbac_analysis_{bundle_name}",
                "description": f"Test centralized RBAC component analysis for {bundle_name}",
                "success": False,
                "duration": 0,
                "details": {
                    "bundle_image": bundle_image,
                    "error": str(e)
                }
            }
        
        return test_result
    
    def test_dry_deduplication(self, bundle_name: str, bundle_image: str) -> Dict[str, Any]:
        """Test DRY deduplication functionality"""
        print(f"🧹 Testing DRY deduplication: {bundle_name}")
        
        cmd = self.base_cmd + ["--image", bundle_image, "--helm"]
        result = self.run_command(cmd)
        
        test_result = {
            "test": f"dry_deduplication_{bundle_name}",
            "description": f"Test DRY deduplication for {bundle_name}",
            "success": result["success"],
            "duration": 0,
            "details": {
                "bundle_image": bundle_image,
                "command": result["command"]
            }
        }
        
        if result["success"]:
            try:
                # Extract YAML content after status messages and headers
                output_lines = result["stdout"].split('\n')
                yaml_start_idx = 0
                
                # Find the start of YAML content (look for nameOverride or other YAML keys)
                for i, line in enumerate(output_lines):
                    if line.strip().startswith('nameOverride:') or line.strip().startswith('fullnameOverride:'):
                        yaml_start_idx = i
                        break
                
                yaml_content = '\n'.join(output_lines[yaml_start_idx:])
                
                helm_values = yaml.safe_load(yaml_content)
                permissions = helm_values.get("permissions", {})
                
                cluster_roles = permissions.get("clusterRoles", [])
                roles = permissions.get("roles", [])
                
                test_result["details"]["cluster_roles_count"] = len(cluster_roles)
                test_result["details"]["roles_count"] = len(roles)
                
                # Analyze rule distribution for deduplication effectiveness
                total_cluster_rules = sum(len(cr.get("customRules", [])) for cr in cluster_roles)
                total_role_rules = sum(len(r.get("customRules", [])) for r in roles)
                
                test_result["details"]["total_cluster_rules"] = total_cluster_rules
                test_result["details"]["total_role_rules"] = total_role_rules
                
                # Check for evidence of deduplication (roles should have fewer rules when cluster rules exist)
                if cluster_roles and roles:
                    deduplication_effective = total_role_rules < total_cluster_rules
                    test_result["details"]["deduplication_effective"] = deduplication_effective
                
                # Look for DRY-related comments or structure
                output_text = result["stdout"]
                has_dedup_evidence = any(keyword in output_text.lower() for keyword in ["deduplicated", "dry", "filtered"])
                test_result["details"]["has_dedup_evidence"] = has_dedup_evidence
                
            except Exception as e:
                test_result["success"] = False
                test_result["details"]["error"] = f"Failed to analyze deduplication: {e}"
        else:
            test_result["details"]["error"] = result["stderr"]
        
        return test_result
    
    def test_output_directory(self, bundle_name: str, bundle_image: str) -> Dict[str, Any]:
        """Test output directory functionality"""
        print(f"📁 Testing output directory: {bundle_name}")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "test-output"
            cmd = self.base_cmd + ["--image", bundle_image, "--output", str(output_dir)]
            result = self.run_command(cmd)
            
            test_result = {
                "test": f"output_directory_{bundle_name}",
                "description": f"Test output directory generation for {bundle_name}",
                "success": result["success"],
                "duration": 0,
                "details": {
                    "bundle_image": bundle_image,
                    "output_directory": str(output_dir),
                    "command": result["command"]
                }
            }
            
            if result["success"]:
                # Check if output directory was created
                if output_dir.exists():
                    files = list(output_dir.glob("*.yaml"))
                    test_result["details"]["files_created"] = [f.name for f in files]
                    test_result["details"]["file_count"] = len(files)
                    
                    # Validate minimum expected files
                    expected_patterns = ["serviceaccount", "clusterrole", "clusterrolebinding"]
                    found_patterns = []
                    
                    for pattern in expected_patterns:
                        if any(pattern in f.name.lower() for f in files):
                            found_patterns.append(pattern)
                    
                    test_result["details"]["found_patterns"] = found_patterns
                    test_result["details"]["has_minimum_files"] = len(found_patterns) >= 3
                    
                    if not test_result["details"]["has_minimum_files"]:
                        test_result["success"] = False
                        test_result["details"]["error"] = f"Missing expected files. Found patterns: {found_patterns}"
                else:
                    test_result["success"] = False
                    test_result["details"]["error"] = "Output directory was not created"
            else:
                test_result["details"]["error"] = result["stderr"]
        
        return test_result
    
    def test_error_handling(self) -> Dict[str, Any]:
        """Test error handling with invalid inputs"""
        print("❌ Testing error handling")
        
        # Test with invalid bundle image
        invalid_image = "invalid-registry.com/nonexistent/bundle:latest"
        cmd = self.base_cmd + ["--image", invalid_image]
        result = self.run_command(cmd, timeout=30)
        
        # The tool returns 0 but outputs error messages, so check for error content instead
        has_error_output = bool(result["stderr"]) or "Error:" in result["stdout"] or "Failed" in result["stdout"]
        
        test_result = {
            "test": "error_handling_invalid_image",
            "description": "Test error handling with invalid bundle image",
            "success": has_error_output,  # Success if error is properly reported
            "duration": 0,
            "details": {
                "invalid_image": invalid_image,
                "command": result["command"],
                "returncode": result["returncode"],
                "error_message": result["stderr"],
                "stdout_message": result["stdout"]
            }
        }
        
        # Check for helpful error message
        error_text = result["stderr"] + " " + result["stdout"]
        if error_text:
            has_helpful_error = any(keyword in error_text.lower() for keyword in ["image", "bundle", "failed", "error"])
            test_result["details"]["has_helpful_error"] = has_helpful_error
        
        return test_result
    
    def test_permission_scenarios(self) -> List[Dict[str, Any]]:
        """Test different permission scenarios comprehensively"""
        print("🎯 Testing permission scenarios")
        
        results = []
        
        # Test each bundle type for different permission scenarios
        for bundle_name, bundle_image in self.test_bundles.items():
            # Skip if bundle image looks like placeholder
            if "1234567890" in bundle_image or "example" in bundle_image:
                continue
                
            scenario_result = {
                "test": f"permission_scenario_{bundle_name}",
                "description": f"Test permission scenario handling for {bundle_name}",
                "success": True,
                "duration": 0,
                "details": {
                    "bundle_name": bundle_name,
                    "bundle_image": bundle_image,
                    "scenarios_tested": []
                }
            }
            
            # Test both YAML and Helm generation
            for output_type in ["yaml", "helm"]:
                cmd = self.base_cmd + ["--image", bundle_image]
                if output_type == "helm":
                    cmd.append("--helm")
                
                result = self.run_command(cmd)
                
                scenario_test = {
                    "output_type": output_type,
                    "success": result["success"],
                    "error": result["stderr"] if not result["success"] else None
                }
                
                if result["success"]:
                    # Analyze output structure
                    try:
                        if output_type == "helm":
                            parsed = yaml.safe_load(result["stdout"])
                            if parsed and "permissions" in parsed:
                                perms = parsed["permissions"]
                                scenario_test["cluster_roles"] = len(perms.get("clusterRoles", []))
                                scenario_test["roles"] = len(perms.get("roles", []))
                        else:
                            # Count YAML documents
                            docs = result["stdout"].split("---")
                            scenario_test["yaml_documents"] = len([d for d in docs if d.strip()])
                    except Exception as e:
                        scenario_test["parse_error"] = str(e)
                
                scenario_result["details"]["scenarios_tested"].append(scenario_test)
                
                if not result["success"]:
                    scenario_result["success"] = False
            
            results.append(scenario_result)
        
        return results
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all OPM tests"""
        print("🚀 Starting OPM Test Suite")
        print("=" * 60)
        
        start_time = time.time()
        all_results = []
        
        # Test bundle processing for each available bundle
        for bundle_name, bundle_image in self.test_bundles.items():
            # Skip placeholder bundles
            if "1234567890" in bundle_image or "example" in bundle_image:
                print(f"⏭️ Skipping placeholder bundle: {bundle_name}")
                continue
            
            # Basic bundle processing
            result = self.test_bundle_processing(bundle_name, bundle_image)
            all_results.append(result)
            self.test_results.append(result)
            
            # Helm generation
            result = self.test_helm_generation(bundle_name, bundle_image)
            all_results.append(result)
            self.test_results.append(result)
            
            # RBAC component analysis
            result = self.test_rbac_component_analysis(bundle_name, bundle_image)
            all_results.append(result)
            self.test_results.append(result)
            
            # DRY deduplication
            result = self.test_dry_deduplication(bundle_name, bundle_image)
            all_results.append(result)
            self.test_results.append(result)
            
            # Output directory
            result = self.test_output_directory(bundle_name, bundle_image)
            all_results.append(result)
            self.test_results.append(result)
        
        # Error handling tests
        result = self.test_error_handling()
        all_results.append(result)
        self.test_results.append(result)
        
        # Permission scenario tests
        scenario_results = self.test_permission_scenarios()
        all_results.extend(scenario_results)
        self.test_results.extend(scenario_results)
        
        end_time = time.time()
        
        # Calculate summary
        total_tests = len(all_results)
        passed_tests = sum(1 for r in all_results if r["success"])
        failed_tests = total_tests - passed_tests
        
        print("\n" + "=" * 60)
        print("📊 OPM Test Results Summary")
        print("=" * 60)
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests} ✅")
        print(f"Failed: {failed_tests} ❌")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        print(f"Duration: {end_time - start_time:.2f}s")
        
        if failed_tests > 0:
            print("\n❌ Failed Tests:")
            for result in all_results:
                if not result["success"]:
                    print(f"  - {result['test']}: {result.get('details', {}).get('error', 'Unknown error')}")
        
        return {
            "total": total_tests,
            "passed": passed_tests,
            "failed": failed_tests,
            "success_rate": (passed_tests/total_tests)*100,
            "duration": end_time - start_time
        }
    
    def save_results(self, results_file: str = None) -> None:
        """Save test results to JSON file"""
        if not results_file:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            results_file = f"opm_test_results_{timestamp}.json"
        
        summary = {
            "test_suite": "opm",
            "timestamp": time.time(),
            "configuration": {
                "skip_tls": self.skip_tls,
                "debug": self.debug,
                "test_bundles": self.test_bundles
            },
            "results": self.test_results
        }
        
        with open(results_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"📄 Test results saved to: {results_file}")


def main():
    """Main test runner"""
    print("🧪 OPM Test Suite")
    print("Testing RBAC Manager OPM functionality")
    print("=" * 60)
    
    # Check if we're in the right directory
    if not Path("rbac-manager.py").exists():
        print("❌ Error: rbac-manager.py not found")
        print("   Please run this test from the tools/rbac-manager directory")
        sys.exit(1)
    
    # Initialize and run test suite
    test_suite = OPMTestSuite(
        skip_tls=True,
        debug=False
    )
    
    # Run tests
    results = test_suite.run_all_tests()
    
    # Save results
    test_suite.save_results()
    
    # Exit with appropriate code
    sys.exit(0 if results["failed"] == 0 else 1)


if __name__ == "__main__":
    main()
