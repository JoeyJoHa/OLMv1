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

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import yaml
from pathlib import Path
from typing import Dict, List, Any, NamedTuple

# Import shared test constants and setup path
from test_constants import OPMTestConstants, TestUtilities
TestUtilities.setup_test_path()


class OPMTestResult(NamedTuple):
    """Structured test result for OPM tests"""
    test_name: str
    description: str
    success: bool
    duration: float
    details: Dict[str, Any]


class OPMCommandBuilder:
    """Builder pattern for OPM test commands"""
    
    def __init__(self, base_cmd: List[str]):
        self.cmd = base_cmd.copy()
    
    def with_image(self, image: str) -> 'OPMCommandBuilder':
        """Add bundle image argument"""
        self.cmd.extend(["--image", image])
        return self
    
    def with_helm(self) -> 'OPMCommandBuilder':
        """Add Helm flag"""
        self.cmd.append("--helm")
        return self
    
    def with_namespace(self, namespace: str) -> 'OPMCommandBuilder':
        """Add namespace argument"""
        self.cmd.extend(["--namespace", namespace])
        return self
    
    def with_output(self, output_path: str) -> 'OPMCommandBuilder':
        """Add output directory argument"""
        self.cmd.extend(["--output", output_path])
        return self
    
    def with_config(self, config_file: str) -> 'OPMCommandBuilder':
        """Add config file argument"""
        self.cmd.extend(["--config", config_file])
        return self
    
    def with_skip_tls(self) -> 'OPMCommandBuilder':
        """Add skip TLS flag"""
        self.cmd.append("--skip-tls")
        return self
    
    def with_debug(self) -> 'OPMCommandBuilder':
        """Add debug flag"""
        self.cmd.append("--debug")
        return self
    
    def build(self) -> List[str]:
        """Build the final command"""
        return self.cmd.copy()

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
        
        # Build base command using builder pattern
        builder = OPMCommandBuilder(["python3", "rbac-manager.py", "opm"])
        if skip_tls:
            builder = builder.with_skip_tls()
        if debug:
            builder = builder.with_debug()
        self.base_cmd = builder.build()
        
        self.test_results = []
        
        # Test bundle images for different scenarios (using real operator bundles)
        self.test_bundles = {
            "openshift-gitops": OPMTestConstants.GITOPS_BUNDLE,
            "quay-operator": OPMTestConstants.QUAY_BUNDLE,
            "argocd-community": OPMTestConstants.ARGOCD_BUNDLE,
            "invalid-bundle": OPMTestConstants.INVALID_BUNDLE, # Mock test to ensure error handling
        }
        
        # Test scenarios for comprehensive coverage (using constants)
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
                "flags": ["--namespace", OPMTestConstants.DEFAULT_NAMESPACE]
            },
            {
                "name": "output_directory",
                "description": "Generate with output directory",
                "flags": ["--output", f"./{OPMTestConstants.OUTPUT_SUBDIR}"]
            },
            {
                "name": "helm_with_namespace",
                "description": "Generate Helm values with custom namespace",
                "flags": ["--helm", "--namespace", OPMTestConstants.PRODUCTION_NAMESPACE]
            }
        ]
    
    def run_command(self, cmd: List[str], input_data: str = None, 
                   timeout: int = OPMTestConstants.DEFAULT_TIMEOUT) -> Dict[str, Any]:
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
    
    def _create_test_result(self, test_name: str, description: str, success: bool, 
                           details: Dict[str, Any], duration: float = 0.0) -> Dict[str, Any]:
        """Create standardized test result structure"""
        result = TestUtilities.create_test_result(test_name, success, details, duration)
        result["description"] = description  # Add OPM-specific field
        return result
    
    def _is_placeholder_bundle(self, bundle_image: str) -> bool:
        """Check if bundle image is a placeholder"""
        # All our test bundles are now real, so only check for the invalid test bundle
        return bundle_image == OPMTestConstants.INVALID_BUNDLE
    
    def _extract_yaml_content(self, output: str, start_marker: str = "apiVersion:") -> str:
        """Extract YAML content from command output"""
        # Check for error conditions first
        if "Failed to extract bundle metadata" in output or "ERROR -" in output:
            return ""
        
        output_lines = output.split('\n')
        yaml_start_idx = 0
        
        # Find the start of YAML content
        for i, line in enumerate(output_lines):
            if line.strip().startswith(start_marker):
                yaml_start_idx = i
                break
        
        # If no YAML markers found, return empty
        if yaml_start_idx == 0 and not any(line.strip().startswith(start_marker) for line in output_lines):
            return ""
        
        return '\n'.join(output_lines[yaml_start_idx:])
    
    def _extract_helm_content(self, output: str) -> str:
        """Extract Helm YAML content from command output"""
        # Check for error conditions first
        if "Failed to extract bundle metadata" in output or "ERROR -" in output:
            return ""
        
        output_lines = output.split('\n')
        yaml_start_idx = 0
        yaml_end_idx = len(output_lines)
        
        # Find the start of YAML content (look for Helm-specific keys)
        helm_markers = ['nameOverride:', 'fullnameOverride:', 'operator:']
        for i, line in enumerate(output_lines):
            if any(line.strip().startswith(marker) for marker in helm_markers):
                yaml_start_idx = i
                break
        
        # If no YAML markers found, return empty
        if yaml_start_idx == 0 and not any(any(line.strip().startswith(marker) for marker in helm_markers) for line in output_lines):
            return ""
        
        # Find the end of YAML content (stop at section headers or non-YAML lines)
        for i in range(yaml_start_idx, len(output_lines)):
            line = output_lines[i].strip()
            # Stop at section headers (lines with = characters)
            if line.startswith('=') and len(line) > 10:
                yaml_end_idx = i
                break
            # Stop at lines that look like status messages
            if line.startswith('2025-') or 'INFO -' in line or 'ERROR -' in line:
                yaml_end_idx = i
                break
        
        # Extract only the YAML content, filtering out comments and empty lines at the start
        yaml_lines = []
        for line in output_lines[yaml_start_idx:yaml_end_idx]:
            stripped = line.strip()
            # Skip comment lines and empty lines, but keep YAML content
            if stripped and not stripped.startswith('#'):
                yaml_lines.append(line)
            elif yaml_lines:  # If we've started collecting YAML, keep empty lines for formatting
                yaml_lines.append(line)
        
        return '\n'.join(yaml_lines)
    
    def _parse_yaml_documents(self, yaml_content: str) -> List[Dict[str, Any]]:
        """Parse YAML content into document sections"""
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
        
        # Parse sections into YAML documents
        documents = []
        for section in sections:
            section = section.strip()
            if section and ('apiVersion:' in section or 'kind:' in section):
                try:
                    parsed = yaml.safe_load(section)
                    if parsed and "kind" in parsed:
                        documents.append(parsed)
                except yaml.YAMLError:
                    continue
        
        return documents
    
    def _validate_yaml_documents(self, documents: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate YAML documents against expected structure"""
        found_docs = [doc.get("kind", "") for doc in documents]
        has_minimum = all(doc in found_docs for doc in OPMTestConstants.EXPECTED_YAML_DOCS[:2])
        
        return {
            "found_documents": found_docs,
            "yaml_document_count": len(documents),
            "has_minimum_docs": has_minimum
        }
    
    def _validate_helm_structure(self, helm_values: Dict[str, Any]) -> Dict[str, Any]:
        """Validate Helm values structure"""
        # Handle None or empty helm_values
        if not helm_values:
            return {
                "found_keys": [],
                "has_required_structure": False,
                "cluster_roles_count": 0,
                "roles_count": 0
            }
        
        found_keys = list(helm_values.keys())
        has_required_structure = all(key in found_keys for key in OPMTestConstants.EXPECTED_HELM_KEYS)
        
        validation = {
            "found_keys": found_keys,
            "has_required_structure": has_required_structure
        }
        
        # Validate permissions structure
        if "permissions" in helm_values:
            perms = helm_values["permissions"]
            validation["cluster_roles_count"] = len(perms.get("clusterRoles", []))
            validation["roles_count"] = len(perms.get("roles", []))
        else:
            validation["cluster_roles_count"] = 0
            validation["roles_count"] = 0
        
        return validation
    
    def _analyze_permission_structure(self, helm_values: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze permission structure to determine operator permission patterns"""
        analysis = {
            "has_cluster_permissions": False,
            "has_namespace_permissions": False,
            "permission_scenario": "unknown",
            "cluster_roles_count": 0,
            "roles_count": 0,
            "total_permissions": 0
        }
        
        # Handle None or empty helm_values
        if not helm_values or "permissions" not in helm_values:
            return analysis
        
        permissions = helm_values["permissions"]
        
        # Analyze cluster roles
        cluster_roles = permissions.get("clusterRoles", [])
        if cluster_roles:
            analysis["has_cluster_permissions"] = True
            analysis["cluster_roles_count"] = len(cluster_roles)
            
            # Count total cluster permissions
            for cluster_role in cluster_roles:
                rules = cluster_role.get("customRules", [])
                analysis["total_permissions"] += len(rules)
        
        # Analyze namespace roles
        roles = permissions.get("roles", [])
        if roles:
            analysis["has_namespace_permissions"] = True
            analysis["roles_count"] = len(roles)
            
            # Count total namespace permissions
            for role in roles:
                rules = role.get("customRules", [])
                analysis["total_permissions"] += len(rules)
        
        # Determine permission scenario
        if analysis["has_cluster_permissions"] and analysis["has_namespace_permissions"]:
            analysis["permission_scenario"] = "both_cluster_and_namespace"
        elif analysis["has_cluster_permissions"]:
            analysis["permission_scenario"] = "cluster_only"
        elif analysis["has_namespace_permissions"]:
            analysis["permission_scenario"] = "namespace_only"
        else:
            analysis["permission_scenario"] = "no_permissions"
        
        return analysis
    
    def _create_config_file(self, temp_dir: str, bundle_image: str, output_type: str = "yaml", 
                           channel: str = OPMTestConstants.STABLE_CHANNEL) -> str:
        """Create a test configuration file"""
        config_file = os.path.join(temp_dir, f"test-{output_type}-config.yaml")
        
        config_content = f"""
operator:
  image: "{bundle_image}"
  namespace: "{OPMTestConstants.DEFAULT_NAMESPACE}"
  channel: "{channel}"
  packageName: "test-operator"
  version: "{OPMTestConstants.TEST_VERSION}"
output:
  mode: "file"
  type: "{output_type}"
  path: "{temp_dir}"
global:
  skip_tls: true
  debug: false
  registry_token: ""
"""
        with open(config_file, 'w') as f:
            f.write(config_content)
        
        return config_file
    
    def _test_config_output(self, test_name: str, description: str, config_file: str, 
                           temp_dir: str, output_type: str) -> Dict[str, Any]:
        """Test config file output generation"""
        cmd = OPMCommandBuilder(self.base_cmd).with_config(config_file).build()
        result = self.run_command(cmd)
        
        details = {
            "config_file": config_file,
            "command": result["command"],
            "returncode": result["returncode"]
        }
        
        if result["success"]:
            if output_type == "yaml":
                # Check if YAML files were created
                yaml_files = list(Path(temp_dir).glob("*-serviceaccount-*.yaml"))
                details["yaml_files_created"] = len(yaml_files) > 0
                details["files_count"] = len(list(Path(temp_dir).glob("*.yaml"))) - 1  # Exclude config file
            elif output_type == "helm":
                # Check if Helm values file was created
                helm_files = list(Path(temp_dir).glob("*-*.yaml"))
                details["helm_file_created"] = len(helm_files) > 0
                
                # Check if channel from config appears in output
                if helm_files:
                    try:
                        with open(helm_files[0], 'r') as f:
                            helm_content = f.read()
                        details["channel_from_config"] = f'channel: {OPMTestConstants.ALPHA_CHANNEL}' in helm_content
                    except Exception:
                        details["channel_from_config"] = False
        else:
            details["error"] = result["stderr"]
        
        return self._create_test_result(test_name, description, result["success"], details)
    
    def test_bundle_processing(self, bundle_name: str, bundle_image: str) -> Dict[str, Any]:
        """Test basic bundle processing and metadata extraction"""
        print(f"🔍 Testing bundle processing: {bundle_name}")
        
        cmd = OPMCommandBuilder(self.base_cmd).with_image(bundle_image).build()
        result = self.run_command(cmd)
        
        details = {
            "bundle_image": bundle_image,
            "command": result["command"],
            "returncode": result["returncode"]
        }
        
        if result["success"]:
            try:
                # Extract and parse YAML content using helper methods
                yaml_content = self._extract_yaml_content(result["stdout"])
                documents = self._parse_yaml_documents(yaml_content)
                validation = self._validate_yaml_documents(documents)
                
                details.update(validation)
                
                if not validation["has_minimum_docs"]:
                    result["success"] = False
                    details["error"] = f"Missing expected documents. Found: {validation['found_documents']}"
                
            except Exception as e:
                result["success"] = False
                details["error"] = f"Failed to parse YAML output: {e}"
        else:
            details["error"] = result["stderr"]
        
        return self._create_test_result(
            f"bundle_processing_{bundle_name}",
            f"Process bundle {bundle_name} and extract RBAC",
            result["success"],
            details
        )
    
    def test_helm_generation(self, bundle_name: str, bundle_image: str) -> Dict[str, Any]:
        """Test Helm values generation"""
        print(f"⚙️ Testing Helm generation: {bundle_name}")
        
        cmd = OPMCommandBuilder(self.base_cmd).with_image(bundle_image).with_helm().build()
        result = self.run_command(cmd)
        
        details = {
            "bundle_image": bundle_image,
            "command": result["command"],
            "returncode": result["returncode"]
        }
        
        if result["success"]:
            try:
                # Extract and parse Helm content using helper methods
                helm_content = self._extract_helm_content(result["stdout"])
                helm_values = yaml.safe_load(helm_content)
                validation = self._validate_helm_structure(helm_values)
                
                details.update(validation)
                
                # Analyze permission structure for this bundle
                permission_analysis = self._analyze_permission_structure(helm_values)
                details.update(permission_analysis)
                
                # Check for channel guidance comment in output
                has_channel_guidance = OPMTestConstants.CHANNEL_GUIDANCE in result["stdout"]
                details["has_channel_guidance"] = has_channel_guidance
                
                if not validation["has_required_structure"]:
                    result["success"] = False
                    details["error"] = f"Invalid Helm structure. Expected: {OPMTestConstants.EXPECTED_HELM_KEYS}, Found: {validation['found_keys']}"
                
            except yaml.YAMLError as e:
                result["success"] = False
                details["error"] = f"Failed to parse Helm YAML: {e}"
        else:
            details["error"] = result["stderr"]
        
        return self._create_test_result(
            f"helm_generation_{bundle_name}",
            f"Generate Helm values for {bundle_name}",
            result["success"],
            details
        )
    
    def test_rbac_component_analysis(self, bundle_name: str, bundle_image: str) -> Dict[str, Any]:
        """Test centralized RBAC component analysis"""
        print(f"🔍 Testing RBAC component analysis: {bundle_name}")
        
        # Import the RBAC manager modules for direct testing
        try:
            from libs.opm.processor import BundleProcessor  # pyright: ignore[reportMissingImports]
            from libs.opm.helm_generator import HelmValuesGenerator  # pyright: ignore[reportMissingImports]
            from libs.core.exceptions import BundleProcessingError  # pyright: ignore[reportMissingImports]
            
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
            
        except BundleProcessingError as e:
            test_result = {
                "test": f"rbac_analysis_{bundle_name}",
                "description": f"Test centralized RBAC component analysis for {bundle_name}",
                "success": False,
                "duration": 0,
                "details": {
                    "bundle_image": bundle_image,
                    "error": f"Bundle processing failed: {str(e)}",
                    "error_type": "BundleProcessingError"
                }
            }
        except Exception as e:
            test_result = {
                "test": f"rbac_analysis_{bundle_name}",
                "description": f"Test centralized RBAC component analysis for {bundle_name}",
                "success": False,
                "duration": 0,
                "details": {
                    "bundle_image": bundle_image,
                    "error": f"Unexpected error: {str(e)}",
                    "error_type": type(e).__name__
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
        
        # Test with invalid bundle image using constants
        cmd = OPMCommandBuilder(self.base_cmd).with_image(OPMTestConstants.INVALID_BUNDLE).build()
        result = self.run_command(cmd, timeout=30)
        
        # The tool returns 0 but outputs error messages, so check for error content instead
        has_error_output = bool(result["stderr"]) or "Error:" in result["stdout"] or "Failed" in result["stdout"]
        
        details = {
            "invalid_image": OPMTestConstants.INVALID_BUNDLE,
            "command": result["command"],
            "returncode": result["returncode"],
            "error_message": result["stderr"],
            "stdout_message": result["stdout"]
        }
        
        # Check for helpful error message using constants
        error_text = result["stderr"] + " " + result["stdout"]
        if error_text:
            has_helpful_error = any(keyword in error_text.lower() for keyword in OPMTestConstants.ERROR_KEYWORDS)
            details["has_helpful_error"] = has_helpful_error
        
        return self._create_test_result(
            "error_handling_invalid_image",
            "Test error handling with invalid bundle image",
            has_error_output,  # Success if error is properly reported
            details
        )
    
    def test_config_functionality(self) -> List[Dict[str, Any]]:
        """Test config file functionality"""
        print("⚙️ Testing config file functionality")
        
        results = []
        test_bundle_image = next(iter(self.test_bundles.values()))
        
        # Skip if placeholder bundle
        if self._is_placeholder_bundle(test_bundle_image):
            return [self._create_test_result(
                "config_functionality_skipped",
                "Config tests skipped - no valid bundle image",
                True,
                {"reason": "No valid test bundle available"}
            )]
        
        # Test 1: Config file with YAML output
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = self._create_config_file(temp_dir, test_bundle_image, "yaml", OPMTestConstants.STABLE_CHANNEL)
            result = self._test_config_output("config_yaml_output", "Test config file with YAML output", 
                                            config_file, temp_dir, "yaml")
            results.append(result)
        
        # Test 2: Config file with Helm output
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = self._create_config_file(temp_dir, test_bundle_image, "helm", OPMTestConstants.ALPHA_CHANNEL)
            result = self._test_config_output("config_helm_output", "Test config file with Helm output", 
                                            config_file, temp_dir, "helm")
            results.append(result)
        
        # Test 3: Invalid config file handling
        with tempfile.TemporaryDirectory() as temp_dir:
            invalid_config_file = os.path.join(temp_dir, "invalid-config.yaml")
            
            # Create invalid config file
            with open(invalid_config_file, 'w') as f:
                f.write("invalid: yaml: content: [")
            
            cmd = OPMCommandBuilder(self.base_cmd).with_config(invalid_config_file).build()
            result = self.run_command(cmd)
            
            invalid_result = self._create_test_result(
                "invalid_config_handling",
                "Test handling of invalid config file",
                not result["success"],  # Should fail gracefully
                {
                    "config_file": invalid_config_file,
                    "command": result["command"],
                    "returncode": result["returncode"],
                    "failed_as_expected": not result["success"]
                }
            )
            results.append(invalid_result)
        
        return results
    
    def test_formatting_features(self) -> List[Dict[str, Any]]:
        """Test FlowStyleList formatting and channel placeholder features"""
        print("🎨 Testing formatting features")
        
        results = []
        test_bundle_image = next(iter(self.test_bundles.values()))
        
        # Skip if placeholder bundle
        if self._is_placeholder_bundle(test_bundle_image):
            return [self._create_test_result(
                "formatting_features_skipped",
                "Formatting tests skipped - no valid bundle image",
                True,
                {"reason": "No valid test bundle available"}
            )]
        
        # Test 1: FlowStyleList formatting in Helm output
        cmd = OPMCommandBuilder(self.base_cmd).with_image(test_bundle_image).with_helm().build()
        result = self.run_command(cmd)
        
        details = {
            "command": result["command"],
            "returncode": result["returncode"]
        }
        
        if result["success"]:
            # Check for flow-style arrays in output using constants
            has_flow_arrays = all(pattern in result["stdout"] for pattern in OPMTestConstants.FLOW_STYLE_PATTERNS)
            details["has_flow_style_arrays"] = has_flow_arrays
            
            # Check for resourceNames placeholder using constants
            has_resource_placeholder = OPMTestConstants.RESOURCE_PLACEHOLDER in result["stdout"]
            details["has_resource_names_placeholder"] = has_resource_placeholder
            
            result["success"] = has_flow_arrays and has_resource_placeholder
        else:
            details["error"] = result["stderr"]
        
        flow_style_result = self._create_test_result(
            "flowstylelist_formatting",
            "Test FlowStyleList formatting in Helm output",
            result["success"],
            details
        )
        results.append(flow_style_result)
        
        # Test 2: Channel placeholder when no config provided
        cmd = OPMCommandBuilder(self.base_cmd).with_image(test_bundle_image).with_helm().build()
        result = self.run_command(cmd)
        
        details = {
            "command": result["command"],
            "returncode": result["returncode"]
        }
        
        if result["success"]:
            # Check for channel placeholder using constants
            has_channel_placeholder = OPMTestConstants.CHANNEL_PLACEHOLDER in result["stdout"]
            details["has_channel_placeholder"] = has_channel_placeholder
            result["success"] = has_channel_placeholder
        else:
            details["error"] = result["stderr"]
        
        channel_result = self._create_test_result(
            "channel_placeholder",
            "Test channel placeholder when no config provided",
            result["success"],
            details
        )
        results.append(channel_result)
        
        # Test 3: Channel guidance comments
        if result["success"]:
            has_channel_guidance = OPMTestConstants.CHANNEL_GUIDANCE in result["stdout"]
            guidance_result = self._create_test_result(
                "channel_guidance_comments",
                "Test channel guidance comments in Helm output",
                has_channel_guidance,
                {
                    "has_guidance_comments": has_channel_guidance,
                    "command": result["command"]
                }
            )
            results.append(guidance_result)
        
        return results
    
    def test_permission_detection(self) -> List[Dict[str, Any]]:
        """Test permission scenario detection for each bundle type"""
        print("🔍 Testing permission scenario detection")
        
        results = []
        
        for bundle_name, bundle_image in self.test_bundles.items():
            print(f"   📋 Analyzing permissions for: {bundle_name}")
            
            # Generate Helm values to analyze permissions
            cmd = OPMCommandBuilder(self.base_cmd).with_image(bundle_image).with_helm().build()
            result = self.run_command(cmd)
            
            details = {
                "bundle_name": bundle_name,
                "bundle_image": bundle_image,
                "command": result["command"],
                "returncode": result["returncode"]
            }
            
            if result["success"]:
                try:
                    # Extract and analyze Helm content
                    helm_content = self._extract_helm_content(result["stdout"])
                    if helm_content.strip():  # Only analyze if we have content
                        helm_values = yaml.safe_load(helm_content)
                        permission_analysis = self._analyze_permission_structure(helm_values)
                        details.update(permission_analysis)
                        
                        # Log the detected scenario
                        scenario = permission_analysis["permission_scenario"]
                        cluster_count = permission_analysis["cluster_roles_count"]
                        role_count = permission_analysis["roles_count"]
                        total_perms = permission_analysis["total_permissions"]
                        
                        print(f"      └─ Scenario: {scenario}")
                        print(f"      └─ ClusterRoles: {cluster_count}, Roles: {role_count}, Total Rules: {total_perms}")
                    else:
                        details["error"] = "No Helm content extracted"
                        result["success"] = False
                        
                except Exception as e:
                    result["success"] = False
                    details["error"] = f"Failed to analyze permissions: {e}"
            else:
                details["error"] = result["stderr"]
            
            test_result = self._create_test_result(
                f"permission_detection_{bundle_name}",
                f"Detect permission scenario for {bundle_name}",
                result["success"],
                details
            )
            results.append(test_result)
        
        return results
    
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
                            # Use the helper method to extract clean Helm content
                            helm_content = self._extract_helm_content(result["stdout"])
                            parsed = yaml.safe_load(helm_content)
                            if parsed and "permissions" in parsed:
                                perms = parsed["permissions"]
                                scenario_test["cluster_roles"] = len(perms.get("clusterRoles", []))
                                scenario_test["roles"] = len(perms.get("roles", []))
                        else:
                            # Count YAML documents using helper method
                            yaml_content = self._extract_yaml_content(result["stdout"])
                            docs = yaml_content.split("---")
                            scenario_test["yaml_documents"] = len([d for d in docs if d.strip()])
                    except Exception as e:
                        scenario_test["parse_error"] = str(e)
                
                scenario_result["details"]["scenarios_tested"].append(scenario_test)
                
                if not result["success"]:
                    scenario_result["success"] = False
            
            results.append(scenario_result)
        
        return results
    
    def get_available_tests(self) -> Dict[str, str]:
        """Get dictionary of available test methods and their descriptions"""
        return {
            "bundle_processing": "Test bundle processing and metadata extraction for all bundles",
            "helm_generation": "Test Helm values generation for all bundles", 
            "rbac_component_analysis": "Test centralized RBAC component analysis for all bundles",
            "dry_deduplication": "Test DRY deduplication functionality for all bundles",
            "output_directory": "Test output directory functionality for all bundles",
            "permission_detection": "Test permission scenario detection for each bundle type",
            "config_functionality": "Test config file functionality",
            "formatting_features": "Test FlowStyleList formatting and channel placeholder features",
            "error_handling": "Test error handling with invalid inputs",
            "permission_scenarios": "Test different permission scenarios comprehensively"
        }
    
    def run_specific_test(self, test_name: str) -> Dict[str, Any]:
        """Run a specific test by name"""
        start_time = time.time()
        results = []
        
        # Define test execution functions
        def run_bundle_tests(test_method):
            """Helper to run test method for all valid bundles"""
            for bundle_name, bundle_image in self.test_bundles.items():
                if bundle_name != "invalid-bundle":  # Skip invalid bundle for most tests
                    result = test_method(bundle_name, bundle_image)
                    results.append(result)
                    self.test_results.append(result)
        
        def run_list_returning_test(test_method):
            """Helper to run test methods that return lists"""
            test_results = test_method()
            results.extend(test_results)
            self.test_results.extend(test_results)
        
        def run_single_test(test_method):
            """Helper to run test methods that return single results"""
            result = test_method()
            results.append(result)
            self.test_results.append(result)
        
        # Map test names to their execution functions
        test_map = {
            "bundle_processing": lambda: run_bundle_tests(self.test_bundle_processing),
            "helm_generation": lambda: run_bundle_tests(self.test_helm_generation),
            "rbac_component_analysis": lambda: run_bundle_tests(self.test_rbac_component_analysis),
            "dry_deduplication": lambda: run_bundle_tests(self.test_dry_deduplication),
            "output_directory": lambda: run_bundle_tests(self.test_output_directory),
            "permission_detection": lambda: run_list_returning_test(self.test_permission_detection),
            "config_functionality": lambda: run_list_returning_test(self.test_config_functionality),
            "formatting_features": lambda: run_list_returning_test(self.test_formatting_features),
            "error_handling": lambda: run_single_test(self.test_error_handling),
            "permission_scenarios": lambda: run_list_returning_test(self.test_permission_scenarios)
        }
        
        # Execute the test if it exists
        if test_name not in test_map:
            print(f"❌ Unknown test: {test_name}")
            return {"error": f"Unknown test: {test_name}"}
        
        test_map[test_name]()
        
        end_time = time.time()
        
        # Calculate summary
        total_tests = len(results)
        passed_tests = sum(1 for r in results if r["success"])
        failed_tests = total_tests - passed_tests
        
        print(f"\n📊 Test '{test_name}' Results:")
        print(f"Total: {total_tests}, Passed: {passed_tests} ✅, Failed: {failed_tests} ❌")
        print(f"Duration: {end_time - start_time:.2f}s")
        
        if failed_tests > 0:
            print("\n❌ Failed Tests:")
            for result in results:
                if not result["success"]:
                    print(f"  - {result['test']}: {result.get('details', {}).get('error', 'Unknown error')}")
        
        return {
            "test_name": test_name,
            "total": total_tests,
            "passed": passed_tests,
            "failed": failed_tests,
            "success_rate": (passed_tests/total_tests)*100 if total_tests > 0 else 0,
            "duration": end_time - start_time,
            "results": results
        }
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all OPM tests"""
        print("🚀 Starting OPM Test Suite")
        print("=" * 60)
        
        start_time = time.time()
        all_results = []
        
        # Test bundle processing for each available bundle
        for bundle_name, bundle_image in self.test_bundles.items():
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
        
        # Permission scenario detection test
        permission_results = self.test_permission_detection()
        all_results.extend(permission_results)
        self.test_results.extend(permission_results)
        
        # Config file tests
        config_results = self.test_config_functionality()
        all_results.extend(config_results)
        self.test_results.extend(config_results)
        
        # FlowStyleList and channel placeholder tests
        formatting_results = self.test_formatting_features()
        all_results.extend(formatting_results)
        self.test_results.extend(formatting_results)
        
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
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="OPM Test Suite")
    parser.add_argument("--unit", nargs="?", const="", help="Run specific test (use without argument to list available tests)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--no-skip-tls", action="store_true", help="Don't skip TLS verification")
    args = parser.parse_args()
    
    print("🧪 OPM Test Suite")
    print("Testing RBAC Manager OPM functionality")
    print("=" * 60)
    
    # Check if we're in the right directory
    if not Path("rbac-manager.py").exists():
        print("❌ Error: rbac-manager.py not found")
        print("   Please run this test from the tools/rbac-manager directory")
        sys.exit(1)
    
    # Initialize test suite
    test_suite = OPMTestSuite(
        skip_tls=not args.no_skip_tls,
        debug=args.debug
    )
    
    # Handle --unit flag
    if args.unit is not None:
        if args.unit == "":
            # List available tests
            available_tests = test_suite.get_available_tests()
            print("\n📋 Available Tests:")
            print("=" * 60)
            for test_name, description in available_tests.items():
                print(f"  {test_name:25} - {description}")
            print(f"\nUsage: python3 {Path(__file__).name} --unit <test_name>")
            sys.exit(0)
        else:
            # Run specific test
            available_tests = test_suite.get_available_tests()
            if args.unit not in available_tests:
                print(f"❌ Unknown test: {args.unit}")
                print(f"\nAvailable tests: {', '.join(available_tests.keys())}")
                sys.exit(1)
            
            print(f"🎯 Running specific test: {args.unit}")
            print("=" * 60)
            results = test_suite.run_specific_test(args.unit)
            
            if "error" in results:
                sys.exit(1)
            
            # Save results
            test_suite.save_results(f"opm_test_{args.unit}_results.json")
            
            # Exit with appropriate code
            sys.exit(0 if results["failed"] == 0 else 1)
    
    # Run all tests
    results = test_suite.run_all_tests()
    
    # Save results
    test_suite.save_results()
    
    # Exit with appropriate code
    sys.exit(0 if results["failed"] == 0 else 1)


if __name__ == "__main__":
    main()
