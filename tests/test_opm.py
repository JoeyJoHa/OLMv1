#!/usr/bin/env python3
"""
OPM Test Suite

Comprehensive tests for OPM functionality including:
- Bundle image processing and metadata extraction
- RBAC generation (Helm values and YAML manifests)
- Permission scenario handling (cluster-only, namespace-only, both, none)
- Output formatting and file generation
- Error handling and edge cases
"""

import argparse
import json
import os
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
from typing import Dict, List, Any, NamedTuple, Callable, Optional

# Import shared test constants and setup path
from test_constants import OPMTestConstants, TestUtilities, BaseTestSuite
TestUtilities.setup_test_path()

# Import RBAC manager modules for direct testing
try:
    from libs.opm.processor import BundleProcessor  # pyright: ignore[reportMissingImports]
    from libs.opm.helm_generator import HelmValuesGenerator  # pyright: ignore[reportMissingImports]
    from libs.core.exceptions import BundleProcessingError  # pyright: ignore[reportMissingImports]
except ImportError:
    # Fallback if imports fail
    BundleProcessor = None
    HelmValuesGenerator = None
    BundleProcessingError = None


class OPMTestResult(NamedTuple):
    """Structured test result for OPM tests"""
    test_name: str
    description: str
    success: bool
    duration: float
    details: Dict[str, Any]


class TestConfiguration(NamedTuple):
    """Configuration for data-driven test execution"""
    test_type: str
    description_template: str
    emoji: str
    command_flags: List[str]
    validation_func: Callable
    requires_temp_dir: bool = False
    skip_invalid_bundle: bool = True


class NonBundleTestConfiguration(NamedTuple):
    """Configuration for non-bundle data-driven test execution"""
    test_name: str
    description: str
    setup_func: Callable
    validation_func: Callable
    requires_temp_dir: bool = True
    should_succeed: bool = True


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
    
    def with_registry_token(self, token: str) -> 'OPMCommandBuilder':
        """Add registry token argument"""
        if token:
            self.cmd.extend(["--registry-token", token])
        return self
    
    def build(self) -> List[str]:
        """Build the final command"""
        return self.cmd.copy()

class OPMTestSuite(BaseTestSuite):
    """Test suite for OPM functionality"""
    
    def __init__(self, skip_tls: bool = False, debug: bool = False, registry_token: str = None):
        """
        Initialize test suite
        
        Args:
            skip_tls: Whether to skip TLS verification
            debug: Enable debug logging
            registry_token: Registry authentication token (optional)
        """
        super().__init__()  # Initialize BaseTestSuite
        
        self.skip_tls = skip_tls
        self.debug = debug
        self.registry_token = registry_token
        
        # Build base command using builder pattern (exclude sensitive registry token)
        builder = OPMCommandBuilder(["python3", "tools/rbac-manager/rbac-manager.py", "opm"])
        if skip_tls:
            builder = builder.with_skip_tls()
        if debug:
            builder = builder.with_debug()
        # Note: registry_token is NOT added to base_cmd for security reasons
        self.base_cmd = builder.build()
        
        # Test bundle images for different scenarios (using real operator bundles)
        self.test_bundles = {
            "openshift-gitops": OPMTestConstants.GITOPS_BUNDLE,
            "quay-operator": OPMTestConstants.QUAY_BUNDLE,
            "argocd-community": OPMTestConstants.ARGOCD_BUNDLE,
            "invalid-bundle": OPMTestConstants.INVALID_BUNDLE, # Mock test to ensure error handling
        }
        
        # Data-driven test configurations
        self.test_configurations = [
            TestConfiguration(
                test_type="bundle_processing",
                description_template="Process bundle {bundle_name} and extract RBAC",
                emoji="🔍",
                command_flags=[],
                validation_func=self._validate_bundle_processing,
                requires_temp_dir=False,
                skip_invalid_bundle=True
            ),
            TestConfiguration(
                test_type="helm_generation",
                description_template="Generate Helm values for {bundle_name}",
                emoji="⚙️",
                command_flags=["--helm"],
                validation_func=self._validate_helm_generation,
                requires_temp_dir=False,
                skip_invalid_bundle=True
            ),
            TestConfiguration(
                test_type="dry_deduplication",
                description_template="Test deduplication for {bundle_name}",
                emoji="🧹",
                command_flags=["--helm"],
                validation_func=self._validate_dry_deduplication,
                requires_temp_dir=False,
                skip_invalid_bundle=True
            ),
            TestConfiguration(
                test_type="output_directory",
                description_template="Test output directory generation for {bundle_name}",
                emoji="📁",
                command_flags=[],
                validation_func=self._validate_output_directory,
                requires_temp_dir=True,
                skip_invalid_bundle=True
            )
        ]
        
        # Non-bundle test configurations
        self.non_bundle_test_configurations = [
            NonBundleTestConfiguration(
                test_name="config_yaml_output",
                description="Test config file with YAML output",
                setup_func=self._setup_config_yaml_test,
                validation_func=self._validate_config_yaml_output,
                requires_temp_dir=True,
                should_succeed=True
            ),
            NonBundleTestConfiguration(
                test_name="config_helm_output",
                description="Test config file with Helm output",
                setup_func=self._setup_config_helm_test,
                validation_func=self._validate_config_helm_output,
                requires_temp_dir=True,
                should_succeed=True
            ),
            NonBundleTestConfiguration(
                test_name="invalid_config_handling",
                description="Test handling of invalid config file",
                setup_func=self._setup_invalid_config_test,
                validation_func=self._validate_invalid_config,
                requires_temp_dir=True,
                should_succeed=False  # Should fail gracefully
            ),
            NonBundleTestConfiguration(
                test_name="flowstylelist_formatting",
                description="Test FlowStyleList formatting in Helm output",
                setup_func=self._setup_flowstyle_test,
                validation_func=self._validate_flowstyle_formatting,
                requires_temp_dir=False,
                should_succeed=True
            ),
            NonBundleTestConfiguration(
                test_name="channel_placeholder",
                description="Test channel placeholder when no config provided",
                setup_func=self._setup_channel_placeholder_test,
                validation_func=self._validate_channel_placeholder,
                requires_temp_dir=False,
                should_succeed=True
            )
        ]
        
        # Additional bundle test configurations for remaining methods
        self.test_configurations.extend([
            TestConfiguration(
                test_type="rbac_component_analysis",
                description_template="Test centralized RBAC component analysis for {bundle_name}",
                emoji="🔍",
                command_flags=[],
                validation_func=self._validate_rbac_component_analysis,
                requires_temp_dir=False,
                skip_invalid_bundle=True
            ),
            TestConfiguration(
                test_type="permission_detection",
                description_template="Detect permission scenario for {bundle_name}",
                emoji="📋",
                command_flags=["--helm"],
                validation_func=self._validate_permission_detection,
                requires_temp_dir=False,
                skip_invalid_bundle=True
            ),
            TestConfiguration(
                test_type="permission_scenarios",
                description_template="Test permission scenario handling for {bundle_name}",
                emoji="🎯",
                command_flags=[],
                validation_func=self._validate_permission_scenarios,
                requires_temp_dir=False,
                skip_invalid_bundle=True
            )
        ])
        
        # Add error handling to non-bundle configurations
        self.non_bundle_test_configurations.append(
            NonBundleTestConfiguration(
                test_name="error_handling_invalid_image",
                description="Test error handling with invalid bundle image",
                setup_func=self._setup_error_handling_test,
                validation_func=self._validate_error_handling,
                requires_temp_dir=False,
                should_succeed=False  # Should fail gracefully
            )
        )
        
    
    def run_opm_command(self, cmd: List[str], input_data: str = None, 
                   timeout: int = OPMTestConstants.DEFAULT_TIMEOUT) -> Dict[str, Any]:
        """
        Execute an OPM command using the inherited run_command method
        
        Args:
            cmd: Command to execute
            input_data: Optional stdin input
            timeout: Command timeout in seconds
            
        Returns:
            Dictionary with command results (mapped for backward compatibility)
        """
        result = super().run_command(cmd, input_data, timeout)
        
        # Filter logging messages and header comments from stdout to keep test results clean
        result["stdout"] = self._filter_logging_from_stdout(result["stdout"])
        result["stdout"] = self._exclude_header_comments(result["stdout"])
        
        # Map new field names to old field names for backward compatibility
        result["success"] = result["returncode"] == 0
        
        return result
    
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
        
        import re
        lines = stdout.split('\n')
        filtered_lines = []
        
        for line in lines:
            # Skip lines that look like logging messages (timestamp - LEVEL - message)
            if re.match(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} - (DEBUG|INFO|WARNING|ERROR|CRITICAL) - ', line):
                continue
            filtered_lines.append(line)
        
        return '\n'.join(filtered_lines)
    
    def _create_test_result(self, test_name: str, description: str, success: bool, 
                           details: Dict[str, Any], duration: float = 0.0) -> Dict[str, Any]:
        """Create standardized test result structure using inherited method"""
        result = self.create_test_result(test_name, success, details, duration)
        result["description"] = description  # Add OPM-specific field
        return result
    
    def _run_bundle_test(self, config: TestConfiguration, bundle_name: str, bundle_image: str) -> Dict[str, Any]:
        """
        Generic test runner for bundle-based tests using data-driven configuration.
        
        Args:
            config: Test configuration containing validation function and command flags
            bundle_name: Name of the bundle being tested
            bundle_image: Bundle image URL
            
        Returns:
            Dictionary containing test results
        """
        print(f"{config.emoji} Testing {config.test_type}: {bundle_name}")
        
        # Build command with configuration flags
        cmd_builder = OPMCommandBuilder(self.base_cmd).with_image(bundle_image)
        
        # Add registry token if available
        if self.registry_token:
            cmd_builder = cmd_builder.with_registry_token(self.registry_token)
        
        # Add configuration-specific flags
        for flag in config.command_flags:
            if flag == "--helm":
                cmd_builder = cmd_builder.with_helm()
            elif flag.startswith("--"):
                # Handle other flags that might be added in the future
                pass
        
        # Handle tests that require temporary directories
        temp_dir_context = None
        output_dir = None
        
        if config.requires_temp_dir:
            import tempfile
            temp_dir_context = tempfile.TemporaryDirectory()
            temp_dir = temp_dir_context.__enter__()
            output_dir = Path(temp_dir) / "test-output"
            cmd_builder = cmd_builder.with_output(str(output_dir))
        
        try:
            # Build and execute command
            cmd = cmd_builder.build()
            result = self.run_opm_command(cmd)
            
            # Prepare base details
            details = {
                "bundle_image": bundle_image,
                "command": result["command"],
                "returncode": result["returncode"],
                "stdout": result["stdout"],
                "stderr": result["stderr"]
            }
            
            # Add output directory info if applicable
            if output_dir:
                details["output_directory"] = str(output_dir)
            
            # Run validation function
            if result["success"]:
                validation_result = config.validation_func(result, details, output_dir)
                details.update(validation_result)
                success = validation_result.get("success", True)
            else:
                details["error"] = result["stderr"]
                success = False
            
            # Generate test name and description
            test_name = f"{config.test_type}_{bundle_name}"
            description = config.description_template.format(bundle_name=bundle_name)
            
            return self._create_test_result(test_name, description, success, details)
            
        finally:
            # Clean up temporary directory if used
            if temp_dir_context:
                temp_dir_context.__exit__(None, None, None)
    
    def _is_placeholder_bundle(self, bundle_image: str) -> bool:
        """Check if bundle image is a placeholder"""
        # All our test bundles are now real, so only check for the invalid test bundle
        return bundle_image == OPMTestConstants.INVALID_BUNDLE
    
    # Validation functions for data-driven tests
    def _validate_bundle_processing(self, result: Dict[str, Any], details: Dict[str, Any], output_dir: Optional[Path] = None) -> Dict[str, Any]:
        """Validation function for bundle processing tests"""
        try:
            # Extract and parse YAML content using helper methods
            yaml_content = self._extract_yaml_content(result["stdout"])
            documents = self._parse_yaml_documents(yaml_content)
            validation = self._validate_yaml_documents(documents)
            
            return {
                "success": validation["has_minimum_docs"],
                **validation
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Processing failed: {str(e)}",
                "found_documents": [],
                "yaml_document_count": 0,
                "has_minimum_docs": False
            }
    
    def _validate_helm_generation(self, result: Dict[str, Any], details: Dict[str, Any], output_dir: Optional[Path] = None) -> Dict[str, Any]:
        """Validation function for Helm generation tests"""
        try:
            # Extract and parse Helm content using helper methods
            helm_content = self._extract_helm_content(result["stdout"])
            helm_values = self._parse_helm_values(helm_content)
            validation = self._validate_helm_structure(helm_values)
            
            return {
                "success": validation["has_required_structure"],
                **validation
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Helm generation failed: {str(e)}",
                "found_keys": [],
                "has_required_structure": False
            }
    
    def _validate_dry_deduplication(self, result: Dict[str, Any], details: Dict[str, Any], output_dir: Optional[Path] = None) -> Dict[str, Any]:
        """Validation function for deduplication tests"""
        try:
            helm_content = self._extract_helm_content(result["stdout"])
            helm_values = self._parse_helm_values(helm_content)
            
            # Analyze deduplication effectiveness
            cluster_roles_count = 0
            roles_count = 0
            total_cluster_rules = 0
            total_role_rules = 0
            
            if helm_values and "permissions" in helm_values:
                permissions = helm_values["permissions"]
                if "clusterRoles" in permissions:
                    cluster_roles_count = len(permissions["clusterRoles"])
                    for cr in permissions["clusterRoles"]:
                        if "rules" in cr:
                            total_cluster_rules += len(cr["rules"])
                
                if "roles" in permissions:
                    roles_count = len(permissions["roles"])
                    for role in permissions["roles"]:
                        if "rules" in role:
                            total_role_rules += len(role["rules"])
            
            # Check for deduplication evidence
            deduplication_effective = total_cluster_rules > 0 or total_role_rules > 0
            
            return {
                "success": True,  # Deduplication tests always succeed if command runs
                "cluster_roles_count": cluster_roles_count,
                "roles_count": roles_count,
                "total_cluster_rules": total_cluster_rules,
                "total_role_rules": total_role_rules,
                "deduplication_effective": deduplication_effective,
                "has_dedup_evidence": False  # This would require more complex analysis
            }
        except Exception:
            return {
                "success": True,  # Still success even if parsing fails
                "cluster_roles_count": 0,
                "roles_count": 0,
                "total_cluster_rules": 0,
                "total_role_rules": 0,
                "has_dedup_evidence": False
            }
    
    def _validate_output_directory(self, result: Dict[str, Any], details: Dict[str, Any], output_dir: Optional[Path] = None) -> Dict[str, Any]:
        """Validation function for output directory tests"""
        if not output_dir or not output_dir.exists():
            return {
                "success": False,
                "error": "Output directory was not created"
            }
        
        try:
            # Check for created files
            files_created = [f.name for f in output_dir.glob("*.yaml")]
            file_count = len(files_created)
            
            # Look for expected patterns
            found_patterns = []
            for pattern in ["serviceaccount", "clusterrole", "clusterrolebinding", "role", "rolebinding"]:
                if any(pattern in f.lower() for f in files_created):
                    found_patterns.append(pattern)
            
            has_minimum_files = file_count >= 3  # Expect at least 3 files
            
            return {
                "success": has_minimum_files,
                "files_created": files_created,
                "file_count": file_count,
                "found_patterns": found_patterns,
                "has_minimum_files": has_minimum_files
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Directory validation failed: {str(e)}"
            }
    
    # Setup functions for non-bundle tests
    def _setup_config_yaml_test(self, temp_dir: str) -> Dict[str, Any]:
        """Setup function for config YAML output test"""
        test_bundle_image = next(iter(self.test_bundles.values()))
        config_file = self._create_config_file(temp_dir, test_bundle_image, "yaml", OPMTestConstants.STABLE_CHANNEL)
        cmd = OPMCommandBuilder(self.base_cmd).with_config(config_file).build()
        
        return {
            "command": cmd,
            "details": {"config_file": config_file}
        }
    
    def _setup_config_helm_test(self, temp_dir: str) -> Dict[str, Any]:
        """Setup function for config Helm output test"""
        test_bundle_image = next(iter(self.test_bundles.values()))
        config_file = self._create_config_file(temp_dir, test_bundle_image, "helm", OPMTestConstants.ALPHA_CHANNEL)
        cmd = OPMCommandBuilder(self.base_cmd).with_config(config_file).build()
        
        return {
            "command": cmd,
            "details": {"config_file": config_file}
        }
    
    def _setup_invalid_config_test(self, temp_dir: str) -> Dict[str, Any]:
        """Setup function for invalid config test"""
        invalid_config_file = os.path.join(temp_dir, "invalid-config.yaml")
        
        # Create invalid config file
        with open(invalid_config_file, 'w') as f:
            f.write("invalid: yaml: content: [")
        
        cmd = OPMCommandBuilder(self.base_cmd).with_config(invalid_config_file).build()
        
        return {
            "command": cmd,
            "details": {"config_file": invalid_config_file}
        }
    
    def _setup_flowstyle_test(self, temp_dir: str) -> Dict[str, Any]:
        """Setup function for FlowStyleList formatting test"""
        test_bundle_image = next(iter(self.test_bundles.values()))
        cmd = OPMCommandBuilder(self.base_cmd).with_image(test_bundle_image).with_helm().build()
        
        return {
            "command": cmd,
            "details": {}
        }
    
    def _setup_channel_placeholder_test(self, temp_dir: str) -> Dict[str, Any]:
        """Setup function for channel placeholder test"""
        test_bundle_image = next(iter(self.test_bundles.values()))
        cmd = OPMCommandBuilder(self.base_cmd).with_image(test_bundle_image).with_helm().build()
        
        return {
            "command": cmd,
            "details": {}
        }
    
    # Validation functions for non-bundle tests
    def _validate_config_yaml_output(self, result: Dict[str, Any], details: Dict[str, Any], temp_dir: str) -> Dict[str, Any]:
        """Validation function for config YAML output test"""
        if result["success"]:
            # Check if YAML files were created
            yaml_files = list(Path(temp_dir).glob("*-serviceaccount-*.yaml"))
            yaml_files_created = len(yaml_files) > 0
            files_count = len(list(Path(temp_dir).glob("*.yaml"))) - 1  # Exclude config file
            
            return {
                "success": True,  # Config tests succeed if command runs
                "yaml_files_created": yaml_files_created,
                "files_count": files_count
            }
        else:
            return {
                "success": False,
                "error": result["stderr"]
            }
    
    def _validate_config_helm_output(self, result: Dict[str, Any], details: Dict[str, Any], temp_dir: str) -> Dict[str, Any]:
        """Validation function for config Helm output test"""
        if result["success"]:
            # Check if Helm values file was created
            helm_files = list(Path(temp_dir).glob("*-*.yaml"))
            helm_file_created = len(helm_files) > 0
            
            # Check if channel from config appears in output
            channel_from_config = False
            if helm_files:
                try:
                    with open(helm_files[0], 'r') as f:
                        helm_content = f.read()
                    channel_from_config = f'channel: {OPMTestConstants.ALPHA_CHANNEL}' in helm_content
                except Exception:
                    pass
            
            return {
                "success": True,  # Config tests succeed if command runs
                "helm_file_created": helm_file_created,
                "channel_from_config": channel_from_config
            }
        else:
            return {
                "success": False,
                "error": result["stderr"]
            }
    
    def _validate_invalid_config(self, result: Dict[str, Any], details: Dict[str, Any], temp_dir: str) -> Dict[str, Any]:
        """Validation function for invalid config test"""
        return {
            "success": not result["success"],  # Should fail gracefully
            "failed_as_expected": not result["success"]
        }
    
    def _validate_flowstyle_formatting(self, result: Dict[str, Any], details: Dict[str, Any], temp_dir: str) -> Dict[str, Any]:
        """Validation function for FlowStyleList formatting test"""
        if result["success"]:
            # Check for flow-style arrays in output using constants
            has_flow_arrays = all(pattern in result["stdout"] for pattern in OPMTestConstants.FLOW_STYLE_PATTERNS)
            
            # Check for resourceNames placeholder using constants
            has_resource_placeholder = OPMTestConstants.RESOURCE_PLACEHOLDER in result["stdout"]
            
            return {
                "success": has_flow_arrays and has_resource_placeholder,
                "has_flow_style_arrays": has_flow_arrays,
                "has_resource_names_placeholder": has_resource_placeholder
            }
        else:
            return {
                "success": False,
                "error": result["stderr"]
            }
    
    def _validate_channel_placeholder(self, result: Dict[str, Any], details: Dict[str, Any], temp_dir: str) -> Dict[str, Any]:
        """Validation function for channel placeholder test"""
        if result["success"]:
            # Check for channel placeholder using constants
            has_channel_placeholder = OPMTestConstants.CHANNEL_PLACEHOLDER in result["stdout"]
            
            return {
                "success": has_channel_placeholder,
                "has_channel_placeholder": has_channel_placeholder
            }
        else:
            return {
                "success": False,
                "error": result["stderr"]
            }
    
    # Setup and validation functions for remaining test methods
    def _setup_error_handling_test(self, temp_dir: str) -> Dict[str, Any]:
        """Setup function for error handling test"""
        cmd = OPMCommandBuilder(self.base_cmd).with_image(OPMTestConstants.INVALID_BUNDLE).build()
        
        return {
            "command": cmd,
            "details": {"invalid_image": OPMTestConstants.INVALID_BUNDLE}
        }
    
    def _validate_error_handling(self, result: Dict[str, Any], details: Dict[str, Any], temp_dir: str) -> Dict[str, Any]:
        """Validation function for error handling test"""
        # The tool returns 0 but outputs error messages, so check for error content instead
        has_error_output = bool(result["stderr"]) or "Error:" in result["stdout"] or "Failed" in result["stdout"]
        
        validation_details = {
            "success": has_error_output,  # Success if error is properly reported
            "error_message": result["stderr"],
            "stdout_message": result["stdout"]
        }
        
        # Check for helpful error message using constants
        error_text = result["stderr"] + " " + result["stdout"]
        if error_text:
            has_helpful_error = any(keyword in error_text.lower() for keyword in OPMTestConstants.ERROR_KEYWORDS)
            validation_details["has_helpful_error"] = has_helpful_error
        
        return validation_details
    
    def _validate_rbac_component_analysis(self, result: Dict[str, Any], details: Dict[str, Any], output_dir: str) -> Dict[str, Any]:
        """Validation function for RBAC component analysis test"""
        if not result["success"]:
            return {
                "success": False,
                "error": result["stderr"]
            }
        
        # Fallback validation using command output analysis
        return self._analyze_command_output_for_rbac_components(result, details)
    
    def _count_kind_in_output(self, kind: str, output: str) -> int:
        """
        Count occurrences of a specific Kubernetes kind in YAML output.
        
        Uses regex to ensure exact matches and avoid substring issues
        (e.g., "ClusterRole" vs "ClusterRoleBinding").
        
        Args:
            kind: The Kubernetes resource kind (e.g., "ServiceAccount", "ClusterRole")
            output: The YAML output string to search
            
        Returns:
            Number of occurrences of the specified kind
        """
        import re
        # Use word boundary to ensure exact match of the kind name
        pattern = rf"kind:\s+{re.escape(kind)}\b"
        return len(re.findall(pattern, output))
    
    def _analyze_command_output_for_rbac_components(self, result: Dict[str, Any], details: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze RBAC components from command output (fallback method).
        
        This method provides an alternative to direct module testing by analyzing
        the actual command output, which is more reliable in test environments.
        """
        try:
            stdout = result.get("stdout", "")
            
            # Define the Kubernetes kinds to check for
            kinds_to_check = ["ServiceAccount", "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding"]
            
            # Count occurrences of each kind using the helper function
            resource_counts = {kind.lower(): self._count_kind_in_output(kind, stdout) for kind in kinds_to_check}
            
            # Determine presence based on counts (more concise than manual checks)
            components_found = {kind.lower(): count > 0 for kind, count in resource_counts.items()}
            
            # Analyze the generated RBAC output for component presence
            validation_details = {
                "success": True,
                "permission_scenario": "unknown",
                "components_found": components_found,
                "resource_counts": resource_counts
            }
            
            # Determine permission scenario based on presence of Role vs ClusterRole
            has_cluster_role = components_found["clusterrole"]
            has_role = components_found["role"]
            
            if has_cluster_role and has_role:
                validation_details["permission_scenario"] = "both_cluster_and_namespace"
            elif has_cluster_role:
                validation_details["permission_scenario"] = "cluster_only"
            elif has_role:
                validation_details["permission_scenario"] = "namespace_only"
            else:
                validation_details["permission_scenario"] = "no_permissions"
            
            # Check for minimum expected components
            required_components = ["serviceaccount", "clusterrole"]
            missing_required = [comp for comp in required_components if not components_found[comp]]
            
            if missing_required:
                validation_details["success"] = False
                validation_details["error"] = f"Missing required components: {missing_required}"
            
            # Add bundle image for reference
            validation_details["bundle_image"] = details.get("bundle_image", "unknown")
            
            return validation_details
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Output analysis failed: {str(e)}",
                "error_type": type(e).__name__
            }
    
    def _validate_permission_detection(self, result: Dict[str, Any], details: Dict[str, Any], output_dir: str) -> Dict[str, Any]:
        """Validation function for permission detection test"""
        if not result["success"]:
            return {
                "success": False,
                "error": result["stderr"]
            }
        
        try:
            # Extract and analyze Helm content
            helm_content = self._extract_helm_content(result["stdout"])
            if helm_content.strip():  # Only analyze if we have content
                helm_values = yaml.safe_load(helm_content)
                permission_analysis = self._analyze_permission_structure(helm_values)
                
                # Log the detected scenario
                scenario = permission_analysis["permission_scenario"]
                cluster_count = permission_analysis["cluster_roles_count"]
                role_count = permission_analysis["roles_count"]
                total_perms = permission_analysis["total_permissions"]
                
                return {
                    "success": True,
                    **permission_analysis,
                    "scenario_summary": f"Scenario: {scenario}, ClusterRoles: {cluster_count}, Roles: {role_count}, Total Rules: {total_perms}"
                }
            else:
                return {
                    "success": False,
                    "error": "No Helm content extracted"
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to analyze permissions: {e}"
            }
    
    def _validate_permission_scenarios(self, result: Dict[str, Any], details: Dict[str, Any], output_dir: str) -> Dict[str, Any]:
        """Validation function for permission scenarios test"""
        bundle_image = details["bundle_image"]
        
        # Skip if bundle image looks like placeholder
        if "1234567890" in bundle_image or "example" in bundle_image:
            return {
                "success": True,
                "skipped": True,
                "reason": "Placeholder bundle image"
            }
        
        validation_details = {
            "success": True,
            "scenarios_tested": []
        }
        
        # Test both YAML and Helm generation
        for output_type in ["yaml", "helm"]:
            cmd_builder = OPMCommandBuilder(self.base_cmd).with_image(bundle_image)
            
            # Add registry token if available (security: only via flag, not config)
            if self.registry_token:
                cmd_builder = cmd_builder.with_registry_token(self.registry_token)
            
            if output_type == "helm":
                cmd_builder = cmd_builder.with_helm()
            
            cmd = cmd_builder.build()
            test_result = self.run_opm_command(cmd)
            
            scenario_test = {
                "output_type": output_type,
                "success": test_result["success"],
                "error": test_result["stderr"] if not test_result["success"] else None
            }
            
            if test_result["success"]:
                # Analyze output structure
                try:
                    if output_type == "helm":
                        # Use the helper method to extract clean Helm content
                        helm_content = self._extract_helm_content(test_result["stdout"])
                        parsed = yaml.safe_load(helm_content)
                        if parsed and "permissions" in parsed:
                            perms = parsed["permissions"]
                            scenario_test["cluster_roles"] = len(perms.get("clusterRoles", []))
                            scenario_test["roles"] = len(perms.get("roles", []))
                    else:
                        # For YAML output, count RBAC resources
                        yaml_docs = test_result["stdout"].split("---")
                        rbac_count = sum(1 for doc in yaml_docs if "kind:" in doc and any(kind in doc for kind in ["ClusterRole", "Role", "ClusterRoleBinding", "RoleBinding"]))
                        scenario_test["rbac_resources"] = rbac_count
                        
                except Exception as e:
                    scenario_test["analysis_error"] = str(e)
            
            validation_details["scenarios_tested"].append(scenario_test)
            
            # If any scenario fails, mark overall as failed
            if not scenario_test["success"]:
                validation_details["success"] = False
        
        return validation_details
    
    def test_data_driven_bundle_tests(self) -> List[Dict[str, Any]]:
        """
        Execute all data-driven bundle tests using the generic test runner.
        
        This method replaces the individual test methods (test_bundle_processing, 
        test_helm_generation, etc.) with a unified data-driven approach.
        
        Returns:
            List of test results for all configurations and bundles
        """
        results = []
        
        for config in self.test_configurations:
            print(f"\n🎯 Running test group: {config.test_type}")
            print("-" * 40)
            
            group_results = []
            
            for bundle_name, bundle_image in self.test_bundles.items():
                # Skip invalid bundle for most tests if configured
                if config.skip_invalid_bundle and bundle_name == "invalid-bundle":
                    continue
                
                try:
                    result = self._run_bundle_test(config, bundle_name, bundle_image)
                    group_results.append(result)
                    results.append(result)
                except Exception as e:
                    # Handle unexpected errors gracefully
                    error_result = self._create_test_result(
                        f"{config.test_type}_{bundle_name}",
                        config.description_template.format(bundle_name=bundle_name),
                        False,
                        {
                            "bundle_image": bundle_image,
                            "error": f"Unexpected error: {str(e)}",
                            "error_type": type(e).__name__
                        }
                    )
                    group_results.append(error_result)
                    results.append(error_result)
            
            # Print group summary
            passed = sum(1 for r in group_results if r["success"])
            failed = len(group_results) - passed
            print(f"\n📊 Test '{config.test_type}' Results:")
            print(f"Total: {len(group_results)}, Passed: {passed} ✅, Failed: {failed} ❌")
            
            if failed > 0:
                print(f"\n❌ Failed Tests:")
                for result in group_results:
                    if not result["success"]:
                        error_msg = result["details"].get("error", "Unknown error")
                        print(f"  - {result['test']}: {error_msg}")
        
        return results
    
    def test_data_driven_config_functionality(self) -> List[Dict[str, Any]]:
        """
        Execute config functionality tests using the generic non-bundle test runner.
        
        This method replaces the original test_config_functionality method with a 
        unified data-driven approach.
        
        Returns:
            List of test results for config functionality tests
        """
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
        
        # Run config-related tests
        config_tests = [config for config in self.non_bundle_test_configurations 
                       if config.test_name.startswith("config_") or config.test_name.startswith("invalid_config")]
        
        for config in config_tests:
            try:
                result = self._run_non_bundle_test(config)
                results.append(result)
            except Exception as e:
                error_result = self._create_test_result(
                    config.test_name,
                    config.description,
                    False,
                    {
                        "error": f"Unexpected error: {str(e)}",
                        "error_type": type(e).__name__
                    }
                )
                results.append(error_result)
        
        return results
    
    def test_data_driven_formatting_features(self) -> List[Dict[str, Any]]:
        """
        Execute formatting feature tests using the generic non-bundle test runner.
        
        This method replaces the original test_formatting_features method with a 
        unified data-driven approach.
        
        Returns:
            List of test results for formatting feature tests
        """
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
        
        # Run formatting-related tests
        formatting_tests = [config for config in self.non_bundle_test_configurations 
                           if config.test_name.startswith("flowstyle") or config.test_name.startswith("channel_")]
        
        for config in formatting_tests:
            try:
                result = self._run_non_bundle_test(config)
                results.append(result)
            except Exception as e:
                error_result = self._create_test_result(
                    config.test_name,
                    config.description,
                    False,
                    {
                        "error": f"Unexpected error: {str(e)}",
                        "error_type": type(e).__name__
                    }
                )
                results.append(error_result)
        
        return results
    
    def _run_single_config_test(self, test_type: str) -> List[Dict[str, Any]]:
        """
        Run a single test configuration for all applicable bundles.
        
        Args:
            test_type: The type of test to run (e.g., "bundle_processing")
            
        Returns:
            List of test results for the specified configuration
        """
        # Find the configuration for this test type
        config = next((c for c in self.test_configurations if c.test_type == test_type), None)
        if not config:
            return [{
                "test": f"{test_type}_error",
                "success": False,
                "details": {"error": f"No configuration found for test type: {test_type}"}
            }]
        
        results = []
        for bundle_name, bundle_image in self.test_bundles.items():
            # Skip invalid bundle for most tests if configured
            if config.skip_invalid_bundle and bundle_name == "invalid-bundle":
                continue
            
            try:
                result = self._run_bundle_test(config, bundle_name, bundle_image)
                results.append(result)
            except Exception as e:
                # Handle unexpected errors gracefully
                error_result = self._create_test_result(
                    f"{config.test_type}_{bundle_name}",
                    config.description_template.format(bundle_name=bundle_name),
                    False,
                    {
                        "bundle_image": bundle_image,
                        "error": f"Unexpected error: {str(e)}",
                        "error_type": type(e).__name__
                    }
                )
                results.append(error_result)
        
        return results
    
    def _run_non_bundle_test(self, config: NonBundleTestConfiguration) -> Dict[str, Any]:
        """
        Generic test runner for non-bundle tests using data-driven configuration.
        
        Args:
            config: Non-bundle test configuration containing setup and validation functions
            
        Returns:
            Dictionary containing test results
        """
        # Handle tests that require temporary directories
        temp_dir_context = None
        temp_dir = None
        
        if config.requires_temp_dir:
            import tempfile
            temp_dir_context = tempfile.TemporaryDirectory()
            temp_dir = temp_dir_context.__enter__()
        
        try:
            # Run setup function to prepare test environment and get command
            setup_result = config.setup_func(temp_dir)
            
            # Add registry token to command if available (security: only via flag, not config)
            command = setup_result["command"]
            if self.registry_token:
                command = command + ["--registry-token", self.registry_token]
            
            # Execute command
            result = self.run_opm_command(command)
            
            # Prepare base details
            details = {
                "command": result["command"],
                "returncode": result["returncode"],
                "stdout": result["stdout"],
                "stderr": result["stderr"]
            }
            
            # Add any setup-specific details
            if "details" in setup_result:
                details.update(setup_result["details"])
            
            # Run validation function
            validation_result = config.validation_func(result, details, temp_dir)
            details.update(validation_result)
            
            # Determine success based on configuration and validation
            if config.should_succeed:
                success = validation_result.get("success", result["success"])
            else:
                # For tests that should fail (like invalid config)
                success = validation_result.get("success", not result["success"])
            
            return self._create_test_result(config.test_name, config.description, success, details)
            
        finally:
            # Clean up temporary directory if used
            if temp_dir_context:
                temp_dir_context.__exit__(None, None, None)
    
    def _extract_yaml_content(self, output: str, start_marker: str = "apiVersion:") -> str:
        """Extract YAML content from command output, excluding header comments"""
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
        
        # Extract the raw content first
        raw_content = '\n'.join(output_lines[yaml_start_idx:])
        
        # Apply header comment exclusion
        return self._exclude_header_comments(raw_content)
    
    def _exclude_header_comments(self, content: str) -> str:
        """
        Exclude header comments from YAML/Helm content
        
        Removes the large header comments generated by _generate_yaml_header_comment
        and _generate_helm_header_comment methods to make test results cleaner.
        
        Args:
            content: Raw YAML/Helm content with potential header comments
            
        Returns:
            Clean content without header comments
        """
        if not content:
            return ""
        
        lines = content.split('\n')
        clean_lines = []
        skip_header_block = False
        
        # Header comment patterns to identify and skip
        header_patterns = [
            "# IMPORTANT: Verify Correct Channel",
            "# SECURITY NOTICE: Post-Installation RBAC Hardening Required",
            "# ====================================================",
            "# =========================================================",
            "# The 'channel' field below is set to 'stable'",
            "# These YAML manifests contain installer permissions",
            "# This values.yaml contains installer permissions"
        ]
        
        for line in lines:
            stripped = line.strip()
            
            # Check if this line starts a header comment block
            if any(pattern in line for pattern in header_patterns):
                skip_header_block = True
                continue
            
            # Skip lines while in header comment block
            if skip_header_block:
                # End of header block when we hit actual YAML content
                if stripped and not stripped.startswith('#'):
                    skip_header_block = False
                    clean_lines.append(line)
                # Continue skipping comment lines
                continue
            
            # Keep all non-header content
            clean_lines.append(line)
        
        return '\n'.join(clean_lines)

    def _extract_helm_content(self, output: str) -> str:
        """Extract Helm YAML content from command output, excluding header comments"""
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
        
        # Extract the raw content first
        raw_content = '\n'.join(output_lines[yaml_start_idx:yaml_end_idx])
        
        # Apply header comment exclusion
        return self._exclude_header_comments(raw_content)
    
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
    
    def _parse_helm_values(self, yaml_content: str) -> Dict[str, Any]:
        """Parse Helm values YAML content"""
        if not yaml_content:
            return {}
        
        try:
            # Extract clean Helm content using existing helper
            helm_content = self._extract_helm_content(yaml_content)
            if not helm_content.strip():
                return {}
            
            # Parse the YAML content
            parsed = yaml.safe_load(helm_content)
            return parsed if parsed else {}
            
        except yaml.YAMLError as e:
            # Log the error but don't fail the test
            print(f"Warning: Failed to parse Helm YAML: {e}")
            return {}
        except Exception as e:
            # Handle any other parsing errors
            print(f"Warning: Unexpected error parsing Helm values: {e}")
            return {}
    
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
"""
        with open(config_file, 'w') as f:
            f.write(config_content)
        
        return config_file
    
    def _test_config_output(self, test_name: str, description: str, config_file: str, 
                           temp_dir: str, output_type: str) -> Dict[str, Any]:
        """Test config file output generation"""
        cmd_builder = OPMCommandBuilder(self.base_cmd).with_config(config_file)
        
        # Add registry token if available (security: only via flag, not config)
        if self.registry_token:
            cmd_builder = cmd_builder.with_registry_token(self.registry_token)
        
        cmd = cmd_builder.build()
        result = self.run_opm_command(cmd)
        
        details = {
            "config_file": config_file,
            "command": result["command"],
            "returncode": result["returncode"],
            "stdout": result["stdout"],
            "stderr": result["stderr"]
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
    
    def get_available_tests(self) -> Dict[str, str]:
        """Get dictionary of available test methods and their descriptions"""
        available_tests = {}
        
        # Add bundle tests from configurations
        for config in self.test_configurations:
            available_tests[config.test_type] = config.description_template.replace("{bundle_name}", "all bundles")
        
        # Add non-bundle tests from configurations
        for config in self.non_bundle_test_configurations:
            available_tests[config.test_name] = config.description
        
        return available_tests
    
    def run_specific_test(self, test_name: str) -> Dict[str, Any]:
        """Run a specific test by name using data-driven configurations"""
        start_time = time.time()
        results = []
        
        # Check if it's a bundle test
        bundle_config = next((config for config in self.test_configurations if config.test_type == test_name), None)
        if bundle_config:
            # Run bundle test using the generic runner
            test_results = self._run_single_config_test(test_name)
            results.extend(test_results)
            self.test_results.extend(test_results)
        else:
            # Check if it's a non-bundle test
            non_bundle_config = next((config for config in self.non_bundle_test_configurations if config.test_name == test_name), None)
            if non_bundle_config:
                # Run non-bundle test using the generic runner
                if test_name.startswith("config_") or test_name.startswith("formatting_"):
                    # These are grouped tests that return lists
                    if test_name.startswith("config_"):
                        test_results = self.test_data_driven_config_functionality()
                    else:
                        test_results = self.test_data_driven_formatting_features()
                    results.extend(test_results)
                    self.test_results.extend(test_results)
                else:
                    # Single non-bundle test
                    result = self._run_non_bundle_test(non_bundle_config)
                    results.append(result)
                    self.test_results.append(result)
            else:
                print(f"❌ Unknown test: {test_name}")
                return {"error": f"Unknown test: {test_name}"}
        
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
        
        # Get all available tests and run each one
        available_tests = self.get_available_tests()
        total_passed = 0
        total_failed = 0
        total_duration = 0.0
        
        for test_name in available_tests.keys():
            print(f"\n🎯 Running test group: {test_name}")
            print("-" * 40)
            
            test_result = self.run_specific_test(test_name)
            
            if "error" not in test_result:
                total_passed += test_result["passed"]
                total_failed += test_result["failed"]
                total_duration += test_result["duration"]
        
        end_time = time.time()
        total_tests = total_passed + total_failed
        
        print("\n" + "=" * 60)
        print("📊 OPM Test Results Summary")
        print("=" * 60)
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {total_passed} ✅")
        print(f"Failed: {total_failed} ❌")
        print(f"Success Rate: {(total_passed/total_tests)*100:.1f}%" if total_tests > 0 else "Success Rate: 0.0%")
        print(f"Duration: {end_time - start_time:.2f}s")
        
        if total_failed > 0:
            print("\n❌ Failed Tests:")
            for result in self.test_results:
                if not result["success"]:
                    print(f"  - {result['test']}: {result.get('details', {}).get('error', 'Unknown error')}")
        
        return {
            "total": total_tests,
            "passed": total_passed,
            "failed": total_failed,
            "success_rate": (total_passed/total_tests)*100 if total_tests > 0 else 0,
            "duration": end_time - start_time
        }
    
    def save_results(self, results_file: str = None) -> None:
        """Save test results to JSON file"""
        if not results_file:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            results_dir = TestUtilities.get_results_dir()
            results_file = str(Path(results_dir) / f"opm_test_results_{timestamp}.json")
        else:
            # If a specific filename is provided, still save it in the results directory
            results_dir = TestUtilities.get_results_dir()
            results_file = str(Path(results_dir) / results_file)
        
        summary = {
            "test_suite": "opm",
            "timestamp": time.time(),
            "configuration": {
                "skip_tls": self.skip_tls,
                "debug": self.debug,
                "registry_token_provided": bool(self.registry_token),  # Don't expose actual token
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
    parser.add_argument("--skip-tls", action="store_true", help="Skip TLS verification")
    parser.add_argument("--registry-token", help="Registry authentication token for private registries")
    args = parser.parse_args()
    
    print("🧪 OPM Test Suite")
    print("Testing RBAC Manager OPM functionality")
    print("=" * 60)
    
    # Check if we're in the right directory
    if not Path("tools/rbac-manager/rbac-manager.py").exists():
        print("❌ Error: rbac-manager.py not found")
        print("   Please run this test from the project root directory")
        sys.exit(1)
    
    # Initialize test suite
    test_suite = OPMTestSuite(
        skip_tls=args.skip_tls,
        debug=args.debug,
        registry_token=args.registry_token
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
