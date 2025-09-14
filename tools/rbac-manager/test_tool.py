#!/usr/bin/env python3
"""
Test script for OPM Metadata Tool

This script tests the basic functionality of the OPM metadata tool
without requiring actual cluster access or opm binary.
"""

import json
import tempfile
import yaml
from pathlib import Path
from opm_metadata_tool import OPMMetadataTool

def create_mock_bundle_metadata():
    """Create mock bundle metadata for testing"""
    return {
        'operator_name': 'test-operator',
        'operator_version': '1.0.0',
        'rbac_rules': [
            {
                'apiGroups': [''],
                'resources': ['pods', 'services', 'configmaps'],
                'verbs': ['get', 'list', 'watch', 'create', 'update', 'patch', 'delete']
            },
            {
                'apiGroups': ['apps'],
                'resources': ['deployments'],
                'verbs': ['get', 'list', 'watch', 'create', 'update', 'patch', 'delete']
            },
            {
                'apiGroups': ['test.example.com'],
                'resources': ['testresources'],
                'verbs': ['*']
            }
        ]
    }

def test_yaml_generation():
    """Test YAML manifest generation"""
    print("Testing YAML manifest generation...")
    
    tool = OPMMetadataTool()
    metadata = create_mock_bundle_metadata()
    
    # Generate YAML manifests
    manifests = tool.generate_yaml_manifests(metadata, "test-namespace", "test-operator")
    
    print(f"Generated {len(manifests)} YAML files:")
    for filename in manifests.keys():
        print(f"  - {filename}")
    
    # Validate ServiceAccount
    sa_yaml = yaml.safe_load(manifests['01-serviceaccount.yaml'])
    assert sa_yaml['kind'] == 'ServiceAccount'
    assert sa_yaml['metadata']['name'] == 'test-operator-installer'
    assert sa_yaml['metadata']['namespace'] == 'test-namespace'
    print("✓ ServiceAccount validation passed")
    
    # Validate ClusterRole
    cr_docs = list(yaml.safe_load_all(manifests['02-clusterrole.yaml']))
    assert len(cr_docs) == 2
    assert cr_docs[0]['kind'] == 'ClusterRole'
    assert cr_docs[1]['kind'] == 'ClusterRole'
    print("✓ ClusterRole validation passed")
    
    # Validate ClusterRoleBinding
    crb_docs = list(yaml.safe_load_all(manifests['03-clusterrolebinding.yaml']))
    assert len(crb_docs) == 2
    assert crb_docs[0]['kind'] == 'ClusterRoleBinding'
    assert crb_docs[1]['kind'] == 'ClusterRoleBinding'
    print("✓ ClusterRoleBinding validation passed")
    
    # Validate ClusterExtension
    ce_yaml = yaml.safe_load(manifests['04-clusterextension.yaml'])
    assert ce_yaml['kind'] == 'ClusterExtension'
    assert ce_yaml['metadata']['name'] == 'test-operator'
    assert ce_yaml['spec']['namespace'] == 'test-namespace'
    print("✓ ClusterExtension validation passed")

def test_helm_generation():
    """Test Helm values generation"""
    print("\nTesting Helm values generation...")
    
    tool = OPMMetadataTool()
    metadata = create_mock_bundle_metadata()
    
    # Generate Helm values
    helm_values = tool.generate_helm_values(metadata, "test-operator")
    
    print(f"Generated {len(helm_values)} Helm files:")
    for filename in helm_values.keys():
        print(f"  - {filename}")
    
    # Validate RBAC-only values
    rbac_values = yaml.safe_load(helm_values['rbac-only-example.yaml'])
    assert rbac_values['operator']['name'] == 'test-operator'
    assert rbac_values['operator']['create'] == False
    assert rbac_values['serviceAccount']['create'] == True
    assert len(rbac_values['permissions']['clusterRoles']) == 2
    print("✓ RBAC-only Helm values validation passed")
    
    # Validate operator values
    op_values = yaml.safe_load(helm_values['values-test-operator.yaml'])
    assert op_values['operator']['name'] == 'test-operator'
    assert op_values['operator']['create'] == True
    assert op_values['operator']['appVersion'] == '1.0.0'
    print("✓ Operator Helm values validation passed")

def test_file_output():
    """Test file output functionality"""
    print("\nTesting file output...")
    
    tool = OPMMetadataTool()
    metadata = create_mock_bundle_metadata()
    
    with tempfile.TemporaryDirectory() as temp_dir:
        output_dir = Path(temp_dir) / "generated-test-operator"
        output_dir.mkdir(exist_ok=True)
        
        yaml_dir = output_dir / "yaml"
        yaml_dir.mkdir(exist_ok=True)
        
        helm_dir = output_dir / "helm"
        helm_dir.mkdir(exist_ok=True)
        
        # Generate and write files
        yaml_manifests = tool.generate_yaml_manifests(metadata, "test-namespace", "test-operator")
        helm_values = tool.generate_helm_values(metadata, "test-operator")
        
        # Write YAML files
        for filename, content in yaml_manifests.items():
            file_path = yaml_dir / filename
            with open(file_path, 'w') as f:
                f.write(content)
        
        # Write Helm files
        for filename, content in helm_values.items():
            file_path = helm_dir / filename
            with open(file_path, 'w') as f:
                f.write(content)
        
        # Verify files exist
        yaml_files = list(yaml_dir.glob("*.yaml"))
        helm_files = list(helm_dir.glob("*.yaml"))
        
        assert len(yaml_files) == 4
        assert len(helm_files) == 2
        
        print(f"✓ Successfully wrote {len(yaml_files)} YAML files")
        print(f"✓ Successfully wrote {len(helm_files)} Helm files")

def main():
    """Run all tests"""
    print("OPM Metadata Tool - Test Suite")
    print("=" * 40)
    
    try:
        test_yaml_generation()
        test_helm_generation()
        test_file_output()
        
        print("\n" + "=" * 40)
        print("✅ All tests passed!")
        print("\nThe OPM Metadata Tool is working correctly.")
        print("You can now use it with real operator bundles.")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
