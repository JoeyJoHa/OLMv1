#!/usr/bin/env python3
"""
Test script for catalogd JSON parsing functionality
"""

import sys
from pathlib import Path

# Add the rbac-manager directory to the Python path
sys.path.insert(0, str(Path(__file__).parent / "rbac-manager"))

from libs import CatalogManager

def test_catalogd_parsing():
    """Test the catalogd JSON parsing with sample data"""
    
    # Sample data that mimics the /api/v1/all endpoint response
    sample_data = [
        {
            "schema": "olm.package",
            "name": "quay-operator",
            "defaultChannel": "stable-3.10"
        },
        {
            "schema": "olm.package", 
            "name": "postgres-operator",
            "defaultChannel": "stable"
        },
        {
            "schema": "olm.channel",
            "name": "stable-3.10",
            "package": "quay-operator"
        },
        {
            "schema": "olm.channel",
            "name": "stable",
            "package": "postgres-operator"
        },
        {
            "schema": "olm.bundle",
            "package": "quay-operator",
            "properties": [
                {
                    "type": "olm.channel",
                    "value": {
                        "channelName": "stable-3.10",
                        "version": "3.10.13"
                    }
                }
            ]
        },
        {
            "schema": "olm.bundle",
            "package": "quay-operator", 
            "properties": [
                {
                    "type": "olm.channel",
                    "value": {
                        "channelName": "stable-3.10",
                        "version": "3.10.12"
                    }
                }
            ]
        }
    ]
    
    # Initialize catalog manager
    catalog_manager = CatalogManager()
    
    print("Testing catalogd JSON parsing...")
    print("=" * 40)
    
    # Test package parsing
    packages = catalog_manager._parse_catalog_data(sample_data, 'packages')
    print(f"Packages found: {packages}")
    assert "quay-operator" in packages
    assert "postgres-operator" in packages
    print("✓ Package parsing works")
    
    # Test channel parsing
    channels = catalog_manager._parse_catalog_data(sample_data, 'channels', 'quay-operator')
    print(f"Channels for quay-operator: {channels}")
    assert "stable-3.10" in channels
    print("✓ Channel parsing works")
    
    # Test version parsing
    versions = catalog_manager._parse_catalog_data(sample_data, 'versions', 'quay-operator', 'stable-3.10')
    print(f"Versions for quay-operator stable-3.10: {versions}")
    assert "3.10.13" in versions
    assert "3.10.12" in versions
    print("✓ Version parsing works")
    
    # Test metadata parsing
    metadata = catalog_manager._parse_catalog_data(sample_data, 'metadata', 'quay-operator', 'stable-3.10', '3.10.13')
    print(f"Metadata for quay-operator stable-3.10 3.10.13: {metadata}")
    assert metadata.get('package') == 'quay-operator'
    print("✓ Metadata parsing works")
    
    print("\n✅ All catalogd parsing tests passed!")

if __name__ == "__main__":
    test_catalogd_parsing()
