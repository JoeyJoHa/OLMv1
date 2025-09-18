#!/usr/bin/env python3
"""
RBAC Manager Entry Point

This script provides a simple entry point for the RBAC Manager tool.
All application logic is contained in the libs.main_app module.
"""

import logging
import sys
from pathlib import Path

# Add the rbac-manager directory (package root) and libs to the Python path
rbac_manager_path = Path(__file__).parent / "rbac-manager"
libs_path = rbac_manager_path / "libs"
sys.path.insert(0, str(rbac_manager_path))
sys.path.insert(0, str(libs_path))

# Logging will be configured by main_app.main()

# Import and execute main application
if __name__ == "__main__":
    try:
        from libs.main_app import main
        main()
    except ImportError as e:
        print(f"Error importing main application: {e}")
        print(f"Please ensure you're running from the correct directory")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)