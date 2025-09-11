#!/usr/bin/env python3
"""
Unified RBAC Manager for OLM Operators.

Refactored version using proper layered architecture and Application class pattern.
This main script is now minimal, focusing only on application entry point.

Architecture layers:
- CLI Interface Layer: Argument parsing and CLI setup  
- Application Layer: Main application orchestration
- UI Layer: Interactive catalog selection
- Business Logic Layer: RBAC processing workflow
- Data Access Layer: API queries and authentication
"""

import sys
from libs.rbac_application import RBACManagerApplication


def main() -> int:
    """
    Application entry point.
    
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    app = RBACManagerApplication()
    return app.run()


if __name__ == "__main__":
    sys.exit(main())
