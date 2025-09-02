#!/usr/bin/env python3
"""
Podman client script for container management.
"""

import os
import sys
import subprocess
from decouple import config, UndefinedValueError


def run_podman_command(cmd_args, input_data=None):
    """Run a podman command using subprocess."""
    try:
        cmd = ['podman'] + cmd_args
        result = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {' '.join(cmd)}")
        print(f"Error: {e.stderr.strip()}")
        raise


def main():
    """Main function to connect to Podman and login to registry."""
    try:
        # Get credentials from environment variables
        username = config('REGISTRY_USERNAME')
        password = config('REGISTRY_PASSWORD')  
        registry = config('REGISTRY_URL')
        
        print(f"Logging into registry: {registry}")
        
        # Login to registry using podman command
        login_result = run_podman_command([
            'login', 
            '--username', username,
            '--password-stdin',
            registry
        ], input_data=password)
        
        print("✅ Successfully logged into registry")
        
        # Example: List containers
        containers_output = run_podman_command(['ps', '-a'])
        print(f"\nContainers:")
        print(containers_output)
        
        # Example: List images  
        images_output = run_podman_command(['images'])
        print(f"\nImages:")
        print(images_output)
        
    except UndefinedValueError as e:
        print(f"Error: Missing environment variable - {e}")
        print("\nRequired environment variables:")
        print("  REGISTRY_USERNAME - Your registry username")
        print("  REGISTRY_PASSWORD - Your registry password")
        print("  REGISTRY_URL - Registry URL (e.g., quay.io)")
        sys.exit(1)
    except subprocess.CalledProcessError:
        print("❌ Podman command failed")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()