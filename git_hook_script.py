#!/usr/bin/env python3
"""
Git pre-commit hook for API Key Leak Detector
This script can be used as a git pre-commit hook to scan staged files for API key leaks.
"""

import os
import sys
import subprocess
import tempfile
import shutil
from pathlib import Path

def get_repo_root():
    """Get the root directory of the git repository."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        print("Error: Not a git repository or git command not found.")
        sys.exit(1)

def get_staged_files():
    """Get list of files staged for commit."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True,
            text=True,
            check=True
        )
        return [f for f in result.stdout.strip().split("\n") if f]
    except subprocess.CalledProcessError:
        print("Error: Could not get staged files.")
        sys.exit(1)

def prepare_files_for_scan(repo_root, staged_files, temp_dir):
    """Copy staged content of files to a temporary directory."""
    scan_dir = os.path.join(temp_dir, "to_scan")
    os.makedirs(scan_dir, exist_ok=True)
    
    print("Preparing files for scanning...")
    for file in staged_files:
        file_path = os.path.join(repo_root, file)
        
        # Skip files that don't exist (e.g., deleted files)
        if not os.path.exists(file_path):
            continue
            
        # Create directory structure in the temp directory
        temp_file_dir = os.path.dirname(os.path.join(scan_dir, file))
        os.makedirs(temp_file_dir, exist_ok=True)
        
        try:
            # Get staged content of the file
            result = subprocess.run(
                ["git", "show", f":{file}"],
                capture_output=True,
                check=True
            )
            
            # Write staged content to temp file
            with open(os.path.join(scan_dir, file), "wb") as f:
                f.write(result.stdout)
        except subprocess.CalledProcessError:
            print(f"Warning: Could not get staged content for {file}. Skipping.")
            continue
    
    return scan_dir

def scan_for_api_keys(repo_root, scan_dir):
    """Run the API key leak detector on the prepared files."""
    scanner_path = os.path.join(repo_root, "apikeyleektester.py")
    
    # Check if scanner exists
    if not os.path.exists(scanner_path):
        print(f"Error: API key leak detector not found at {scanner_path}")
        return False
    
    print("Scanning staged files for API key leaks...")
    try:
        result = subprocess.run(
            ["python3", scanner_path, scan_dir, "--format", "text"],
            capture_output=False,  # Show output directly
            check=True
        )
        return True  # No leaks found
    except subprocess.CalledProcessError:
        return False  # Leaks found or error occurred

def main():
    """Main function for pre-commit hook."""
    print("🔍 Scanning for API key leaks before commit...")
    
    # Get repository root
    repo_root = get_repo_root()
    
    # Get staged files
    staged_files = get_staged_files()
    if not staged_files:
        print("No files to scan. Commit proceeding.")
        sys.exit(0)
    
    # Create temporary directory
    temp_dir = tempfile.mkdtemp()
    try:
        # Prepare files for scanning
        scan_dir = prepare_files_for_scan(repo_root, staged_files, temp_dir)
        
        # Scan for API keys
        no_leaks_found = scan_for_api_keys(repo_root, scan_dir)
        
        if no_leaks_found:
            print("✅ No API key leaks detected. Proceeding with commit.")
            sys.exit(0)
        else:
            print("⛔ API key leaks detected! Commit aborted.")
            print("Please fix the leaks before committing.")
            sys.exit(1)
    finally:
        # Clean up temporary directory
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    main() 