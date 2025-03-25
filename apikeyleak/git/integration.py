"""
Git integration for API Key Leak Detector.
"""
import os
import shutil
from typing import List
from datetime import datetime
from colorama import Fore, Style
from tqdm import tqdm

from apikeyleak.core.models import LeakFinding
from apikeyleak.core.scanner import scan_file, should_skip_file

def get_git_tracked_files(repo_path: str) -> List[str]:
    """Get list of tracked files in a git repository."""
    try:
        import git
        repo = git.Repo(repo_path)
        tracked_files = []
        
        for item in repo.index.entries:
            file_path = os.path.join(repo_path, item[0])
            if os.path.isfile(file_path):
                tracked_files.append(file_path)
                
        return tracked_files
    except Exception as e:
        print(f"{Fore.YELLOW}Warning: Could not get git tracked files: {str(e)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Falling back to regular directory scan{Style.RESET_ALL}")
        return []

def scan_git_history(repo_path: str, exclude_patterns: List[str], context_size: int, silent: bool = False) -> List[LeakFinding]:
    """Scan git commit history for API key leaks."""
    try:
        import git
        repo = git.Repo(repo_path)
        findings = []
        
        print(f"{Fore.CYAN}Scanning git commit history...{Style.RESET_ALL}")
        
        # Get all commits
        commits = list(repo.iter_commits())
        
        with tqdm(total=len(commits), desc="Scanning commits", disable=silent) as pbar:
            for commit in commits:
                # Get the diff of this commit
                if len(commit.parents) > 0:
                    diffs = commit.parents[0].diff(commit)
                else:
                    diffs = commit.diff(git.NULL_TREE)
                
                # Check each changed file
                for diff in diffs:
                    if diff.a_blob and diff.b_blob and hasattr(diff, 'b_path'):
                        file_path = diff.b_path
                        
                        if not should_skip_file(file_path, exclude_patterns):
                            # Get the content of the file in this commit
                            try:
                                content = diff.b_blob.data_stream.read().decode('utf-8', errors='ignore')
                                # Create a temporary file for scanning
                                temp_dir = os.path.join(repo_path, 'temp_scan')
                                os.makedirs(temp_dir, exist_ok=True)
                                temp_file = os.path.join(temp_dir, os.path.basename(file_path))
                                
                                try:
                                    with open(temp_file, 'w', encoding='utf-8') as f:
                                        f.write(content)
                                    
                                    # Scan the temp file
                                    file_findings = scan_file(temp_file, context_size)
                                    
                                    # Update file path to include commit info
                                    for finding in file_findings:
                                        finding.file_path = f"{file_path} (commit {commit.hexsha[:8]})"
                                    
                                    findings.extend(file_findings)
                                finally:
                                    # Clean up temp file
                                    if os.path.exists(temp_dir):
                                        shutil.rmtree(temp_dir)
                            except:
                                # Skip binary files or files with encoding issues
                                pass
                pbar.update(1)
        
        return findings
    except Exception as e:
        print(f"{Fore.YELLOW}Warning: Could not scan git history: {str(e)}{Style.RESET_ALL}")
        return []

def get_changed_files_since_last_scan(repo_path: str) -> List[str]:
    """Get list of files changed since last scan."""
    try:
        # Read timestamp of last scan from .lastkeyscan file
        last_scan_file = os.path.join(repo_path, '.lastkeyscan')
        last_scan_time = None
        
        if os.path.exists(last_scan_file):
            with open(last_scan_file, 'r') as f:
                last_scan_time = datetime.fromisoformat(f.read().strip())
        
        changed_files = []
        
        # If we have a last scan time, get files modified since then
        if last_scan_time:
            for root, _, files in os.walk(repo_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if os.path.isfile(file_path):
                        mod_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                        if mod_time > last_scan_time:
                            changed_files.append(file_path)
        
        # Write current timestamp for next incremental scan
        with open(last_scan_file, 'w') as f:
            f.write(datetime.now().isoformat())
            
        return changed_files if changed_files else []
    except Exception as e:
        print(f"{Fore.YELLOW}Warning: Could not get changed files: {str(e)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Falling back to regular directory scan{Style.RESET_ALL}")
        return []

def install_git_hook(repo_path: str, use_python_hook: bool = False) -> None:
    """Install git pre-commit hook to scan for API key leaks.
    
    Args:
        repo_path: Path to the git repository
        use_python_hook: If True, install the Python hook instead of bash
    """
    try:
        hook_path = os.path.join(repo_path, '.git', 'hooks', 'pre-commit')
        
        if use_python_hook:
            # Python hook
            # First create the Python hook script
            python_hook_path = os.path.join(repo_path, 'git_hook_script.py')
            
            if not os.path.exists(python_hook_path):
                print(f"{Fore.YELLOW}Python hook script not found at {python_hook_path}.{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Creating git_hook_script.py...{Style.RESET_ALL}")
                
                # Create the Python hook script if it doesn't exist
                script_content = '''#!/usr/bin/env python3
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
        return [f for f in result.stdout.strip().split("\\n") if f]
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
    main()'''

                with open(python_hook_path, 'w') as f:
                    f.write(script_content)
                
                # Make the script executable
                os.chmod(python_hook_path, 0o755)
            
            # Create the pre-commit hook that calls the Python script
            hook_content = f"""#!/bin/sh
# API Key Leak Detector pre-commit hook (Python version)
# This hook will call the Python script git_hook_script.py

# Get the directory of the current repository
REPO_DIR=$(git rev-parse --show-toplevel)

# Run the Python hook script
exec python3 "$REPO_DIR/git_hook_script.py"
"""
        else:
            # Bash hook
            hook_content = """#!/bin/sh
# API Key Leak Detector pre-commit hook
echo "🔍 Scanning for API key leaks before commit..."

# Get the directory of the current repository
REPO_DIR=$(git rev-parse --show-toplevel)

# Get list of staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED_FILES" ]; then
    echo "No files to scan. Commit proceeding."
    exit 0
fi

# Create a temporary directory for the scan
TEMP_DIR=$(mktemp -d)
TEMP_FILE="$TEMP_DIR/staged_files.txt"
echo "$STAGED_FILES" > "$TEMP_FILE"

# Copy each staged file to a temporary directory to scan its staged content
mkdir -p "$TEMP_DIR/to_scan"
EXIT_CODE=0

echo "Preparing files for scanning..."
while IFS= read -r file; do
    # Skip if file doesn't exist (e.g. deleted file)
    if [ ! -f "$file" ]; then
        continue
    fi
    
    # Create directory structure
    mkdir -p "$TEMP_DIR/to_scan/$(dirname "$file")"
    
    # Get staged content of the file
    git show ":$file" > "$TEMP_DIR/to_scan/$file"
done < "$TEMP_FILE"

echo "Scanning staged files for API key leaks..."
# Run the API key leak detector only on the staged versions of the files
python3 "$REPO_DIR/apikeyleektester.py" "$TEMP_DIR/to_scan" --format text

# Check if scan found any leaks
if [ $? -ne 0 ]; then
    echo "⛔ API key leaks detected! Commit aborted."
    echo "Please fix the leaks before committing."
    EXIT_CODE=1
else
    echo "✅ No API key leaks detected. Proceeding with commit."
fi

# Clean up temporary directory
rm -rf "$TEMP_DIR"
exit $EXIT_CODE
"""
        
        # Write hook script
        with open(hook_path, 'w') as f:
            f.write(hook_content)
            
        # Make hook executable
        os.chmod(hook_path, 0o755)
        
        hook_type = "Python" if use_python_hook else "Bash"
        print(f"{Fore.GREEN}{hook_type} git pre-commit hook installed successfully at {hook_path}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Your code will now be scanned for API key leaks before each commit{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error installing git hook: {str(e)}{Style.RESET_ALL}") 