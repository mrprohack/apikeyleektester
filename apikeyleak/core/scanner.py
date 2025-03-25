"""
Core scanning functionality for API Key Leak Detector.
"""
import os
import re
import fnmatch
import concurrent.futures
from typing import List, Tuple
from tqdm import tqdm
from colorama import Fore, Style

from apikeyleak.core.models import LeakFinding
from apikeyleak.core.patterns import (
    API_PATTERNS, 
    DEFAULT_EXCLUDE_PATTERNS, 
    is_false_positive
)

def should_skip_file(file_path: str, exclude_patterns: List[str]) -> bool:
    """Determine if a file should be skipped based on exclude patterns."""
    for pattern in exclude_patterns:
        if fnmatch.fnmatch(file_path, pattern) or fnmatch.fnmatch(os.path.basename(file_path), pattern):
            return True
    return False

def get_context_lines(lines: List[str], line_num: int, context_size: int = 2) -> Tuple[List[str], List[str]]:
    """Get lines before and after the detection for context."""
    start = max(0, line_num - context_size - 1)
    end = min(len(lines), line_num + context_size)
    
    before = lines[start:line_num-1]
    after = lines[line_num:end]
    
    return before, after

def scan_file(file_path: str, context_size: int = 2) -> List[LeakFinding]:
    """Scan a file for potential API key leaks with improved detection."""
    findings = []

    try:
        with open(file_path, 'r', errors='ignore') as file:
            lines = file.readlines()
            for line_num, line in enumerate(lines, 1):
                for pattern_name, pattern in API_PATTERNS.items():
                    matches = re.findall(pattern, line)
                    for match in matches:
                        if isinstance(match, tuple):
                            leak_text = match[0]
                        else:
                            leak_text = match
                            
                        if is_false_positive(leak_text):
                            continue
                            
                        # Get context lines
                        before, after = get_context_lines(lines, line_num, context_size)
                        
                        findings.append(LeakFinding(
                            file_path=file_path,
                            line_num=line_num,
                            leak_text=leak_text,
                            pattern_name=pattern_name,
                            context_before=before,
                            context_after=after
                        ))
    except Exception as e:
        print(f"{Fore.YELLOW}Warning: Could not read file {file_path}: {str(e)}{Style.RESET_ALL}")
    
    return findings

def scan_directory(directory_path: str, 
                   exclude_patterns: List[str] = None, 
                   context_size: int = 2,
                   max_workers: int = None,
                   silent: bool = False) -> List[LeakFinding]:
    """Scan all files in a directory recursively with multi-threading support."""
    if exclude_patterns is None:
        exclude_patterns = DEFAULT_EXCLUDE_PATTERNS
        
    all_findings = []
    files_to_scan = []

    # First collect all files
    for root, dirs, files in os.walk(directory_path):
        # Filter directories
        dirs[:] = [d for d in dirs if not any(fnmatch.fnmatch(d, pattern) for pattern in exclude_patterns)]
        
        for file in files:
            file_path = os.path.join(root, file)
            if not should_skip_file(file_path, exclude_patterns):
                files_to_scan.append(file_path)
    
    # Scan files with a thread pool for better performance
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_file = {executor.submit(scan_file, file_path, context_size): file_path 
                          for file_path in files_to_scan}
        
        # Use tqdm for a progress bar
        with tqdm(total=len(files_to_scan), desc="Scanning files", disable=silent) as pbar:
            for future in concurrent.futures.as_completed(future_to_file):
                file_findings = future.result()
                if file_findings:
                    all_findings.extend(file_findings)
                pbar.update(1)
    
    return all_findings

def scan_specific_files(files_to_scan: List[str],
                        context_size: int = 2,
                        max_workers: int = None,
                        silent: bool = False) -> List[LeakFinding]:
    """Scan a specific list of files."""
    all_findings = []
    
    # Scan files with a thread pool for better performance
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_file = {executor.submit(scan_file, file_path, context_size): file_path 
                          for file_path in files_to_scan}
        
        # Use tqdm for a progress bar
        with tqdm(total=len(files_to_scan), desc="Scanning files", disable=silent) as pbar:
            for future in concurrent.futures.as_completed(future_to_file):
                file_findings = future.result()
                if file_findings:
                    all_findings.extend(file_findings)
                pbar.update(1)
    
    return all_findings 