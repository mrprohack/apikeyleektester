#!/usr/bin/env python3
"""
API Key Leak Detector - Main Entry Point

A powerful and flexible tool for detecting potential API key leaks in your codebase.
"""
import sys
import os
import argparse
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored terminal text
init()

# Import from our package modules
from apikeyleak.core.patterns import API_PATTERNS, DEFAULT_EXCLUDE_PATTERNS, load_custom_patterns
from apikeyleak.core.scanner import scan_file, scan_directory, should_skip_file
from apikeyleak.git.integration import (
    get_git_tracked_files, 
    scan_git_history, 
    get_changed_files_since_last_scan,
    install_git_hook
)
from apikeyleak.utils.config import load_config_file, get_gitignore_exclusions
from apikeyleak.utils.helpers import print_color_findings, suggest_remediation
from apikeyleak.output.exporters import (
    export_json, 
    export_csv, 
    export_text, 
    generate_html_report
)

def main():
    """Main function for API Key Leak Detector."""
    parser = argparse.ArgumentParser(
        description="Advanced scanner for potential API key leaks in code.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("path", help="Path to the file or directory to scan")
    parser.add_argument("-o", "--output", help="Path to save the scan results", default=None)
    parser.add_argument("--format", choices=["text", "json", "csv", "html"], default="text",
                       help="Output format for results")
    parser.add_argument("--exclude", nargs="+", default=None,
                       help="Patterns of files/directories to exclude")
    parser.add_argument("--context", type=int, default=2,
                       help="Number of context lines to show before and after findings")
    parser.add_argument("--workers", type=int, default=None,
                       help="Number of worker threads for parallel scanning")
    parser.add_argument("--custom-patterns", type=str, default=None,
                       help="Path to JSON file with custom regex patterns")
    parser.add_argument("--no-context", action="store_true",
                       help="Don't show context lines in the output")
    parser.add_argument("--config", type=str, default=None,
                       help="Path to configuration file (YAML or JSON)")
    parser.add_argument("--git-scan", action="store_true", 
                       help="Scan only git tracked files")
    parser.add_argument("--git-history", action="store_true",
                       help="Scan git commit history for leaks")
    parser.add_argument("--incremental", action="store_true",
                       help="Only scan files changed since last scan")
    parser.add_argument("--install-hook", action="store_true",
                       help="Install git pre-commit hook to scan for leaks before commits")
    parser.add_argument("--python-hook", action="store_true",
                       help="Use Python version of the git hook instead of bash (use with --install-hook)")
    parser.add_argument("--remediation", action="store_true",
                       help="Suggest remediation for detected leaks")
    parser.add_argument("--silent", action="store_true",
                       help="Suppress progress output, display only findings")
    parser.add_argument("--no-git-files", action="store_true",
                       help="Exclude all Git-related files from scanning (.git directory and its contents)")
    args = parser.parse_args()

    # Load config file if provided
    config = {}
    if args.config:
        config = load_config_file(args.config)
        
        # Override command-line arguments with config file values if present
        for key, value in config.items():
            if hasattr(args, key) and getattr(args, key) is None:
                setattr(args, key, value)

    # Load custom patterns if provided
    if args.custom_patterns:
        custom_patterns = load_custom_patterns(args.custom_patterns)
        API_PATTERNS.update(custom_patterns)

    exclude_patterns = DEFAULT_EXCLUDE_PATTERNS.copy()
    if args.exclude:
        exclude_patterns.extend(args.exclude)
        
    # Add gitignore exclusions if scanning a git repository
    if args.git_scan or args.git_history:
        gitignore_patterns = get_gitignore_exclusions(args.path)
        exclude_patterns.extend(gitignore_patterns)
        
    # Exclude all git files if requested
    if args.no_git_files:
        exclude_patterns.append('.git/**')
        exclude_patterns.append('.git*')
        
    # Install git pre-commit hook if requested
    if args.install_hook:
        install_git_hook(args.path, use_python_hook=args.python_hook)
        return

    program_name = os.path.basename(args.path)
    if not args.silent:
        print(f"\n📁 {Fore.CYAN}Scanning: {program_name}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Using {len(API_PATTERNS)} detection patterns{Style.RESET_ALL}")

    start_time = datetime.now()

    # Determine which files to scan based on the provided options
    findings = []
    
    if args.git_history:
        findings = scan_git_history(args.path, exclude_patterns, args.context, args.silent)
    elif os.path.isdir(args.path):
        if args.git_scan:
            files_to_scan = get_git_tracked_files(args.path)
            if not args.silent and files_to_scan:
                print(f"{Fore.CYAN}Scanning {len(files_to_scan)} git-tracked files{Style.RESET_ALL}")
                
            # Use the specific files scanning function
            from apikeyleak.core.scanner import scan_specific_files
            findings = scan_specific_files(
                files_to_scan,
                context_size=args.context,
                max_workers=args.workers,
                silent=args.silent
            )
        elif args.incremental:
            files_to_scan = get_changed_files_since_last_scan(args.path)
            if not args.silent and files_to_scan:
                print(f"{Fore.CYAN}Scanning {len(files_to_scan)} changed files{Style.RESET_ALL}")
                
            # Use the specific files scanning function
            from apikeyleak.core.scanner import scan_specific_files
            findings = scan_specific_files(
                files_to_scan,
                context_size=args.context,
                max_workers=args.workers,
                silent=args.silent
            )
        else:
            # Use the regular directory scanning
            findings = scan_directory(
                args.path, 
                exclude_patterns=exclude_patterns,
                context_size=args.context,
                max_workers=args.workers,
                silent=args.silent
            )
    else:
        # Single file scanning
        if should_skip_file(args.path, exclude_patterns):
            if not args.silent:
                print(f"{Fore.YELLOW}Skipping file {args.path} based on exclude patterns{Style.RESET_ALL}")
        else:
            findings = scan_file(args.path, context_size=args.context)

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    # Add remediation suggestions if requested
    if args.remediation and findings:
        for finding in findings:
            finding.remediation = suggest_remediation(finding)

    # Output results based on format
    if args.format == "text":
        if args.output:
            export_text(findings, args.output, program_name, args.remediation)
        else:
            print_color_findings(findings, show_context=not args.no_context)
    elif args.format == "json":
        if args.output:
            export_json(findings, args.output)
        else:
            import json
            print(json.dumps([finding.to_dict() for finding in findings], indent=2))
    elif args.format == "csv":
        if args.output:
            export_csv(findings, args.output)
        else:
            import csv
            import sys
            writer = csv.writer(sys.stdout)
            writer.writerow(['File', 'Line', 'Type', 'Severity', 'Key'])
            for finding in findings:
                from apikeyleak.utils.helpers import mask_sensitive_data
                writer.writerow([
                    finding.file_path,
                    finding.line_num,
                    finding.pattern_name,
                    finding.severity,
                    mask_sensitive_data(finding.leak_text)
                ])
    elif args.format == "html":
        if args.output:
            generate_html_report(findings, args.output, args.remediation)
        else:
            print(f"{Fore.YELLOW}HTML output requires an output file path with --output{Style.RESET_ALL}")
            print_color_findings(findings, show_context=not args.no_context)

    # Print summary
    if not args.silent:
        print(f"\n{Fore.CYAN}Scan completed in {duration:.2f} seconds{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Files scanned: {len(set([finding.file_path for finding in findings]) if findings else [])} with {len(findings)} potential leaks found{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
