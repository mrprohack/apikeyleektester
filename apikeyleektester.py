import re
import argparse
import os
import json
import csv
import sys
import fnmatch
from datetime import datetime
from typing import Dict, List, Tuple, Set, Optional, Any, Union
from collections import defaultdict
import concurrent.futures
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored terminal text
init()

# Extended list of regex patterns to detect various API keys with improved patterns
API_PATTERNS = {
    # Generic API keys
    'Generic API Key': r'(api[-_]?(key|token|secret)[\s=:]*["\']?([a-zA-Z0-9-_]{16,})["\']?)',
    
    # OAuth Tokens
    'Bearer Token': r'(bearer\s+[a-zA-Z0-9-_]{20,40})',
    
    # AWS Keys
    'AWS Access Key ID': r'((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})',
    'AWS Secret Key': r'((?:[a-zA-Z0-9+/]{40})(?:[\r\n]+|$))',
    'AWS MWS Auth Token': r'(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
    
    # GitHub
    'GitHub Personal Access Token': r'(github[_\-\.]?token[_\-\.]?[\w\d]{35,40})',
    'GitHub OAuth Access Token': r'(gho_[a-zA-Z0-9]{36})',
    'GitHub Personal Access Token (old)': r'(ghp_[a-zA-Z0-9]{36})',
    'GitHub App Token': r'(ghu_[a-zA-Z0-9]{36})',
    'GitHub Refresh Token': r'(ghr_[a-zA-Z0-9]{76})',
    
    # Stripe
    'Stripe Live Key': r'(sk_live_[0-9a-zA-Z]{24})',
    'Stripe Test Key': r'(sk_test_[0-9a-zA-Z]{24})',
    'Stripe Publishable Key': r'(pk_(test|live)_[0-9a-zA-Z]{24})',
    
    # Slack
    'Slack Token': r'(xox[abposr]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})',
    'Slack Webhook': r'(https?://hooks\.slack\.com/services/T[a-zA-Z0-9]{8}/B[a-zA-Z0-9]{8}/[a-zA-Z0-9]{24})',
    
    # Google
    'Google API Key': r'(AIza[0-9A-Za-z-_]{35})',
    'Google OAuth Refresh Token': r'(1/[0-9A-Za-z-_]{43}|1/[0-9A-Za-z-_]{64})',
    'Google OAuth Access Token': r'(ya29\.[0-9A-Za-z-_]+)',
    
    # Firebase
    'Firebase Database': r'(https?://[a-zA-Z0-9-]+\.firebaseio\.com)',
    
    # JSON Web Tokens
    'JWT Token': r'(eyJ[a-zA-Z0-9]{10,}\.eyJ[a-zA-Z0-9]{10,}\.[a-zA-Z0-9_-]{10,})',
    
    # Facebook
    'Facebook Access Token': r'(EAACEdEose0cBA[0-9A-Za-z]+)',
    'Facebook OAuth': r'([fF][aA][cC][eE][bB][oO][oO][kK].*[\'|"][0-9a-f]{32}[\'|"])',
    
    # Twitter
    'Twitter Access Token': r'([tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40})',
    'Twitter OAuth': r'([tT][wW][iI][tT][tT][eE][rR].*[\'|"][0-9a-zA-Z]{35,44}[\'|"])',
    
    # Heroku
    'Heroku API Key': r'([hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})',
    
    # Mailgun
    'Mailgun API Key': r'(key-[0-9a-zA-Z]{32})',
    
    # Square
    'Square Access Token': r'(sq0atp-[0-9A-Za-z-_]{22})',
    'Square OAuth Secret': r'(sq0csp-[0-9A-Za-z-_]{43})',
    
    # PayPal
    'PayPal Braintree Access Token': r'(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})',
    
    # Twilio
    'Twilio API Key': r'(SK[0-9a-fA-F]{32})',
    'Twilio Account SID': r'(AC[a-zA-Z0-9_\-]{32})',
    
    # Mailchimp
    'Mailchimp API Key': r'([0-9a-f]{32}-us[0-9]{1,2})',
    
    # Sensitive Environment Variables
    'Sensitive Env Var': r'(?:password|passwd|pwd|secret|token|api[_-]?key)["\s=:]+["\']([^"\']{8,})["\']'
}

# Known false positives to exclude
FALSE_POSITIVES = [
    'YOUR_API_KEY_HERE',
    'EXAMPLE_KEY',
    'INSERT_API_KEY_HERE',
    'your-api-key-here',
    'example-key',
    'placeholder',
    'api-key-placeholder',
    # Add more common placeholders here
]

# Default files/directories to exclude
DEFAULT_EXCLUDE_PATTERNS = [
    '*.svg', '*.png', '*.jpg', '*.jpeg', '*.gif', '*.ico', '*.pdf',
    '*.pyc', '*.pyo', '*.so', '*.dll', '*.class', '*.exe', 
    '.git/*', '.svn/*', '.hg/*', '.idea/*', '.vscode/*', 
    'node_modules/*', 'vendor/*', 'venv/*', 'env/*', '*.min.js',
    '*.min.css', 'dist/*', 'build/*'
]

class SeverityLevel:
    """Severity levels for API key leaks."""
    HIGH = 'HIGH'
    MEDIUM = 'MEDIUM'
    LOW = 'LOW'

class LeakFinding:
    """Class to represent a detected API key leak with context."""
    def __init__(self, 
                 file_path: str, 
                 line_num: int, 
                 leak_text: str, 
                 pattern_name: str,
                 context_before: List[str] = None,
                 context_after: List[str] = None):
        self.file_path = file_path
        self.line_num = line_num
        self.leak_text = leak_text
        self.pattern_name = pattern_name
        self.context_before = context_before or []
        self.context_after = context_after or []
        self.severity = self._determine_severity()
    
    def _determine_severity(self) -> str:
        """Determine severity based on key type and content."""
        high_severity_keys = ['AWS', 'Stripe Live', 'GitHub', 'Google', 'JWT', 'Bearer']
        medium_severity_keys = ['API Key', 'Token', 'Secret', 'Slack', 'Twilio']
        
        for key in high_severity_keys:
            if key in self.pattern_name:
                return SeverityLevel.HIGH
        
        for key in medium_severity_keys:
            if key in self.pattern_name:
                return SeverityLevel.MEDIUM
        
        # If it contains 'test' or 'dev', consider it lower severity
        if 'test' in self.pattern_name.lower() or 'dev' in self.leak_text.lower():
            return SeverityLevel.LOW
            
        return SeverityLevel.MEDIUM
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for serialization."""
        return {
            'file_path': self.file_path,
            'line_number': self.line_num,
            'leak_text': self.leak_text,
            'pattern_name': self.pattern_name,
            'severity': self.severity,
            'context_before': self.context_before,
            'context_after': self.context_after
        }

def is_false_positive(leak_text: str) -> bool:
    """Check if a detected leak is likely a false positive."""
    # Check against known false positives
    for fp in FALSE_POSITIVES:
        if fp.lower() in leak_text.lower():
            return True
            
    # Check common patterns that indicate test/example keys
    common_indicators = ['example', 'test', 'fake', 'sample', 'placeholder', 'xxx', '000000']
    for indicator in common_indicators:
        if indicator.lower() in leak_text.lower():
            return True
    
    return False

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
                   max_workers: int = None) -> List[LeakFinding]:
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
        
        for future in concurrent.futures.as_completed(future_to_file):
            file_findings = future.result()
            if file_findings:
                all_findings.extend(file_findings)
    
    return all_findings

def print_color_findings(findings: List[LeakFinding], show_context: bool = True) -> None:
    """Print findings with color highlighting."""
    if not findings:
        print(f"\n{Fore.GREEN}✅ No API keys found.{Style.RESET_ALL}")
        return
        
    # Group by file
    findings_by_file = defaultdict(list)
    for finding in findings:
        findings_by_file[finding.file_path].append(finding)
    
    total_files = len(findings_by_file)
    total_keys = len(findings)
    
    print(f"\n{Fore.RED}🔴 Potential API keys found: {total_keys} across {total_files} files{Style.RESET_ALL}\n")
    
    # Count by severity
    severity_counts = {
        SeverityLevel.HIGH: len([f for f in findings if f.severity == SeverityLevel.HIGH]),
        SeverityLevel.MEDIUM: len([f for f in findings if f.severity == SeverityLevel.MEDIUM]),
        SeverityLevel.LOW: len([f for f in findings if f.severity == SeverityLevel.LOW])
    }
    
    print(f"{Fore.RED}HIGH: {severity_counts[SeverityLevel.HIGH]} {Fore.YELLOW}MEDIUM: {severity_counts[SeverityLevel.MEDIUM]} {Fore.BLUE}LOW: {severity_counts[SeverityLevel.LOW]}{Style.RESET_ALL}\n")
    
    for file_path, file_findings in findings_by_file.items():
        print(f"{Fore.CYAN}{file_path}:{Style.RESET_ALL}")
        for finding in file_findings:
            severity_color = Fore.RED if finding.severity == SeverityLevel.HIGH else (
                              Fore.YELLOW if finding.severity == SeverityLevel.MEDIUM else Fore.BLUE)
                              
            print(f"  {severity_color}[{finding.severity}]{Style.RESET_ALL} Line {finding.line_num}: {finding.pattern_name}")
            
            # Print masked key for security reasons
            masked_key = mask_sensitive_data(finding.leak_text)
            print(f"      Key: {masked_key}")
            
            if show_context:
                if finding.context_before:
                    print(f"{Fore.WHITE}      Context before:{Style.RESET_ALL}")
                    for i, ctx_line in enumerate(finding.context_before):
                        ctx_line_num = finding.line_num - len(finding.context_before) + i
                        print(f"        {ctx_line_num}: {ctx_line.rstrip()}")
                
                # Print the line with the leak
                print(f"{Fore.RED}        {finding.line_num}: {Style.RESET_ALL}", end="")
                print(finding.leak_text)
                
                if finding.context_after:
                    print(f"{Fore.WHITE}      Context after:{Style.RESET_ALL}")
                    for i, ctx_line in enumerate(finding.context_after):
                        ctx_line_num = finding.line_num + i + 1
                        print(f"        {ctx_line_num}: {ctx_line.rstrip()}")
            
            print("")

def mask_sensitive_data(text: str) -> str:
    """Mask sensitive data for safer display."""
    if len(text) <= 8:
        return "*" * len(text)
    
    # Show first 4 and last 4 characters, mask the middle
    return text[:4] + "*" * (len(text) - 8) + text[-4:]

def export_json(findings: List[LeakFinding], output_file: str) -> None:
    """Export findings to JSON file."""
    with open(output_file, 'w') as f:
        json.dump({
            'scan_time': datetime.now().isoformat(),
            'total_findings': len(findings),
            'findings': [finding.to_dict() for finding in findings]
        }, f, indent=2)

def export_csv(findings: List[LeakFinding], output_file: str) -> None:
    """Export findings to CSV file."""
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['File', 'Line', 'Type', 'Severity', 'Key'])
        for finding in findings:
            writer.writerow([
                finding.file_path,
                finding.line_num,
                finding.pattern_name,
                finding.severity,
                mask_sensitive_data(finding.leak_text)
            ])

def load_custom_patterns(patterns_file: str) -> Dict[str, str]:
    """Load custom patterns from a JSON file."""
    try:
        with open(patterns_file, 'r') as f:
            patterns = json.load(f)
        return patterns
    except Exception as e:
        print(f"{Fore.YELLOW}Warning: Could not load custom patterns: {str(e)}{Style.RESET_ALL}")
        return {}

def main():
    parser = argparse.ArgumentParser(
        description="Advanced scanner for potential API key leaks in code.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("path", help="Path to the file or directory to scan")
    parser.add_argument("-o", "--output", help="Path to save the scan results", default=None)
    parser.add_argument("--format", choices=["text", "json", "csv"], default="text",
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
    args = parser.parse_args()

    # Load custom patterns if provided
    if args.custom_patterns:
        custom_patterns = load_custom_patterns(args.custom_patterns)
        API_PATTERNS.update(custom_patterns)

    exclude_patterns = DEFAULT_EXCLUDE_PATTERNS
    if args.exclude:
        exclude_patterns.extend(args.exclude)

    program_name = os.path.basename(args.path)
    print(f"\n📁 {Fore.CYAN}Scanning: {program_name}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Using {len(API_PATTERNS)} detection patterns{Style.RESET_ALL}")

    start_time = datetime.now()

    if os.path.isdir(args.path):
        findings = scan_directory(
            args.path, 
            exclude_patterns=exclude_patterns,
            context_size=args.context,
            max_workers=args.workers
        )
    else:
        if should_skip_file(args.path, exclude_patterns):
            print(f"{Fore.YELLOW}Skipping file {args.path} based on exclude patterns{Style.RESET_ALL}")
            findings = []
        else:
            findings = scan_file(args.path, context_size=args.context)

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    # Output results
    if args.format == "text":
        print_color_findings(findings, show_context=not args.no_context)
    elif args.format == "json":
        if args.output:
            export_json(findings, args.output)
            print(f"\n{Fore.GREEN}Results saved to {args.output} in JSON format{Style.RESET_ALL}")
        else:
            print(json.dumps([finding.to_dict() for finding in findings], indent=2))
    elif args.format == "csv":
        if args.output:
            export_csv(findings, args.output)
            print(f"\n{Fore.GREEN}Results saved to {args.output} in CSV format{Style.RESET_ALL}")
        else:
            writer = csv.writer(sys.stdout)
            writer.writerow(['File', 'Line', 'Type', 'Severity', 'Key'])
            for finding in findings:
                writer.writerow([
                    finding.file_path,
                    finding.line_num,
                    finding.pattern_name,
                    finding.severity,
                    mask_sensitive_data(finding.leak_text)
                ])

    # Print summary
    print(f"\n{Fore.CYAN}Scan completed in {duration:.2f} seconds{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Files scanned: {len(list(set([finding.file_path for finding in findings])))} with {len(findings)} potential leaks found{Style.RESET_ALL}")

    # Default output format
    if args.output and args.format == "text":
        with open(args.output, 'w') as output_file:
            output_file.write(f"Scan results for: {program_name}\n\n")
            output_file.write(f"Total findings: {len(findings)}\n\n")
            for finding in findings:
                output_file.write(f"{finding.file_path}:\n")
                output_file.write(f"  Line {finding.line_num}: {finding.pattern_name}\n")
                output_file.write(f"  Key: {mask_sensitive_data(finding.leak_text)}\n")
                output_file.write("\n")

if __name__ == "__main__":
    main()
