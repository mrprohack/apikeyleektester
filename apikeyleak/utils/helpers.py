"""
Helper utilities for API Key Leak Detector.
"""
from typing import Dict, List, Any, Optional
from collections import defaultdict
from colorama import Fore, Style

from apikeyleak.core.models import LeakFinding, SeverityLevel

def mask_sensitive_data(text: str) -> str:
    """Mask sensitive data for safer display."""
    if len(text) <= 8:
        return "*" * len(text)
    
    # Show first 4 and last 4 characters, mask the middle
    return text[:4] + "*" * (len(text) - 8) + text[-4:]

def suggest_remediation(finding: LeakFinding) -> str:
    """Suggest remediation for a detected API key leak."""
    remediation_tips = {
        "AWS": "Use AWS Parameter Store, Secrets Manager, or environment variables with proper IAM roles.",
        "GitHub": "Use GitHub secrets for workflows, or credential manager for local development.",
        "Stripe": "Store Stripe keys in server-side environment variables, never in client code.",
        "Google": "Use GCP Secret Manager and service accounts with least privilege.",
        "API Key": "Store API keys in environment variables or a secure secrets manager.",
        "Bearer": "Use OAuth flows properly with secure token storage and refresh methods.",
        "Secret": "Store secrets in environment variables or a dedicated secrets manager.",
        "Token": "Use short-lived tokens with a secure refresh mechanism.",
    }
    
    for key, tip in remediation_tips.items():
        if key in finding.pattern_name:
            return tip
            
    return "Store this sensitive data in environment variables or a secure secrets management solution."

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
            
            # Print remediation suggestion if available
            if finding.remediation:
                print(f"{Fore.GREEN}      Remediation: {finding.remediation}{Style.RESET_ALL}")
                
            print("") 