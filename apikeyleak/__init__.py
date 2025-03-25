"""
API Key Leak Detector

A powerful and flexible tool for detecting potential API key leaks in your codebase.
"""

__version__ = "0.1.0"
__author__ = "mrprohack"
__license__ = "MIT"

# Import core functionality first
from apikeyleak.core.models import LeakFinding, SeverityLevel
from apikeyleak.core.patterns import API_PATTERNS, DEFAULT_EXCLUDE_PATTERNS, load_custom_patterns
from apikeyleak.core.scanner import scan_file, scan_directory, scan_specific_files

# Then import git integration
from apikeyleak.git.integration import (
    get_git_tracked_files,
    scan_git_history,
    get_changed_files_since_last_scan,
    install_git_hook
)

# Finally import utility functions
from apikeyleak.utils.config import load_config_file, get_gitignore_exclusions
from apikeyleak.utils.helpers import mask_sensitive_data, suggest_remediation
from apikeyleak.output.exporters import (
    export_json,
    export_csv,
    export_text,
    generate_html_report
)

__all__ = [
    'scan_file',
    'scan_directory',
    'scan_specific_files',
    'API_PATTERNS',
    'DEFAULT_EXCLUDE_PATTERNS',
    'load_custom_patterns',
    'LeakFinding',
    'SeverityLevel',
    'get_git_tracked_files',
    'scan_git_history',
    'get_changed_files_since_last_scan',
    'install_git_hook',
    'load_config_file',
    'get_gitignore_exclusions',
    'mask_sensitive_data',
    'suggest_remediation',
    'export_json',
    'export_csv',
    'export_text',
    'generate_html_report'
]
