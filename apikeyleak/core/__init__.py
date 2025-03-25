"""
Core functionality for API Key Leak Detector.
"""

# Import models and patterns first
from apikeyleak.core.models import LeakFinding, SeverityLevel
from apikeyleak.core.patterns import API_PATTERNS, DEFAULT_EXCLUDE_PATTERNS, load_custom_patterns

# Then import scanner functionality
from apikeyleak.core.scanner import scan_file, scan_directory, scan_specific_files

__all__ = [
    'scan_file',
    'scan_directory',
    'scan_specific_files',
    'API_PATTERNS',
    'DEFAULT_EXCLUDE_PATTERNS',
    'load_custom_patterns',
    'LeakFinding',
    'SeverityLevel'
]
