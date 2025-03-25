"""
Core functionality for API Key Leak Detector.
"""

from apikeyleak.core.scanner import scan_file, scan_directory, scan_specific_files
from apikeyleak.core.patterns import API_PATTERNS, DEFAULT_EXCLUDE_PATTERNS, load_custom_patterns
from apikeyleak.core.models import LeakFinding, SeverityLevel

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
