"""
Git integration for API Key Leak Detector.
"""

from apikeyleak.git.integration import (
    get_git_tracked_files,
    scan_git_history,
    get_changed_files_since_last_scan,
    install_git_hook
)

__all__ = [
    'get_git_tracked_files',
    'scan_git_history',
    'get_changed_files_since_last_scan',
    'install_git_hook'
]
