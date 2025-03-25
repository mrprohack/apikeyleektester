"""
Data models for API Key Leak Detector.
"""
from typing import Dict, List, Any

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
        self.remediation = None
    
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
        result = {
            'file_path': self.file_path,
            'line_number': self.line_num,
            'leak_text': self.leak_text,
            'pattern_name': self.pattern_name,
            'severity': self.severity,
            'context_before': self.context_before,
            'context_after': self.context_after
        }
        
        if self.remediation:
            result['remediation'] = self.remediation
            
        return result 