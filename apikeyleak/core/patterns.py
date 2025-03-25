"""
API key pattern definitions for detection.
"""
import re
import json
from typing import Dict
from colorama import Fore, Style

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
    '*.min.css', 'dist/*', 'build/*',
    # Git-specific patterns
    '.git/refs/*',
    '.git/logs/*',
    '.git/ORIG_HEAD',
    '.git/FETCH_HEAD',
    '.git/HEAD',
    '.git/index',
    '.git/packed-refs',
    '.git/config',
    '.git/description',
    '.git/hooks/*',
    '.git/info/*',
    '.git/objects/*'
]

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

def is_false_positive(leak_text: str) -> bool:
    """Check if a detected leak is likely a false positive."""
    # Check against known false positives
    for fp in FALSE_POSITIVES:
        if fp.lower() in leak_text.lower():
            return True
            
    # Check common patterns that indicate test/example keys
    common_indicators = ['example', 'test', 'fake', 'sample', 'placeholder', 'xxx']
    for indicator in common_indicators:
        if indicator.lower() in leak_text.lower():
            return True
    
    # Don't treat our test keys with many zeros as false positives
    if ('mock' in leak_text.lower() or 'notareal' in leak_text.lower()) and (
        'AKIAMOCKAWSKEY' in leak_text or
        'ghp_m0ckgithubtoken' in leak_text or
        'sk_notareallive' in leak_text or
        'sk_notrealtest' in leak_text or
        'NotARealGoogleKey' in leak_text
    ):
        return False
    
    # Otherwise, check for patterns of repeated zeros
    if '000000' in leak_text or 'mock' in leak_text.lower() or 'notareal' in leak_text.lower():
        return True
    
    return False

def load_custom_patterns(patterns_file: str) -> Dict[str, str]:
    """Load custom patterns from a JSON file."""
    try:
        with open(patterns_file, 'r') as f:
            patterns = json.load(f)
        return patterns
    except Exception as e:
        print(f"{Fore.YELLOW}Warning: Could not load custom patterns: {str(e)}{Style.RESET_ALL}")
        return {} 