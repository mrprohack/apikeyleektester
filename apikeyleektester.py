import re
import argparse

# Extended list of regex patterns to detect various API keys
API_PATTERNS = [
    r'(api[-_]?(key|token|secret)[\s=:]*["\']?([a-zA-Z0-9-_]{16,})["\']?)',   # Generic API keys
    r'(bearer\s+[a-zA-Z0-9-_]{20,40})',                                       # Bearer tokens
    r'(aws_access_key_id[\s=:]*["\']?([A-Z0-9]{20})["\']?)',                  # AWS Access Key
    r'(aws_secret_access_key[\s=:]*["\']?([a-zA-Z0-9/+]{40})["\']?)',         # AWS Secret Key
    r'(ghp_[a-zA-Z0-9]{36})',                                                # GitHub Personal Access Token
    r'(sk_live_[a-zA-Z0-9]{24})',                                            # Stripe live secret key
    r'(sk_test_[a-zA-Z0-9]{24})',                                            # Stripe test secret key
    r'(xox[baprs]-[0-9a-zA-Z]{10,48})',                                      # Slack token
    r'(AIza[0-9A-Za-z-_]{35})',                                              # Google API Key
    r'(eyJhbGciOiJIUzI1Ni[0-9a-zA-Z_-]+)',                                   # JWT tokens
    r'([A-Za-z0-9+/]{32,64})',                                               # Random Base64-encoded keys
    r'([A-Za-z0-9]{32,64})',                                                 # Random alphanumeric keys (e.g., V1ISk1mzjAaxkdQYSgmR5vzTW9dQmy8c)
    r'([a-zA-Z0-9_-]{16,64})'                                                # Miscellaneous token formats
]

def scan_file(file_path):
    """Scan a file for potential API key leaks."""
    with open(file_path, 'r', errors='ignore') as f:
        content = f.read()
    
    leaks = []

    for pattern in API_PATTERNS:
        matches = re.findall(pattern, content)
        if matches:
            leaks.extend(matches)
    
    if leaks:
        print(f"\n🔴 Potential API keys found in {file_path}:\n")
        for leak in leaks:
            if isinstance(leak, tuple):
                print(f"  🔥 {leak[0]}")
            else:
                print(f"  🔥 {leak}")
    else:
        print(f"\n✅ No API keys found in {file_path}.")

def main():
    parser = argparse.ArgumentParser(description="Scan program files for potential API key leaks.")
    parser.add_argument("file", help="Path to the program file (e.g., .py, .c, .js, .java)")
    args = parser.parse_args()

    scan_file(args.file)

if __name__ == "__main__":
    main()

