import re
import argparse
import os

# Extended list of regex patterns to detect various API keys
API_PATTERNS = [
    # Generic API keys
    r'(api[-_]?(key|token|secret)[\s=:]*["\']?([a-zA-Z0-9-_]{16,})["\']?)',
    # Bearer tokens
    r'(bearer\s+[a-zA-Z0-9-_]{20,40})',
    # AWS Access Key
    r'(aws_access_key_id[\s=:]*["\']?([A-Z0-9]{20})["\']?)',
    # AWS Secret Key
    r'(aws_secret_access_key[\s=:]*["\']?([a-zA-Z0-9/+]{40})["\']?)',
    # GitHub Personal Access Token
    r'(ghp_[a-zA-Z0-9]{36})',
    # Stripe live secret key
    r'(sk_live_[a-zA-Z0-9]{24})',
    # Stripe test secret key
    r'(sk_test_[a-zA-Z0-9]{24})',
    # Slack token
    r'(xox[baprs]-[0-9a-zA-Z]{10,48})',
    # Google API Key
    r'(AIza[0-9A-Za-z-_]{35})',
    # JWT tokens
    r'(eyJhbGciOiJIUzI1Ni[0-9a-zA-Z_-]+)',
    # Random Base64-encoded keys
    r'([A-Za-z0-9+/]{32,64})',
    # Random alphanumeric keys
    r'([A-Za-z0-9]{32,64})',
    # Miscellaneous token formats
    r'([a-zA-Z0-9_-]{16,64})'
]

def scan_file(file_path):
    """Scan a file for potential API key leaks."""
    leaks = set()  # Use a set to store unique leaks

    with open(file_path, 'r', errors='ignore') as file:
        content = file.read()

        for pattern in API_PATTERNS:
            matches = re.findall(pattern, content)
            for match in matches:
                if isinstance(match, tuple):
                    leaks.add(match[0])
                else:
                    leaks.add(match)

    return list(leaks)

def scan_directory(directory_path):
    """Scan all files in a directory recursively for potential API key leaks."""
    all_leaks = {}

    for root, dirs, files in os.walk(directory_path):
        # Skip .git directories
        dirs[:] = [d for d in dirs if d != '.git']
        
        for file in files:
            file_path = os.path.join(root, file)
            leaks = scan_file(file_path)
            if leaks:
                all_leaks[file_path] = leaks

    return all_leaks
    
def main():
    parser = argparse.ArgumentParser(description="Scan program files for potential API key leaks.")
    parser.add_argument("path", help="Path to the program file or directory")
    parser.add_argument("-o", "--output", help="Path to save the scan results", default=None)
    args = parser.parse_args()

    if os.path.isdir(args.path):
        results = scan_directory(args.path)
    else:
        results = {args.path: scan_file(args.path)}

    if results:
        print("\n🔴 Potential API keys found:\n")
        for file_path, leaks in results.items():
            print(f"{file_path}:")
            for leak in leaks:
                print(f"  🔥 {leak}")
    else:
        print("\n✅ No API keys found.")

    if args.output:
        with open(args.output, 'w') as output_file:
            for file_path, leaks in results.items():
                output_file.write(f"{file_path}:\n")
                for leak in leaks:
                    output_file.write(f"  🔥 {leak}\n")

if __name__ == "__main__":
    main()
