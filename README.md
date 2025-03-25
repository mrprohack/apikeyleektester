# API Key Leak Detector

A powerful and flexible tool for detecting potential API key leaks in your codebase.

## Features

- **Advanced Detection**: Recognizes over 30 types of API keys and tokens
- **Reduced False Positives**: Intelligently filters out example keys and placeholders
- **Context-Aware Reporting**: Shows code context around detected leaks
- **Multi-Threading Support**: Fast scanning of large codebases
- **Customizable**: Add your own regex patterns or exclude specific files/directories
- **Multiple Output Formats**: Choose between text, JSON, CSV, or interactive HTML reports
- **Severity Classification**: Prioritize findings based on risk level (HIGH, MEDIUM, LOW)
- **Masked Key Display**: Securely displays sensitive information
- **Git Integration**: Scan tracked files, commit history, and use pre-commit hooks
- **Progress Tracking**: Visual progress bar for large scans
- **Configuration Files**: Use YAML/JSON configuration for consistent scans
- **Incremental Scanning**: Only scan files changed since the last scan
- **Remediation Suggestions**: Get actionable advice on how to fix detected leaks

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/apikeyleektest.git
cd apikeyleektest

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python apikeyleektester.py /path/to/your/code
```

### Avoiding False Positives

```bash
# Exclude Git files to avoid false positives from Git hashes
python apikeyleektester.py /path/to/your/code --no-git-files

# Or use the git-scan option to only scan tracked files
python apikeyleektester.py /path/to/your/code --git-scan
```

### Advanced Usage

```bash
# Scan with custom exclude patterns and 4 context lines
python apikeyleektester.py /path/to/your/code --context 4 --exclude "*.log" "backup/*"

# Skip specific folders or files
python apikeyleektester.py /path/to/your/code --skip "node_modules" "/path/to/specific/file.js" "test/fixtures"

# Export results to JSON
python apikeyleektester.py /path/to/your/code --format json --output results.json

# Use custom detection patterns
python apikeyleektester.py /path/to/your/code --custom-patterns my_patterns.json

# Control parallel processing
python apikeyleektester.py /path/to/your/code --workers 8

# Generate an interactive HTML report with remediation suggestions
python apikeyleektester.py /path/to/your/code --format html --output report.html --remediation

# Use a configuration file for consistent settings
python apikeyleektester.py /path/to/your/code --config scan_config.yaml
```

### Git Integration

```bash
# Only scan git-tracked files (ignores untracked and .gitignore files)
python apikeyleektester.py /path/to/your/code --git-scan

# Scan git commit history for leaked keys
python apikeyleektester.py /path/to/your/code --git-history

# Install a pre-commit hook to prevent committing leaked keys
python apikeyleektester.py /path/to/your/code --install-hook

# Install a Python-based pre-commit hook (more robust than bash)
python apikeyleektester.py /path/to/your/code --install-hook --python-hook

# Only scan files that have changed since the last scan
python apikeyleektester.py /path/to/your/code --incremental
```

### Command Line Options

- `path`: Path to the file or directory to scan
- `-o, --output`: Path to save the scan results
- `--format`: Output format (text, json, csv, or html)
- `--exclude`: Patterns of files/directories to exclude
- `--skip`: Specific files or folders to skip during scanning (absolute or relative paths)
- `--context`: Number of context lines to show before and after findings
- `--workers`: Number of worker threads for parallel scanning
- `--custom-patterns`: Path to JSON file with custom regex patterns
- `--no-context`: Don't show context lines in the output
- `--config`: Path to YAML or JSON configuration file
- `--git-scan`: Only scan git-tracked files
- `--git-history`: Scan git commit history for leaks
- `--incremental`: Only scan files changed since last scan
- `--install-hook`: Install git pre-commit hook
- `--python-hook`: Use Python version of git hook (more robust, cross-platform)
- `--remediation`: Show remediation suggestions for detected leaks
- `--silent`: Suppress progress output, display only findings
- `--no-git-files`: Exclude all Git-related files from scanning to avoid false positives from Git hashes

## Configuration Files

You can use YAML or JSON configuration files to store your scan settings:

```yaml
# Example config_example.yaml
exclude:
  - "*.log"
  - "tests/fixtures/*"
skip:
  - "node_modules"
  - "/path/to/specific/file.js"
format: "html"
output: "api_key_scan_report.html"
context: 3
remediation: true
custom_patterns: "custom_patterns_example.json"
workers: 4
```

## Creating Custom Pattern Files

You can create your own JSON file with custom regex patterns:

```json
{
  "My Custom API Key": "(custom-api-key-[a-zA-Z0-9]{20})",
  "Internal Token": "(internal-[0-9]{10}-[a-z]{8})"
}
```

## Example Output

```
📁 Scanning: my_project

🔴 Potential API keys found: 3 across 2 files

HIGH: 1 MEDIUM: 2 LOW: 0

/path/to/file.py:
  [HIGH] Line 42: AWS Access Key ID
      Key: AKIA****************EXAMPLE
      Context before:
        40: # Initialize AWS client
        41: client = boto3.client('s3',
        42: aws_access_key_id='AKIAIOSFODNN7EXAMPLE',
        43: aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')
      Context after:
        44: s3 = client.list_buckets()
      Remediation: Use AWS Parameter Store, Secrets Manager, or environment variables with proper IAM roles.

/path/to/another_file.js:
  [MEDIUM] Line 15: Generic API Key
      Key: apiK****************H8gj
...
```

## HTML Reports

The HTML report option provides an interactive interface to explore findings:
- Filter by severity, key type, or filename
- Sort findings 
- View code context
- Get remediation suggestions
- Print or share findings easily

## Continuous Integration

You can add the API Key Leak Detector to your CI/CD pipelines:

```yaml
# Example GitHub Action workflow
name: API Key Leak Check

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.8'
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
      - name: Scan for API key leaks
        run: python apikeyleektester.py . --format json --output leaks.json
      - name: Check for leaks
        run: |
          if [ "$(jq '.total_findings' leaks.json)" -gt 0 ]; then
            echo "API key leaks detected!"
            exit 1
          fi
```

## Security Considerations

- This tool is designed to help identify potential API key leaks in your code
- Always verify findings manually as false positives may occur
- Use in your CI/CD pipeline to prevent accidental leaks
- Consider using a secret management solution for your real projects

## License

MIT
