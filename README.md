# API Key Leak Detector

A powerful and flexible tool for detecting potential API key leaks in your codebase.

## Features

- **Advanced Detection**: Recognizes over 30 types of API keys and tokens
- **Reduced False Positives**: Intelligently filters out example keys and placeholders
- **Context-Aware Reporting**: Shows code context around detected leaks
- **Multi-Threading Support**: Fast scanning of large codebases
- **Customizable**: Add your own regex patterns or exclude specific files/directories
- **Multiple Output Formats**: Choose between text, JSON, or CSV output
- **Severity Classification**: Prioritize findings based on risk level (HIGH, MEDIUM, LOW)
- **Masked Key Display**: Securely displays sensitive information

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

### Advanced Usage

```bash
# Scan with custom exclude patterns and 4 context lines
python apikeyleektester.py /path/to/your/code --context 4 --exclude "*.log" "backup/*"

# Export results to JSON
python apikeyleektester.py /path/to/your/code --format json --output results.json

# Use custom detection patterns
python apikeyleektester.py /path/to/your/code --custom-patterns my_patterns.json

# Control parallel processing
python apikeyleektester.py /path/to/your/code --workers 8
```

### Command Line Options

- `path`: Path to the file or directory to scan
- `-o, --output`: Path to save the scan results
- `--format`: Output format (text, json, or csv)
- `--exclude`: Patterns of files/directories to exclude
- `--context`: Number of context lines to show before and after findings
- `--workers`: Number of worker threads for parallel scanning
- `--custom-patterns`: Path to JSON file with custom regex patterns
- `--no-context`: Don't show context lines in the output

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

/path/to/another_file.js:
  [MEDIUM] Line 15: Generic API Key
      Key: apiK****************H8gj
...
```

## Security Considerations

- This tool is designed to help identify potential API key leaks in your code
- Always verify findings manually as false positives may occur
- Use in your CI/CD pipeline to prevent accidental leaks
- Consider using a secret management solution for your real projects

## License

MIT
