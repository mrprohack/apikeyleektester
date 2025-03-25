"""
Export functions for API Key Leak Detector.
"""
import os
import json
import csv
import jinja2
from typing import List, Dict, Any
from datetime import datetime
from colorama import Fore, Style

from apikeyleak.core.models import LeakFinding
from apikeyleak.utils.helpers import mask_sensitive_data, suggest_remediation

def export_json(findings: List[LeakFinding], output_file: str) -> None:
    """Export findings to JSON file."""
    with open(output_file, 'w') as f:
        json.dump({
            'scan_time': datetime.now().isoformat(),
            'total_findings': len(findings),
            'findings': [finding.to_dict() for finding in findings]
        }, f, indent=2)
    
    print(f"\n{Fore.GREEN}Results saved to {output_file} in JSON format{Style.RESET_ALL}")

def export_csv(findings: List[LeakFinding], output_file: str) -> None:
    """Export findings to CSV file."""
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['File', 'Line', 'Type', 'Severity', 'Key', 'Remediation'])
        for finding in findings:
            writer.writerow([
                finding.file_path,
                finding.line_num,
                finding.pattern_name,
                finding.severity,
                mask_sensitive_data(finding.leak_text),
                finding.remediation if finding.remediation else ''
            ])
    
    print(f"\n{Fore.GREEN}Results saved to {output_file} in CSV format{Style.RESET_ALL}")

def export_text(findings: List[LeakFinding], output_file: str, program_name: str, with_remediation: bool = False) -> None:
    """Export findings to text file."""
    with open(output_file, 'w') as f:
        f.write(f"Scan results for: {program_name}\n\n")
        f.write(f"Total findings: {len(findings)}\n\n")
        for finding in findings:
            f.write(f"{finding.file_path}:\n")
            f.write(f"  Line {finding.line_num}: {finding.pattern_name}\n")
            f.write(f"  Key: {mask_sensitive_data(finding.leak_text)}\n")
            if with_remediation and finding.remediation:
                f.write(f"  Remediation: {finding.remediation}\n")
            f.write("\n")
    
    print(f"\n{Fore.GREEN}Results saved to {output_file} in text format{Style.RESET_ALL}")

def generate_html_report(findings: List[LeakFinding], output_file: str, with_remediation: bool = False) -> None:
    """Generate an HTML report with interactive filtering and sorting."""
    template_str = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Key Leak Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }
        h1 { color: #2c3e50; margin-bottom: 20px; }
        .summary { display: flex; margin-bottom: 20px; background: #f5f5f5; padding: 15px; border-radius: 5px; }
        .summary-item { margin-right: 30px; }
        .summary-number { font-size: 24px; font-weight: bold; }
        .filters { margin-bottom: 20px; padding: 15px; background: #f5f5f5; border-radius: 5px; }
        .finding { margin-bottom: 25px; padding: 15px; border-left: 5px solid #3498db; background: #f9f9f9; }
        .finding.high { border-left-color: #e74c3c; }
        .finding.medium { border-left-color: #f39c12; }
        .finding.low { border-left-color: #2ecc71; }
        .file-path { color: #2c3e50; font-weight: bold; margin-bottom: 10px; }
        .leak-info { display: flex; margin-bottom: 10px; }
        .leak-type { width: 200px; font-weight: bold; }
        .leak-text { font-family: monospace; background: #eee; padding: 3px 6px; border-radius: 3px; }
        .context { background: #fff; padding: 10px; border: 1px solid #ddd; font-family: monospace; white-space: pre; overflow-x: auto; }
        .remediation { background: #e8f4fc; padding: 10px; margin-top: 10px; border-radius: 3px; }
        .severity { display: inline-block; padding: 3px 8px; border-radius: 3px; color: white; font-size: 12px; font-weight: bold; }
        .severity.high { background: #e74c3c; }
        .severity.medium { background: #f39c12; }
        .severity.low { background: #2ecc71; }
        select, input { padding: 8px; margin-right: 10px; border: 1px solid #ddd; border-radius: 3px; }
        button { padding: 8px 15px; background: #3498db; color: white; border: none; border-radius: 3px; cursor: pointer; }
        button:hover { background: #2980b9; }
    </style>
</head>
<body>
    <h1>API Key Leak Scan Report</h1>
    
    <div class="summary">
        <div class="summary-item">
            <div class="summary-number">{{ findings|length }}</div>
            <div>Total Findings</div>
        </div>
        <div class="summary-item">
            <div class="summary-number">{{ findings|selectattr('severity', 'equalto', 'HIGH')|list|length }}</div>
            <div>High Severity</div>
        </div>
        <div class="summary-item">
            <div class="summary-number">{{ findings|selectattr('severity', 'equalto', 'MEDIUM')|list|length }}</div>
            <div>Medium Severity</div>
        </div>
        <div class="summary-item">
            <div class="summary-number">{{ findings|selectattr('severity', 'equalto', 'LOW')|list|length }}</div>
            <div>Low Severity</div>
        </div>
        <div class="summary-item">
            <div class="summary-number">{{ findings|map(attribute='file_path')|unique|list|length }}</div>
            <div>Files Affected</div>
        </div>
    </div>
    
    <div class="filters">
        <h3>Filters</h3>
        <div>
            <select id="severityFilter">
                <option value="all">All Severities</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
            </select>
            
            <select id="typeFilter">
                <option value="all">All Types</option>
                {% for type in findings|map(attribute='pattern_name')|unique|sort %}
                <option value="{{ type }}">{{ type }}</option>
                {% endfor %}
            </select>
            
            <input type="text" id="fileFilter" placeholder="Filter by filename...">
            
            <button onclick="applyFilters()">Apply Filters</button>
            <button onclick="resetFilters()">Reset</button>
        </div>
    </div>
    
    <div id="findings">
    {% for finding in findings %}
        <div class="finding {{ finding['severity']|lower }}" 
             data-severity="{{ finding['severity'] }}"
             data-type="{{ finding['pattern_name'] }}"
             data-file="{{ finding['file_path'] }}">
            <div class="file-path">
                {{ finding['file_path'] }}:{{ finding['line_number'] }}
                <span class="severity {{ finding['severity']|lower }}">{{ finding['severity'] }}</span>
            </div>
            
            <div class="leak-info">
                <div class="leak-type">{{ finding['pattern_name'] }}</div>
                <div class="leak-text">{{ finding['leak_text']|mask_key }}</div>
            </div>
            
            <div class="context">{% if finding['context_before'] %}{% for line in finding['context_before'] %}{{ loop.index + finding['line_number'] - finding['context_before']|length - 1 }}: {{ line }}
{% endfor %}{% endif %}{{ finding['line_number'] }}: <mark>{{ finding['leak_text'] }}</mark>
{% if finding['context_after'] %}{% for line in finding['context_after'] %}{{ loop.index + finding['line_number'] }}: {{ line }}
{% endfor %}{% endif %}</div>
            
            {% if remediation and finding['remediation'] %}
            <div class="remediation">
                <strong>Remediation Suggestion:</strong> {{ finding['remediation'] }}
            </div>
            {% endif %}
        </div>
    {% endfor %}
    </div>
    
    <script>
        function applyFilters() {
            const severityFilter = document.getElementById('severityFilter').value;
            const typeFilter = document.getElementById('typeFilter').value;
            const fileFilter = document.getElementById('fileFilter').value.toLowerCase();
            
            const findings = document.querySelectorAll('.finding');
            
            findings.forEach(finding => {
                const severity = finding.getAttribute('data-severity');
                const type = finding.getAttribute('data-type');
                const file = finding.getAttribute('data-file').toLowerCase();
                
                const severityMatch = severityFilter === 'all' || severity === severityFilter;
                const typeMatch = typeFilter === 'all' || type === typeFilter;
                const fileMatch = fileFilter === '' || file.includes(fileFilter);
                
                if (severityMatch && typeMatch && fileMatch) {
                    finding.style.display = 'block';
                } else {
                    finding.style.display = 'none';
                }
            });
        }
        
        function resetFilters() {
            document.getElementById('severityFilter').value = 'all';
            document.getElementById('typeFilter').value = 'all';
            document.getElementById('fileFilter').value = '';
            
            document.querySelectorAll('.finding').forEach(finding => {
                finding.style.display = 'block';
            });
        }
        
        // Initial load
        document.addEventListener('DOMContentLoaded', function() {
            applyFilters();
        });
    </script>
</body>
</html>"""

    # Add remediation suggestions if enabled
    if with_remediation:
        for finding in findings:
            finding.remediation = suggest_remediation(finding)
    
    # Create Jinja2 environment and template
    env = jinja2.Environment()
    env.filters['mask_key'] = mask_sensitive_data
    template = env.from_string(template_str)
    
    # Render template with findings
    html_content = template.render(
        findings=[finding.to_dict() for finding in findings],
        remediation=with_remediation
    )
    
    # Write to output file
    with open(output_file, 'w') as f:
        f.write(html_content)
        
    print(f"\n{Fore.GREEN}HTML report saved to {output_file}{Style.RESET_ALL}") 