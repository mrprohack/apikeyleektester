"""
Configuration utilities for API Key Leak Detector.
"""
import os
import yaml
import json
from typing import Dict, Any, List
from colorama import Fore, Style

def load_config_file(config_file: str) -> Dict[str, Any]:
    """Load configuration from a YAML or JSON file."""
    try:
        file_ext = os.path.splitext(config_file)[1].lower()
        with open(config_file, 'r') as f:
            if file_ext in ('.yaml', '.yml'):
                config = yaml.safe_load(f)
            elif file_ext == '.json':
                config = json.load(f)
            else:
                print(f"{Fore.YELLOW}Warning: Unsupported config file format: {file_ext}. Using JSON.{Style.RESET_ALL}")
                config = json.load(f)
        
        print(f"{Fore.GREEN}Loaded configuration from {config_file}{Style.RESET_ALL}")
        return config
    except Exception as e:
        print(f"{Fore.YELLOW}Warning: Could not load config file: {str(e)}{Style.RESET_ALL}")
        return {}

def get_gitignore_exclusions(directory: str) -> List[str]:
    """Parse .gitignore files and return patterns to exclude."""
    try:
        gitignore_file = os.path.join(directory, '.gitignore')
        if os.path.exists(gitignore_file):
            with open(gitignore_file, 'r') as f:
                patterns = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            return patterns
        return []
    except Exception as e:
        print(f"{Fore.YELLOW}Warning: Could not parse .gitignore: {str(e)}{Style.RESET_ALL}")
        return [] 