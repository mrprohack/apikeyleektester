#!/usr/bin/env python3
"""
Command-line interface for API Key Leak Detector.
"""
import sys
import os

def main():
    """Main entry point for the CLI command."""
    # Get the path to apikeyleektester.py
    script_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'apikeyleektester.py')
    
    # Call the main script with the provided arguments
    sys.path.insert(0, os.path.dirname(script_path))
    
    # Import the main function from apikeyleektester.py
    from apikeyleektester import main as run_main
    
    # Run the main function
    run_main()

if __name__ == "__main__":
    main() 