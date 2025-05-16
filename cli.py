#!/usr/bin/env python3
import os
import sys
import json
import argparse
from typing import Dict, Any

from core.llm_client import LLMClient
from core.file_scanner import FileScanner
from integrations.gitlab_integration import GitLabIntegration

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="CodeSheriff - Detect malicious code using LLM"
    )
    
    # Create subparsers for different modes
    subparsers = parser.add_subparsers(dest="mode", help="Operation mode")
    
    # Common arguments
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument(
        "-w", "--workers",
        type=int,
        default=None,
        help="Maximum number of worker threads (default: CPU count + 4)"
    )
    common_parser.add_argument(
        "-o", "--output", 
        help="Output file path (default: stdout)"
    )
    
    # Project mode parser
    project_parser = subparsers.add_parser("project", help="Scan a project directory", parents=[common_parser])
    project_parser.add_argument("path", help="Path to the project directory or file")
    project_parser.add_argument(
        "-r", "--recursive", 
        action="store_true", 
        help="Scan subdirectories recursively"
    )
    
    # GitLab mode parser
    gitlab_parser = subparsers.add_parser("gitlab", help="Scan a GitLab merge request", parents=[common_parser])
    gitlab_parser.add_argument("project_dir", help="Path to the project directory")
    gitlab_parser.add_argument("source_branch", help="Source branch of the merge request")
    gitlab_parser.add_argument("target_branch", help="Target branch of the merge request")
    
    return parser.parse_args()

def write_output(results: Dict[str, Any], output_path: str = None):
    """Write results to output file or stdout"""
    output_json = json.dumps(results, indent=2, ensure_ascii=False)
    
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(output_json)
        print(f"Results written to {output_path}")
    else:
        print(output_json)

def main():
    """Main entry point"""
    args = parse_args()
    
    # Check if API key is set
    if not os.environ.get("DEEPSEEK_API_KEY"):
        print("Error: DEEPSEEK_API_KEY environment variable is not set")
        print("Please set it using: export DEEPSEEK_API_KEY=your_api_key")
        sys.exit(1)
    
    # Initialize LLM client
    llm_client = LLMClient()
    
    if args.mode == "project":
        # Project mode
        scanner = FileScanner(llm_client=llm_client, max_workers=args.workers)
        
        if os.path.isfile(args.path):
            # Scan a single file
            results = scanner.scan_file(args.path)
        else:
            # Scan a directory
            results = scanner.scan_directory(args.path, recursive=args.recursive)
        
        write_output(results, args.output)
    
    elif args.mode == "gitlab":
        # GitLab mode
        gitlab = GitLabIntegration(llm_client=llm_client, max_workers=args.workers)
        results = gitlab.scan_merge_request(
            args.project_dir, 
            args.source_branch, 
            args.target_branch
        )
        
        write_output(results, args.output)
    
    else:
        print("Error: No mode specified")
        print("Use 'project' or 'gitlab' mode")
        sys.exit(1)

if __name__ == "__main__":
    main() 