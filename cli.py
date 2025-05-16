#!/usr/bin/env python3
import os
import sys
import json
import argparse
import logging
from typing import Dict, Any

from core.llm_client import LLMClient
from core.file_scanner import FileScanner
from integrations.gitlab_integration import GitLabIntegration
from utils import config

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
        "-c", "--concurrent-requests",
        type=int,
        default=None,
        help=f"Maximum number of concurrent API requests (default: {config.MAX_CONCURRENT_REQUESTS})"
    )
    common_parser.add_argument(
        "-o", "--output", 
        help="Output file path (default: stdout)"
    )
    common_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    common_parser.add_argument(
        "-d", "--debug",
        action="store_true",
        help="Enable debug mode with detailed logging"
    )
    common_parser.add_argument(
        "--provider",
        default=None,
        help=f"LLM provider to use (default: {config.LLM_PROVIDER}). Options: openai, deepseek, anthropic, azure, custom, local, etc."
    )
    common_parser.add_argument(
        "--model",
        default=None,
        help=f"LLM model to use (default: {config.LLM_MODEL})"
    )
    common_parser.add_argument(
        "--api-key",
        default=None,
        help="LLM API key (default: from environment variables)"
    )
    common_parser.add_argument(
        "--api-url",
        default=None,
        help="LLM API URL (default: from environment variables)"
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

def setup_logging(debug=False, verbose=False):
    """设置日志级别"""
    # 默认设置为WARNING级别
    logging.getLogger().setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("LiteLLM").setLevel(logging.WARNING)
    
    if debug:
        logging.getLogger("CodeSheriff").setLevel(logging.DEBUG)
        # 开启LiteLLM的调试模式
        import litellm
        litellm.set_verbose = True
        litellm._turn_on_debug()
    elif verbose:
        logging.getLogger("CodeSheriff").setLevel(logging.INFO)
    else:
        logging.getLogger("CodeSheriff").setLevel(logging.WARNING)

def main():
    """Main entry point"""
    args = parse_args()
    
    # 设置日志级别
    setup_logging(debug=args.debug, verbose=args.verbose)
    
    logger = logging.getLogger("CodeSheriff")
    
    # Check if API key is set
    api_key = args.api_key or config.LLM_API_KEY
    provider = args.provider or config.LLM_PROVIDER
    
    if not api_key and provider not in ['local', 'custom']:
        logger.error(f"Error: API key for {provider} is not set")
        print(f"Error: API key for {provider} is not set")
        print(f"Please set it using: export LLM_API_KEY=your_api_key or {provider.upper()}_API_KEY=your_api_key")
        print("Or provide it using the --api-key option")
        sys.exit(1)
    
    # Override the MAX_CONCURRENT_REQUESTS if specified
    if args.concurrent_requests is not None:
        config.MAX_CONCURRENT_REQUESTS = args.concurrent_requests
    
    # Determine the number of worker threads
    max_workers = args.workers or min(32, os.cpu_count() + 4)
    
    # Print configuration if verbose
    if args.verbose or args.debug:
        logger.info(f"Configuration:")
        logger.info(f"  - Provider: {args.provider or config.LLM_PROVIDER}")
        logger.info(f"  - Model: {args.model or config.LLM_MODEL}")
        logger.info(f"  - API URL: {args.api_url or config.LLM_API_URL}")
        logger.info(f"  - Worker threads: {max_workers}")
        logger.info(f"  - Concurrent API requests: {config.MAX_CONCURRENT_REQUESTS}")
        logger.info(f"  - Malicious threshold: {config.MALICIOUS_THRESHOLD}")
        logger.info(f"  - Max file size: {config.MAX_FILE_SIZE} bytes")
        logger.info(f"  - Supported extensions: {', '.join(config.SUPPORTED_EXTENSIONS)}")
        logger.info(f"  - Debug mode: {args.debug}")
    
    # Initialize LLM client
    llm_client = LLMClient(
        api_key=args.api_key,
        api_url=args.api_url,
        model=args.model,
        provider=args.provider,
        verbose=args.verbose or args.debug
    )
    
    if args.mode == "project":
        # Project mode
        scanner = FileScanner(llm_client=llm_client, max_workers=max_workers)
        
        if os.path.isfile(args.path):
            # Scan a single file
            if args.verbose or args.debug:
                logger.info(f"Scanning file: {args.path}")
            results = scanner.scan_file(args.path)
        else:
            # Scan a directory
            if args.verbose or args.debug:
                logger.info(f"Scanning directory: {args.path} (recursive: {args.recursive})")
            results = scanner.scan_directory(args.path, recursive=args.recursive)
        
        write_output(results, args.output)
    
    elif args.mode == "gitlab":
        # GitLab mode
        gitlab = GitLabIntegration(llm_client=llm_client, max_workers=max_workers)
        if args.verbose or args.debug:
            logger.info(f"Scanning merge request:")
            logger.info(f"  - Project directory: {args.project_dir}")
            logger.info(f"  - Source branch: {args.source_branch}")
            logger.info(f"  - Target branch: {args.target_branch}")
        results = gitlab.scan_merge_request(
            args.project_dir, 
            args.source_branch, 
            args.target_branch
        )
        
        write_output(results, args.output)
    
    else:
        logger.error("Error: No mode specified")
        print("Error: No mode specified")
        print("Use 'project' or 'gitlab' mode")
        sys.exit(1)

if __name__ == "__main__":
    main() 