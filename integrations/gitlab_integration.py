import os
import json
import subprocess
from typing import List, Dict, Any, Optional
import concurrent.futures
from tqdm import tqdm
import sys
from threading import Lock

from core.llm_client import LLMClient
from core.file_scanner import FileScanner

class GitLabIntegration:
    def __init__(self, llm_client: Optional[LLMClient] = None, max_workers: int = None):
        """
        Initialize the GitLab integration
        
        Args:
            llm_client: LLM client instance (creates one if not provided)
            max_workers: Maximum number of worker threads (defaults to number of processors)
        """
        self.llm_client = llm_client or LLMClient()
        self.file_scanner = FileScanner(llm_client=self.llm_client)
        self.max_workers = max_workers or min(32, os.cpu_count() + 4)
        self.progress_lock = Lock()
    
    def scan_merge_request(self, 
                           project_dir: str, 
                           source_branch: str, 
                           target_branch: str) -> Dict[str, Any]:
        """
        Scan a merge request for malicious code
        
        Args:
            project_dir: Path to the project directory
            source_branch: Source branch of the merge request
            target_branch: Target branch of the merge request
            
        Returns:
            Dict with scan results
        """
        # Get the changed files in the merge request
        changed_files = self._get_changed_files(project_dir, source_branch, target_branch)
        
        if not changed_files:
            return {
                "summary": {
                    "total_files": 0,
                    "malicious_files": 0,
                    "suspicious_files": 0,
                    "clean_files": 0,
                    "error_files": 0
                },
                "message": "No files changed in this merge request"
            }
        
        # Scan files in parallel
        results = []
        valid_files = [os.path.join(project_dir, file_path) for file_path in changed_files 
                      if os.path.exists(os.path.join(project_dir, file_path)) and 
                      os.path.isfile(os.path.join(project_dir, file_path))]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Create a shared progress bar
            progress = tqdm(total=len(valid_files), desc="Scanning files", file=sys.stdout)
            
            # Submit all scan tasks
            future_to_file = {executor.submit(self._scan_file_with_progress, file_path, progress): file_path 
                             for file_path in valid_files}
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_file):
                result = future.result()
                results.append(result)
                
            progress.close()
        
        # Aggregate results
        return self.file_scanner._aggregate_results(results)
    
    def _scan_file_with_progress(self, file_path: str, progress: tqdm) -> Dict[str, Any]:
        """Scan a file and update the progress bar"""
        result = self.file_scanner.scan_file(file_path)
        with self.progress_lock:
            progress.update(1)
        return result
    
    def _get_changed_files(self, project_dir: str, source_branch: str, target_branch: str) -> List[str]:
        """
        Get the changed files in a merge request
        
        Args:
            project_dir: Path to the project directory
            source_branch: Source branch of the merge request
            target_branch: Target branch of the merge request
            
        Returns:
            List of changed file paths
        """
        try:
            # Change to the project directory
            original_dir = os.getcwd()
            os.chdir(project_dir)
            
            # Get the changed files using git diff
            cmd = ["git", "diff", "--name-only", f"{target_branch}...{source_branch}"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            # Return to the original directory
            os.chdir(original_dir)
            
            # Parse the result
            changed_files = [file.strip() for file in result.stdout.split("\n") if file.strip()]
            return changed_files
        except subprocess.CalledProcessError as e:
            print(f"Error getting changed files: {e}")
            return []
        except Exception as e:
            print(f"Unexpected error: {e}")
            return [] 