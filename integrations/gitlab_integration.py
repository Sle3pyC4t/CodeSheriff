import os
import json
import subprocess
from typing import List, Dict, Any, Optional

from core.llm_client import LLMClient
from core.file_scanner import FileScanner

class GitLabIntegration:
    def __init__(self, llm_client: Optional[LLMClient] = None):
        """
        Initialize the GitLab integration
        
        Args:
            llm_client: LLM client instance (creates one if not provided)
        """
        self.llm_client = llm_client or LLMClient()
        self.file_scanner = FileScanner(llm_client=self.llm_client)
    
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
        
        # Scan each changed file
        results = []
        for file_path in changed_files:
            full_path = os.path.join(project_dir, file_path)
            if os.path.exists(full_path) and os.path.isfile(full_path):
                result = self.file_scanner.scan_file(full_path)
                results.append(result)
        
        # Aggregate results
        return self.file_scanner._aggregate_results(results)
    
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