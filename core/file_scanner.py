import os
import sys
from typing import List, Dict, Any, Generator, Tuple
from pathlib import Path
from tqdm import tqdm
import concurrent.futures
from threading import Lock

from utils import config
from core.llm_client import LLMClient

class FileScanner:
    def __init__(self, llm_client: LLMClient = None, max_workers: int = None):
        """
        Initialize the file scanner
        
        Args:
            llm_client: LLM client instance (creates one if not provided)
            max_workers: Maximum number of worker threads (defaults to number of processors)
        """
        self.llm_client = llm_client or LLMClient()
        self.max_workers = max_workers or min(32, os.cpu_count() + 4)
        self.progress_lock = Lock()
        
    def scan_directory(self, directory_path: str, recursive: bool = True) -> Dict[str, Any]:
        """
        Scan a directory for malicious code
        
        Args:
            directory_path: Path to the directory to scan
            recursive: Whether to scan subdirectories recursively
            
        Returns:
            Dict with scan results
        """
        directory_path = os.path.abspath(directory_path)
        
        if not os.path.exists(directory_path):
            return {"error": f"Directory not found: {directory_path}"}
        
        if not os.path.isdir(directory_path):
            return {"error": f"Not a directory: {directory_path}"}
        
        # Get all files to scan
        files_to_scan = list(self._get_files_to_scan(directory_path, recursive))
        
        if not files_to_scan:
            return {"error": "No supported files found to scan"}
        
        # Scan files in parallel
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Create a shared progress bar
            progress = tqdm(total=len(files_to_scan), desc="Scanning files", file=sys.stdout)
            
            # Submit all scan tasks
            future_to_file = {executor.submit(self._scan_file_with_progress, file_path, progress): file_path 
                             for file_path in files_to_scan}
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_file):
                result = future.result()
                results.append(result)
                
            progress.close()
        
        # Aggregate results
        return self._aggregate_results(results)
    
    def _scan_file_with_progress(self, file_path: str, progress: tqdm) -> Dict[str, Any]:
        """Scan a file and update the progress bar"""
        result = self.scan_file(file_path)
        with self.progress_lock:
            progress.update(1)
        return result
    
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """
        Scan a single file for malicious code
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            Dict with scan results for the file
        """
        file_path = os.path.abspath(file_path)
        
        if not os.path.exists(file_path):
            return {
                "file_path": file_path,
                "error": "File not found"
            }
        
        if not os.path.isfile(file_path):
            return {
                "file_path": file_path,
                "error": "Not a file"
            }
        
        # Check file size
        if os.path.getsize(file_path) > config.MAX_FILE_SIZE:
            return {
                "file_path": file_path,
                "error": f"File too large (max size: {config.MAX_FILE_SIZE} bytes)"
            }
        
        # Check file extension
        _, ext = os.path.splitext(file_path)
        if ext not in config.SUPPORTED_EXTENSIONS:
            return {
                "file_path": file_path,
                "error": f"Unsupported file extension: {ext}"
            }
        
        try:
            # Read file content
            with open(file_path, "r", encoding="utf-8") as f:
                code = f.read()
            
            # Analyze the code
            analysis = self.llm_client.analyze_code(code, file_path)
            
            # Return the result
            return {
                "file_path": file_path,
                "analysis": analysis
            }
        except Exception as e:
            return {
                "file_path": file_path,
                "error": str(e)
            }
    
    def _get_files_to_scan(self, directory_path: str, recursive: bool) -> Generator[str, None, None]:
        """
        Get all files to scan in the directory
        
        Args:
            directory_path: Path to the directory
            recursive: Whether to scan subdirectories recursively
            
        Yields:
            Paths of files to scan
        """
        for root, dirs, files in os.walk(directory_path):
            if not recursive and root != directory_path:
                continue
                
            for file in files:
                file_path = os.path.join(root, file)
                _, ext = os.path.splitext(file_path)
                
                # Skip files that are too large or have unsupported extensions
                if (ext in config.SUPPORTED_EXTENSIONS and 
                    os.path.getsize(file_path) <= config.MAX_FILE_SIZE):
                    yield file_path
    
    def _aggregate_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Aggregate scan results
        
        Args:
            results: List of scan results
            
        Returns:
            Dict with aggregated results
        """
        malicious_files = []
        suspicious_files = []
        clean_files = []
        error_files = []
        
        for result in results:
            file_path = result.get("file_path", "unknown")
            
            if "error" in result:
                error_files.append({
                    "file_path": file_path,
                    "error": result["error"]
                })
                continue
            
            analysis = result.get("analysis", {})
            
            if analysis.get("is_malicious", False):
                malicious_files.append({
                    "file_path": file_path,
                    "probability": analysis.get("malicious_probability", 1.0),
                    "reasoning": analysis.get("reasoning", ""),
                    "threats": analysis.get("identified_threats", [])
                })
            elif analysis.get("malicious_probability", 0) >= config.MALICIOUS_THRESHOLD / 2:
                suspicious_files.append({
                    "file_path": file_path,
                    "probability": analysis.get("malicious_probability", 0.0),
                    "reasoning": analysis.get("reasoning", "")
                })
            else:
                clean_files.append({
                    "file_path": file_path
                })
        
        return {
            "summary": {
                "total_files": len(results),
                "malicious_files": len(malicious_files),
                "suspicious_files": len(suspicious_files),
                "clean_files": len(clean_files),
                "error_files": len(error_files)
            },
            "malicious_files": sorted(malicious_files, key=lambda x: x["probability"], reverse=True),
            "suspicious_files": sorted(suspicious_files, key=lambda x: x["probability"], reverse=True),
            "clean_files": clean_files,
            "error_files": error_files
        } 