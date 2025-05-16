import json
import requests
from typing import Dict, Any, Optional
import threading
import os

from utils import config

class LLMClient:
    def __init__(self, api_key: Optional[str] = None, api_url: Optional[str] = None, verbose: bool = False):
        """
        Initialize the LLM client
        
        Args:
            api_key: DeepSeek API key (defaults to config)
            api_url: DeepSeek API URL (defaults to config)
            verbose: Whether to print verbose output
        """
        self.api_key = api_key or config.DEEPSEEK_API_KEY
        self.api_url = api_url or config.DEEPSEEK_API_URL
        self.verbose = verbose
        
        # Semaphore to limit concurrent API requests
        self.request_semaphore = threading.Semaphore(config.MAX_CONCURRENT_REQUESTS)
        
        # Counter for active requests
        self.active_requests = 0
        self.counter_lock = threading.Lock()
        
        if not self.api_key:
            raise ValueError("DeepSeek API key is required. Set DEEPSEEK_API_KEY in .env file or pass it directly.")
    
    def analyze_code(self, code: str, file_path: str) -> Dict[str, Any]:
        """
        Analyze code to determine if it's malicious
        
        Args:
            code: The code content to analyze
            file_path: Path to the file (for context)
            
        Returns:
            Dict with analysis results including malicious probability and reasoning
        """
        # Prepare the prompt for malicious code detection
        prompt = self._create_malicious_code_prompt(code, file_path)
        
        # Call the DeepSeek API
        response = self._call_api(prompt, file_path)
        
        # Parse the response
        return self._parse_response(response)
    
    def _create_malicious_code_prompt(self, code: str, file_path: str) -> str:
        """Create a prompt for malicious code detection"""
        return f"""You are a security expert analyzing code for malicious intent.
        
Please analyze the following code from file '{file_path}' and determine if it contains malicious code.
Malicious code includes but is not limited to: backdoors, data exfiltration, encryption for ransomware,
system manipulation without consent, obfuscated harmful functionality, etc.

CODE TO ANALYZE:
```
{code}
```

Provide your analysis in the following JSON format:
{{
    "is_malicious": true/false,
    "malicious_probability": 0.0-1.0,
    "reasoning": "detailed explanation of why the code is or isn't considered malicious",
    "identified_threats": ["list", "of", "specific", "threats", "if", "any"]
}}

Only respond with valid JSON. Do not include any other text in your response.
"""
    
    def _call_api(self, prompt: str, file_path: str) -> Dict[str, Any]:
        """Call the DeepSeek API with the given prompt"""
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        
        payload = {
            "model": config.MODEL_NAME,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.1,  # Low temperature for more deterministic responses
            "response_format": {"type": "json_object"}
        }
        
        # Use a semaphore to limit concurrent API requests
        with self.request_semaphore:
            # Update active requests counter
            with self.counter_lock:
                self.active_requests += 1
                current_active = self.active_requests
            
            # Print debug info if verbose
            if self.verbose:
                filename = os.path.basename(file_path)
                print(f"[Thread {threading.current_thread().name}] Analyzing {filename} (Active requests: {current_active}/{config.MAX_CONCURRENT_REQUESTS})")
            
            try:
                # Use a session for better connection reuse
                session = requests.Session()
                response = session.post(self.api_url, headers=headers, json=payload)
                response.raise_for_status()
                return response.json()
            finally:
                # Update active requests counter
                with self.counter_lock:
                    self.active_requests -= 1
    
    def _parse_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Parse the API response to extract the analysis results"""
        try:
            # Extract content from the response
            content = response.get("choices", [{}])[0].get("message", {}).get("content", "{}")
            
            # Parse the JSON content
            result = json.loads(content)
            
            # Ensure the result has the expected format
            if not all(key in result for key in ["is_malicious", "malicious_probability", "reasoning"]):
                raise ValueError("Invalid response format")
            
            return result
        except (json.JSONDecodeError, KeyError, IndexError) as e:
            # Return an error response if parsing fails
            return {
                "is_malicious": False,
                "malicious_probability": 0.0,
                "reasoning": f"Error parsing LLM response: {str(e)}",
                "error": True
            } 