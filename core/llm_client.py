import json
import os
import threading
import logging
from typing import Dict, Any, Optional, List

import litellm
from litellm import completion

from utils import config

# 设置日志记录
logging.basicConfig(level=logging.WARNING, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("CodeSheriff")

class LLMClient:
    """
    A client for interacting with various LLM APIs using litellm as the adapter.
    Supports various providers including OpenAI, DeepSeek, Azure, Anthropic, etc.
    Also supports custom/enterprise LLM deployments.
    """
    
    def __init__(self, 
                 api_key: Optional[str] = None, 
                 api_url: Optional[str] = None, 
                 model: Optional[str] = None,
                 provider: Optional[str] = None,
                 verbose: bool = False):
        """
        Initialize the LLM client
        
        Args:
            api_key: API key (defaults to config)
            api_url: API URL (defaults to config)
            model: Model name (defaults to config)
            provider: Provider name (defaults to config)
            verbose: Whether to print verbose output
        """
        self.api_key = api_key or config.LLM_API_KEY
        self.api_url = api_url or config.LLM_API_URL
        self.model = model or config.LLM_MODEL
        self.provider = provider or config.LLM_PROVIDER
        self.verbose = verbose
        
        # 配置LiteLLM
        litellm.set_verbose = False  # 关闭LiteLLM的详细输出
        litellm.suppress_debug_info = True  # 抑制调试信息
        
        # Semaphore to limit concurrent API requests
        self.request_semaphore = threading.Semaphore(config.MAX_CONCURRENT_REQUESTS)
        
        # Counter for active requests
        self.active_requests = 0
        self.counter_lock = threading.Lock()
        
        if not self.api_key and self.provider not in ['local', 'custom']:
            raise ValueError(f"API key is required for provider {self.provider}. Set LLM_API_KEY in .env file or pass it directly.")
        
        if self.verbose:
            logger.info(f"Initialized LLM client with provider: {self.provider}, model: {self.model}")
            if self.api_url:
                logger.info(f"Using custom API URL: {self.api_url}")
    
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
        
        # Call the LLM API
        try:
            response = self._call_api(prompt, file_path)
            # Parse the response
            return self._parse_response(response)
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {str(e)}")
            return {
                "is_malicious": False,
                "malicious_probability": 0.0,
                "reasoning": f"Error analyzing code: {str(e)}",
                "error": True
            }
    
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
        """Call the LLM API with the given prompt"""
        # Use a semaphore to limit concurrent API requests
        with self.request_semaphore:
            # Update active requests counter
            with self.counter_lock:
                self.active_requests += 1
                current_active = self.active_requests
            
            # Print debug info if verbose
            if self.verbose:
                filename = os.path.basename(file_path)
                print(f"[Thread {threading.current_thread().name}] Analyzing {filename} with {self.model} (Active requests: {current_active}/{config.MAX_CONCURRENT_REQUESTS})")
            
            try:
                # Prepare the messages
                messages = [{"role": "user", "content": prompt}]
                
                # 构建模型名称
                if self.provider in ['custom', 'local']:
                    model_name = self.model
                else:
                    model_name = self.model  # 直接使用模型名称，不要加上提供商前缀
                
                # 准备API调用参数
                params = {
                    "model": model_name,
                    "messages": messages,
                    "temperature": 0.1,
                    "response_format": {"type": "json_object"}
                }
                
                # 添加API URL和密钥（如果有）
                if self.api_url:
                    params["api_base"] = self.api_url
                if self.api_key:
                    params["api_key"] = self.api_key
                
                if self.verbose:
                    logger.info(f"Calling {model_name} API for file: {os.path.basename(file_path)}")
                
                # 调用API
                response = completion(**params)
                
                if self.verbose:
                    logger.info(f"Received response for file: {os.path.basename(file_path)}")
                
                return response
            except Exception as e:
                logger.error(f"API call error for {os.path.basename(file_path)}: {str(e)}")
                raise
            finally:
                # Update active requests counter
                with self.counter_lock:
                    self.active_requests -= 1
    
    def _parse_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Parse the API response to extract the analysis results"""
        try:
            # Extract content from the response
            content = response.choices[0].message.content
            
            # Parse the JSON content
            result = json.loads(content)
            
            # Ensure the result has the expected format
            if not all(key in result for key in ["is_malicious", "malicious_probability", "reasoning"]):
                raise ValueError("Invalid response format")
            
            return result
        except (json.JSONDecodeError, KeyError, IndexError, AttributeError) as e:
            # Return an error response if parsing fails
            logger.error(f"Error parsing LLM response: {str(e)}")
            return {
                "is_malicious": False,
                "malicious_probability": 0.0,
                "reasoning": f"Error parsing LLM response: {str(e)}",
                "error": True
            } 