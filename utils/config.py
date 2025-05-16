import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# LLM API configuration
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "deepseek")  # Provider name: openai, deepseek, anthropic, azure, custom, local, etc.
LLM_API_KEY = os.getenv("LLM_API_KEY")  # API key for the selected provider
LLM_API_URL = os.getenv("LLM_API_URL")  # API URL for the selected provider
LLM_MODEL = os.getenv("LLM_MODEL", "deepseek-coder")  # Model name
MAX_CONCURRENT_REQUESTS = int(os.getenv("MAX_CONCURRENT_REQUESTS", "10"))  # Default to 10 concurrent requests

# Code analysis thresholds
MALICIOUS_THRESHOLD = float(os.getenv("MALICIOUS_THRESHOLD", "0.7"))  # Probability threshold for malicious code

# File processing settings
MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", "1000000"))  # 1MB
SUPPORTED_EXTENSIONS = os.getenv("SUPPORTED_EXTENSIONS", ".py,.js,.ts,.php,.java,.c,.cpp,.cs,.go,.rb,.pl,.sh,.ps1").split(",") 