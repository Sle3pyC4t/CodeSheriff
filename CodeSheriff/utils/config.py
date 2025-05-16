import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# DeepSeek API configuration
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
DEEPSEEK_API_URL = os.getenv("DEEPSEEK_API_URL", "https://api.deepseek.com/v1/chat/completions")

# Model configuration
MODEL_NAME = os.getenv("MODEL_NAME", "deepseek-coder")

# Code analysis thresholds
MALICIOUS_THRESHOLD = float(os.getenv("MALICIOUS_THRESHOLD", "0.7"))  # Probability threshold for malicious code

# File processing settings
MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", "1000000"))  # 1MB
SUPPORTED_EXTENSIONS = os.getenv("SUPPORTED_EXTENSIONS", ".py,.js,.ts,.php,.java,.c,.cpp,.cs,.go,.rb,.pl,.sh,.ps1").split(",") 