# CodeSheriff

A tool that uses LLM (Large Language Models) to detect potentially malicious code in files or GitLab merge requests.

## Features

- **Project Mode**: Scan a directory or file for malicious code
- **GitLab Mode**: Scan files changed in a GitLab merge request
- **Flexible LLM Support**: Works with various providers (OpenAI, DeepSeek, Anthropic), enterprise/internal deployments, and locally hosted servers
- Structured output with malicious probability and reasoning
- Support for multiple programming languages

## Project Structure

```
CodeSheriff/
├── core/                  # Core functionality
│   ├── llm_client.py      # LLM API client
│   └── file_scanner.py    # File scanning logic
├── integrations/          # External integrations
│   └── gitlab_integration.py  # GitLab MR integration
├── utils/                 # Utility modules
│   └── config.py          # Configuration handling
└── cli.py                 # Command-line interface
```

## Installation

### Using Virtual Environment (recommended)

1. Clone the repository:
   ```
   git clone https://github.com/Sle3pyC4t/CodeSheriff.git
   cd CodeSheriff
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the package in development mode:
   ```
   pip install -e .
   ```

4. Create a `.env` file from the template:
   ```
   cp env.example .env
   ```

5. Edit the `.env` file and add your API key:
   ```
   LLM_API_KEY=your_api_key_here
   ```

### Global Installation

1. Clone the repository:
   ```
   git clone https://github.com/Sle3pyC4t/CodeSheriff.git
   cd CodeSheriff
   ```

2. Install the package:
   ```
   pip install .
   ```

3. Create a `.env` file from the template:
   ```
   cp env.example .env
   ```

4. Edit the `.env` file and add your API key:
   ```
   LLM_API_KEY=your_api_key_here
   ```

## Usage

### Project Mode

Scan a single file:
```
code-sheriff project path/to/file.py
```

Scan a directory (non-recursive):
```
code-sheriff project path/to/directory
```

Scan a directory recursively:
```
code-sheriff project path/to/directory -r
```

Save results to a file:
```
code-sheriff project path/to/directory -r -o results.json
```

### GitLab Mode

Scan files changed in a merge request:
```
code-sheriff gitlab /path/to/repo source_branch target_branch
```

Save results to a file:
```
code-sheriff gitlab /path/to/repo source_branch target_branch -o results.json
```

### Using Different LLM Providers

You can specify a different LLM provider and model at runtime:

```
# Use OpenAI
code-sheriff project path/to/directory --provider openai --model gpt-4o --api-key your_api_key

# Use Anthropic
code-sheriff project path/to/directory --provider anthropic --model claude-3-opus-20240229

# Use a local LLM server
code-sheriff project path/to/directory --provider custom --model llama3 --api-url http://localhost:8000/v1/chat/completions
```

## Output Format

The tool outputs a JSON structure with the following format:

```json
{
  "summary": {
    "total_files": 10,
    "malicious_files": 1,
    "suspicious_files": 2,
    "clean_files": 6,
    "error_files": 1
  },
  "malicious_files": [
    {
      "file_path": "path/to/malicious.py",
      "probability": 0.95,
      "reasoning": "This file contains code that attempts to exfiltrate sensitive data...",
      "threats": ["data_exfiltration", "backdoor"]
    }
  ],
  "suspicious_files": [
    {
      "file_path": "path/to/suspicious.js",
      "probability": 0.6,
      "reasoning": "This file uses obfuscated code that might hide malicious intent..."
    }
  ],
  "clean_files": [
    {
      "file_path": "path/to/clean.py"
    }
  ],
  "error_files": [
    {
      "file_path": "path/to/error.bin",
      "error": "Unsupported file extension: .bin"
    }
  ]
}
```

## Supported File Extensions

By default, the tool supports the following file extensions:
- `.py` (Python)
- `.js` (JavaScript)
- `.ts` (TypeScript)
- `.php` (PHP)
- `.java` (Java)
- `.c` (C)
- `.cpp` (C++)
- `.cs` (C#)
- `.go` (Go)
- `.rb` (Ruby)
- `.pl` (Perl)
- `.sh` (Shell)
- `.ps1` (PowerShell)

You can modify the supported extensions in the `.env` file.

## Configuration

You can configure the tool by editing the `.env` file:

- `LLM_PROVIDER`: LLM provider to use (default: deepseek)
- `LLM_API_KEY`: Your API key for the selected provider
- `LLM_API_URL`: API URL for the selected provider
- `LLM_MODEL`: Model to use (e.g., deepseek-coder, gpt-4o, claude-3-opus-20240229)
- `MAX_CONCURRENT_REQUESTS`: Maximum number of concurrent API requests (default: 10)
- `MALICIOUS_THRESHOLD`: Threshold for malicious code probability (default: 0.7)
- `MAX_FILE_SIZE`: Maximum file size in bytes (default: 1000000)
- `SUPPORTED_EXTENSIONS`: Comma-separated list of supported file extensions

### Supported LLM Providers

The tool supports the following LLM providers:

- `openai`: OpenAI API (GPT models)
- `deepseek`: DeepSeek API (default)
- `anthropic`: Anthropic API (Claude models)
- `azure`: Azure OpenAI Service
- `custom`: Custom API endpoints (enterprise/internal LLMs)
- `local`: Locally hosted LLM servers 