# CodeSheriff

A tool that uses LLM (Large Language Models) to detect potentially malicious code in files or GitLab merge requests.

## Features

- **Project Mode**: Scan a directory or file for malicious code
- **GitLab Mode**: Scan files changed in a GitLab merge request
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
   git clone https://github.com/yourusername/CodeSheriff.git
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

5. Edit the `.env` file and add your DeepSeek API key:
   ```
   DEEPSEEK_API_KEY=your_api_key_here
   ```

### Global Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/CodeSheriff.git
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

4. Edit the `.env` file and add your DeepSeek API key:
   ```
   DEEPSEEK_API_KEY=your_api_key_here
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

- `DEEPSEEK_API_KEY`: Your DeepSeek API key
- `DEEPSEEK_API_URL`: DeepSeek API URL (default: https://api.deepseek.com/v1/chat/completions)
- `MODEL_NAME`: Model to use (default: deepseek-coder)
- `MALICIOUS_THRESHOLD`: Threshold for malicious code probability (default: 0.7)
- `MAX_FILE_SIZE`: Maximum file size in bytes (default: 1000000)
- `SUPPORTED_EXTENSIONS`: Comma-separated list of supported file extensions 