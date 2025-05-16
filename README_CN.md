# CodeSheriff 代码警长

一个使用大型语言模型（LLM）来检测文件或GitLab合并请求中潜在恶意代码的工具。

## 功能特点

- **项目模式**：扫描目录或文件中的恶意代码
- **GitLab模式**：扫描GitLab合并请求中更改的文件
- **灵活的LLM支持**：支持多种提供商（OpenAI、DeepSeek、Anthropic），企业/内部部署，以及本地托管服务器
- 结构化输出，包含恶意概率和判断理由
- 支持多种编程语言

## 项目结构

```
CodeSheriff/
├── core/                  # 核心功能
│   ├── llm_client.py      # LLM API客户端
│   └── file_scanner.py    # 文件扫描逻辑
├── integrations/          # 外部集成
│   └── gitlab_integration.py  # GitLab合并请求集成
├── utils/                 # 工具模块
│   └── config.py          # 配置处理
└── cli.py                 # 命令行界面
```

## 安装方法

### 使用虚拟环境（推荐）

1. 克隆仓库：
   ```
   git clone https://github.com/Sle3pyC4t/CodeSheriff.git
   cd CodeSheriff
   ```

2. 创建并激活虚拟环境：
   ```
   python -m venv venv
   source venv/bin/activate  # Windows系统：venv\Scripts\activate
   ```

3. 以开发模式安装包：
   ```
   pip install -e .
   ```

4. 从模板创建`.env`文件：
   ```
   cp env.example .env
   ```

5. 编辑`.env`文件并添加你的API密钥：
   ```
   LLM_API_KEY=your_api_key_here
   ```

### 全局安装

1. 克隆仓库：
   ```
   git clone https://github.com/Sle3pyC4t/CodeSheriff.git
   cd CodeSheriff
   ```

2. 安装包：
   ```
   pip install .
   ```

3. 从模板创建`.env`文件：
   ```
   cp env.example .env
   ```

4. 编辑`.env`文件并添加你的API密钥：
   ```
   LLM_API_KEY=your_api_key_here
   ```

## 使用方法

### 项目模式

扫描单个文件：
```
code-sheriff project path/to/file.py
```

扫描目录（非递归）：
```
code-sheriff project path/to/directory
```

递归扫描目录：
```
code-sheriff project path/to/directory -r
```

将结果保存到文件：
```
code-sheriff project path/to/directory -r -o results.json
```

### GitLab模式

扫描合并请求中更改的文件：
```
code-sheriff gitlab /path/to/repo source_branch target_branch
```

将结果保存到文件：
```
code-sheriff gitlab /path/to/repo source_branch target_branch -o results.json
```

### 使用不同的LLM提供商

你可以在运行时指定不同的LLM提供商和模型：

```
# 使用OpenAI
code-sheriff project path/to/directory --provider openai --model gpt-4o --api-key your_api_key

# 使用Anthropic
code-sheriff project path/to/directory --provider anthropic --model claude-3-opus-20240229

# 使用本地LLM服务器
code-sheriff project path/to/directory --provider custom --model llama3 --api-url http://localhost:8000/v1/chat/completions
```

## 输出格式

该工具输出具有以下格式的JSON结构：

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

## 支持的文件扩展名

默认情况下，该工具支持以下文件扩展名：
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

你可以在`.env`文件中修改支持的扩展名。

## 配置

你可以通过编辑`.env`文件来配置该工具：

- `LLM_PROVIDER`：LLM提供商（默认：deepseek）
- `LLM_API_KEY`：你的API密钥
- `LLM_API_URL`：API URL（默认：https://api.deepseek.com/v1/chat/completions）
- `LLM_MODEL`：使用的模型（默认：deepseek-coder）
- `MAX_CONCURRENT_REQUESTS`：最大并发API请求数（默认：10）
- `MALICIOUS_THRESHOLD`：恶意代码概率阈值（默认：0.7）
- `MAX_FILE_SIZE`：最大文件大小（字节）（默认：1000000）
- `SUPPORTED_EXTENSIONS`：支持的文件扩展名，以逗号分隔

### 支持的LLM提供商

该工具支持以下LLM提供商：

- `openai`：OpenAI API（GPT模型）
- `deepseek`：DeepSeek API（默认）
- `anthropic`：Anthropic API（Claude模型）
- `azure`：Azure OpenAI服务
- `custom`：自定义API端点（企业/内部LLMs）
- `local`：本地托管的LLM服务器 