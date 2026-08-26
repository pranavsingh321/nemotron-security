# Nemotron Security Analyzer

AI-powered security analysis for Python codebases using NVIDIA Nemotron via Ollama. Runs locally — no data leaves your machine.

## Requirements

- [Ollama](https://ollama.com) installed
- Python 3.10+
- Optional: `semgrep`, `bandit`, `trivy` for enhanced scanning

## Quick Start

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model (pick one)
ollama pull nemotron-mini    # fast, 8B params (default)
ollama pull nemotron:70b     # better quality, needs ~40GB RAM
ollama pull llama3.1:8b      # alternative if nemotron unavailable

# Clone and run
git clone <repo-url> ~/nemotron-security
cd ~/nemotron-security
chmod +x analyze.sh

# Analyze a repo
./analyze.sh ~/repos/nova
```

## Usage

```bash
# Basic analysis (all .py files, excluding tests)
./analyze.sh ~/repos/my-project

# Use a larger model for better results
./analyze.sh ~/repos/my-project --model nemotron:70b

# Focus on specific directories
./analyze.sh ~/repos/my-project --focus api,compute

# Custom output location
./analyze.sh ~/repos/my-project --output /tmp/security-report.md

# Also run semgrep + bandit + trivy, then triage with AI
./analyze.sh ~/repos/my-project --scanners

# Combine all options
./analyze.sh ~/repos/nova --model nemotron:70b --focus api,compute --scanners --output ~/reports/nova-security.md
```

## How It Works

```
Target Repo
    │
    ├── [optional] Scanner Phase
    │   ├── semgrep (pattern-based vulns)
    │   ├── bandit (Python security linting)
    │   └── trivy (dependency CVEs)
    │   │
    │   └── AI triages scanner results
    │       → true positive / false positive
    │       → priority ranking
    │
    └── AI Code Review Phase
        ├── Collects .py files (excludes tests)
        ├── Sends each file to Nemotron
        └── Reports: type, severity, line, fix
```

## Models

| Model | Size | RAM | Speed | Quality |
|-------|------|-----|-------|---------|
| `nemotron-mini` | 8B | 8GB | Fast | Good |
| `nemotron:70b` | 70B | 40GB | Slow | Best |
| `llama3.1:8b` | 8B | 8GB | Fast | Good |
| `codellama:13b` | 13B | 16GB | Medium | Good |

```bash
# Check available models
ollama list

# Pull a new model
ollama pull <model-name>

# Remove a model
ollama rm <model-name>
```

## Output

Reports are saved to `reports/<project-name>/` by default:

```markdown
# Security Analysis: nova

## Scanner Triage
(Cross-references semgrep/bandit/trivy findings)

## AI Code Review

### nova/api/openstack/compute/servers.py
- Type: SQL injection
- Severity: CRITICAL
- Line: 142
- Exploitation: Easy
- Fix: Use parameterized queries...

### nova/compute/manager.py
- No security issues found.
```

## Integration with Banneker

```bash
# Run banneker pipeline + security analysis
cd ~/repos/banneker
TARGET_DIR=~/repos/nova MINIMAL=true ./banneker-pipeline.sh
./analyze.sh ~/repos/nova --scanners --focus api,compute
```

## Manual Ollama Usage

```bash
# Interactive chat
ollama run nemotron-mini

# Single prompt
ollama run nemotron-mini "Review this code for SQL injection: $(cat file.py)"

# Pipe content
cat file.py | ollama run nemotron-mini "Find security vulnerabilities in this code"

# API (runs in background)
curl http://localhost:11434/api/generate -d '{
  "model": "nemotron-mini",
  "prompt": "Review for security issues",
  "stream": false
}'
```

## Troubleshooting

**Ollama not starting:**
```bash
ollama serve  # starts on port 11434
```

**Model too large for RAM:**
```bash
# Use the smaller model
ollama pull nemotron-mini
./analyze.sh ~/repos/nova --model nemotron-mini
```

**Slow analysis:**
```bash
# Focus on specific dirs instead of entire repo
./analyze.sh ~/repos/nova --focus api

# Or reduce file count
find ~/repos/nova/nova -name "*.py" -not -path "*/test*" | head -20 | xargs -I{} ollama run nemotron-mini "Security review: $(cat {})"
```
