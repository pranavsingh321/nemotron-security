# Nemotron Security Analyzer

AI-powered security analysis for Python codebases. Works with local Ollama or remote litellm proxy.

## Requirements

- Python 3.10+
- `pip install openai`
- One of:
  - [Ollama](https://ollama.com) (local, `analyze.sh`)
  - litellm proxy (remote, `analyze.py`)
- Optional: `semgrep`, `bandit`, `trivy`

## Quick Start

### Option A: Local Ollama (analyze.sh)

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull nemotron-3.5-lightning
./analyze.sh ~/repos/nova
```

### Option B: litellm proxy (analyze.py)

```bash
pip install openai
export LITELLM_HOST=http://<your-litellm-host>:4000
python3 analyze.py ~/repos/nova
```

## Usage

```bash
# analyze.sh (Ollama)
./analyze.sh ~/repos/nova
./analyze.sh ~/repos/nova --model nemotron:70b --focus api,compute

# analyze.py (litellm proxy)
export LITELLM_HOST=http://192.168.1.100:4000
python3 analyze.py ~/repos/nova
python3 analyze.py ~/repos/nova --model openai/gpt-4o
python3 analyze.py ~/repos/nova --model ollama/nemotron-3.5-lightning
python3 analyze.py ~/repos/nova --focus api --scanners --output ~/report.md
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LITELLM_HOST` | `http://localhost:4000` | litellm proxy URL (analyze.py only) |

## Model Selection

### Via Ollama (analyze.sh)

```bash
./analyze.sh ~/repos/nova --model nemotron-3.5-lightning  # default
./analyze.sh ~/repos/nova --model nemotron-mini
./analyze.sh ~/repos/nova --model nemotron:70b
```

### Via litellm proxy (analyze.py)

Model names depend on your litellm config. Common patterns:

```bash
# Ollama models through litellm
python3 analyze.py ~/repos/nova --model ollama/nemotron-3.5-lightning
python3 analyze.py ~/repos/nova --model ollama/nemotron-mini

# OpenAI through litellm
python3 analyze.py ~/repos/nova --model openai/gpt-4o
python3 analyze.py ~/repos/nova --model openai/gpt-4o-mini

# Anthropic through litellm
python3 analyze.py ~/repos/nova --model anthropic/claude-sonnet-4-20250514
```

Check your litellm config for available model names.

## litellm Proxy Setup

If you don't have a litellm proxy yet, here's how to set one up:

```bash
# Install litellm
pip install litellm[proxy]

# Run with Ollama backend
litellm --model ollama/nemotron-3.5-lightning --port 4000

# Run with multiple backends (config.yaml)
litellm --config config.yaml --port 4000
```

Example `config.yaml`:
```yaml
model_list:
  - model_name: nemotron-3.5-lightning
    litellm_params:
      model: ollama/nemotron-3.5-lightning
  - model_name: gpt-4o
    litellm_params:
      model: openai/gpt-4o
      api_key: os.environ/OPENAI_API_KEY
  - model_name: claude
    litellm_params:
      model: anthropic/claude-sonnet-4-20250514
      api_key: os.environ/ANTHROPIC_API_KEY
```

## How It Works

```
Target Repo
    │
    ├── [optional] Scanner Phase (--scanners)
    │   ├── semgrep, bandit, trivy
    │   └── AI triages findings → true/false positive
    │
    └── AI Code Review Phase
        ├── Collects .py files (excludes tests)
        ├── Sends each file to model
        └── Reports: type, severity, line, fix
```

## Output

Reports saved to `reports/<project-name>/` by default:

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
```
