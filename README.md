# Nemotron Security Analyzer

AI-powered security analysis for Python codebases. Uses opencode or litellm proxy.

## Requirements

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) (for setup)
- `opencode` installed and configured
- Optional: `semgrep`, `bandit`, `trivy` for enhanced scanning

## Setup

```bash
git clone <repo-url> ~/nemotron-security
cd ~/nemotron-security
./setup.sh
```

## Usage

### Option A: opencode (recommended)

Uses whatever model is configured in your opencode setup. No extra API keys needed.

```bash
./analyze-opencode.sh ~/repos/nova
./analyze-opencode.sh ~/repos/nova --focus api,compute
./analyze-opencode.sh ~/repos/nova --scanners
```

### Option B: litellm proxy

Connects to a litellm proxy for access to multiple models (Nemotron, GPT-4o, Claude, etc.).

```bash
export LITELLM_HOST=http://127.0.0.1:4000
python3 analyze.py ~/repos/nova
python3 analyze.py ~/repos/nova --model openai/gpt-4o
python3 analyze.py ~/repos/nova --model ollama/nemotron-3.5-lightning
```

## Options

| Flag | Description |
|------|-------------|
| `--focus api,compute` | Only analyze specific directories |
| `--scanners` | Also run semgrep/bandit/trivy and triage results |
| `--output /path/to/report.md` | Custom output location |

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

Reports saved to `reports/<project-name>/` by default.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LITELLM_HOST` | `http://127.0.0.1:4000` | litellm proxy URL (analyze.py only) |
| `OPENCODE_BIN` | `opencode` | Path to opencode binary (analyze-opencode.sh only) |
