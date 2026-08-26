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

Default model: `ollama/nemotron-3.5-lightning`

```bash
./analyze-opencode.sh ~/repos/nova
./analyze-opencode.sh ~/repos/nova --model openai/gpt-4o
./analyze-opencode.sh ~/repos/nova --model ollama/nemotron-mini
./analyze-opencode.sh ~/repos/nova --focus api,compute --scanners
```

### Option B: litellm proxy

```bash
export LITELLM_HOST=http://127.0.0.1:4000
python3 analyze.py ~/repos/nova
python3 analyze.py ~/repos/nova --model openai/gpt-4o
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--model` | `ollama/nemotron-3.5-lightning` | Model to use (provider/model format) |
| `--focus` | all .py files | Only analyze specific directories |
| `--scanners` | off | Also run semgrep/bandit/trivy and triage results |
| `--output` | `reports/<name>.md` | Custom output location |

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
| `OPENCODE_BIN` | `opencode` | Path to opencode binary |
