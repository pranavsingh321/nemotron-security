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

Default model: `local-spark/nemotron-3.5-light`

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
| `--model` | `local-spark/nemotron-3.5-light` | Model to use (provider/model format) |
| `--focus` | all .py files | Only analyze specific directories |
| `--scanners` | off | Also run semgrep/bandit/trivy and triage results |
| `--output` | `reports/<name>.md` | Custom output location |
| `--max-files` | 30 | Max files to analyze (risk-sorted) |

## How It Works

The analyzer uses a three-phase approach:

1. **Scanner phase** (`--scanners`): semgrep/bandit/trivy find hotspots, which are triaged by AI
2. **Project context**: AI identifies framework + highest-risk components first
3. **AI code review**: files are risk-sorted (auth, api, sql, upload, secret, exec in filename rank higher) and reviewed one at a time with **full file content** passed to the model, guided by scanner findings and project context

```
Target Repo
    │
    ├── Phase 1: Scanners (--scanners)
    │   ├── semgrep, bandit, trivy
    │   └── AI triages findings → true/false positive
    │
    ├── Phase 2: Project context
    │   └── AI identifies framework + risk areas
    │
    └── Phase 3: AI Code Review
        ├── Collects .py files, risk-sorted
        ├── Passes full file content + context to model
        └── Reports: type, severity, line, exploit, fix
```

## Output

Reports saved to `reports/<project-name>.md` by default. After the full analysis, each run also generates an **executive summary** at `reports/<project-name>-summary.md` containing the verdict, top risks, quick wins, and notes. If the model produces no summary, a stats-only fallback summary is written instead.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ANALYZE_MODEL` | `local-spark/nemotron-3.5-light` | Default model for analyze-opencode.sh |
| `LITELLM_HOST` | `http://127.0.0.1:4000` | litellm proxy URL (analyze.py only) |
| `OPENCODE_BIN` | `opencode` | Path to opencode binary |
