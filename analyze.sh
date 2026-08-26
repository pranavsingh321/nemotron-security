#!/bin/bash
set -euo pipefail

# Nemotron Security Analyzer
# Runs NVIDIA Nemotron via Ollama for AI-powered security code review.
#
# Usage:
#   ./analyze.sh ~/repos/my-project
#   ./analyze.sh ~/repos/my-project --model nemotron:70b
#   ./analyze.sh ~/repos/my-project --focus api,compute
#   ./analyze.sh ~/repos/my-project --output /tmp/report.md

TARGET_DIR="${1:?Usage: ./analyze.sh <target-dir> [--model MODEL] [--focus DIRS] [--output FILE] [--scanners]}"
MODEL="${MODEL:-nemotron-mini}"
FOCUS=""
OUTPUT=""
RUN_SCANNERS=false

shift
while [[ $# -gt 0 ]]; do
  case "$1" in
    --model)  MODEL="$2"; shift 2 ;;
    --focus)  FOCUS="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    --scanners) RUN_SCANNERS=true; shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

[[ -d "$TARGET_DIR" ]] || { echo "ERROR: Directory not found: $TARGET_DIR"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_NAME="$(basename "$TARGET_DIR")"
OUTPUT="${OUTPUT:-$SCRIPT_DIR/reports/$TARGET_NAME.md}"
mkdir -p "$(dirname "$OUTPUT")"

log() { echo "==> $*"; }

# ---------------------------------------------------------------------------
# Ollama check
# ---------------------------------------------------------------------------

check_ollama() {
  if ! command -v ollama &>/dev/null; then
    echo "ERROR: ollama not installed. Run: curl -fsSL https://ollama.com/install.sh | sh"
    exit 1
  fi
  if ! ollama list 2>/dev/null | grep -q "$MODEL"; then
    log "Pulling model: $MODEL..."
    ollama pull "$MODEL"
  fi
}

# ---------------------------------------------------------------------------
# Scanner phase (optional)
# ---------------------------------------------------------------------------

run_scanners() {
  local scan_dir="/tmp/nemotron-scans/$TARGET_NAME"
  mkdir -p "$scan_dir"

  log "Running semgrep..."
  if command -v semgrep &>/dev/null; then
    semgrep --config=auto --json "$TARGET_DIR" 2>/dev/null > "$scan_dir/semgrep.json" || true
  else
    log "semgrep not installed, skipping. Install: pip install semgrep"
  fi

  log "Running bandit..."
  if command -v bandit &>/dev/null; then
    bandit -r "$TARGET_DIR" -x tests -f json > "$scan_dir/bandit.json" 2>/dev/null || true
  else
    log "bandit not installed, skipping. Install: pip install bandit"
  fi

  log "Running trivy..."
  if command -v trivy &>/dev/null; then
    trivy fs --format json "$TARGET_DIR" > "$scan_dir/trivy.json" 2>/dev/null || true
  else
    log "trivy not installed, skipping. Install: brew install trivy"
  fi

  echo "$scan_dir"
}

# ---------------------------------------------------------------------------
# File collection
# ---------------------------------------------------------------------------

collect_files() {
  local dir="$1"
  local focus="$2"

  if [[ -n "$focus" ]]; then
    IFS=',' read -ra FOCUS_DIRS <<< "$focus"
    for d in "${FOCUS_DIRS[@]}"; do
      find "$dir" -path "*/$d/*.py" -not -path "*/test*" -not -path "*/.tox/*" -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null
    done
  else
    find "$dir" -name "*.py" -not -path "*/test*" -not -path "*/.tox/*" -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null
  fi | head -50
}

# ---------------------------------------------------------------------------
# AI analysis
# ---------------------------------------------------------------------------

analyze_file() {
  local file="$1"
  local rel_path="${file#$TARGET_DIR/}"

  ollama run "$MODEL" "$(cat <<'PROMPT'
You are a senior security engineer reviewing code for vulnerabilities.

Analyze the following file for security issues. For each finding:
- Type: (e.g., SQL injection, XSS, hardcoded secret, SSRF, path traversal, insecure deserialization, command injection, privilege escalation)
- Severity: CRITICAL / HIGH / MEDIUM / LOW / INFO
- Line numbers
- Exploitation difficulty: Easy / Medium / Hard
- Fix recommendation (code snippet if possible)

If no issues found, respond with: "No security issues found."

Be specific. Do not flag generic warnings. Only report real, exploitable vulnerabilities.

File: ${rel_path}
---
PROMPT
$(cat "$file"))" 2>/dev/null
}

analyze_scanner_results() {
  local scan_dir="$1"

  local findings=""
  for f in "$scan_dir"/*.json; do
    [[ -f "$f" ]] || continue
    local name="$(basename "$f" .json)"
    findings+="--- $name ---\n"
    findings+="$(cat "$f" | head -2000)\n\n"
  done

  if [[ -z "$findings" ]]; then
    return
  fi

  ollama run "$MODEL" "$(cat <<'PROMPT'
You are a security analyst triaging scanner results.

Review these findings from static analysis tools. For each:
- Confirm if true positive or false positive
- Provide context specific to this codebase
- Prioritize by exploitability
- Suggest fixes

Output a prioritized list with severity and confidence.

Scanner results:
PROMPT
(findings))"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

log "Nemotron Security Analyzer"
log "  Target: $TARGET_DIR"
log "  Model:  $MODEL"
log "  Output: $OUTPUT"
[[ -n "$FOCUS" ]] && log "  Focus:  $FOCUS"

check_ollama

# Start report
cat > "$OUTPUT" <<EOF
# Security Analysis: $TARGET_NAME

**Date:** $(date -u +%Y-%m-%dT%H:%M:%SZ)
**Model:** $MODEL
**Target:** $TARGET_DIR
$( [[ -n "$FOCUS" ]] && echo "**Focus:** $FOCUS" )

---

EOF

# Phase 1: Run scanners (optional)
if [[ "$RUN_SCANNERS" == "true" ]]; then
  log "Phase 1: Running scanners..."
  scan_dir="$(run_scanners)"
  log "Analyzing scanner results with $MODEL..."
  echo "## Scanner Triage" >> "$OUTPUT"
  echo "" >> "$OUTPUT"
  analyze_scanner_results "$scan_dir" >> "$OUTPUT"
  echo "" >> "$OUTPUT"
  echo "---" >> "$OUTPUT"
  echo "" >> "$OUTPUT"
fi

# Phase 2: AI file-by-file review
log "Phase 2: AI code review..."
echo "## AI Code Review" >> "$OUTPUT"
echo "" >> "$OUTPUT"

file_count=0
while IFS= read -r file; do
  [[ -f "$file" ]] || continue
  rel="${file#$TARGET_DIR/}"
  log "  Analyzing: $rel"
  echo "### $rel" >> "$OUTPUT"
  echo "" >> "$OUTPUT"
  analyze_file "$file" >> "$OUTPUT"
  echo "" >> "$OUTPUT"
  echo "---" >> "$OUTPUT"
  echo "" >> "$OUTPUT"
  ((file_count++))
done < <(collect_files "$TARGET_DIR" "$FOCUS")

log "Analyzed $file_count files."
log "Report saved to: $OUTPUT"
