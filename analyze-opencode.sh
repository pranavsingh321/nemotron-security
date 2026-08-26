#!/bin/bash
set -euo pipefail

# Security Analyzer — opencode version
# Uses opencode directly for security review with any configured model.
#
# Usage:
#   ./analyze-opencode.sh ~/repos/nova
#   ./analyze-opencode.sh ~/repos/nova --model openai/gpt-4o
#   ./analyze-opencode.sh ~/repos/nova --focus api,compute --scanners

TARGET_DIR="${1:?Usage: ./analyze-opencode.sh <target-dir> [--model MODEL] [--focus DIRS] [--scanners] [--output FILE]}"
MODEL="ollama/nemotron-3.5-lightning"
FOCUS=""
OUTPUT=""
RUN_SCANNERS=false
OPENCODE_BIN="${OPENCODE_BIN:-opencode}"

shift
while [[ $# -gt 0 ]]; do
  case "$1" in
    --model)    MODEL="$2"; shift 2 ;;
    --focus)    FOCUS="$2"; shift 2 ;;
    --output)   OUTPUT="$2"; shift 2 ;;
    --scanners) RUN_SCANNERS=true; shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

[[ -d "$TARGET_DIR" ]] || { echo "ERROR: Directory not found: $TARGET_DIR"; exit 1; }
command -v "$OPENCODE_BIN" &>/dev/null || { echo "ERROR: opencode not found"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_NAME="$(basename "$TARGET_DIR")"
OUTPUT="${OUTPUT:-$SCRIPT_DIR/reports/$TARGET_NAME.md}"
mkdir -p "$(dirname "$OUTPUT")"

log() { echo "==> $*"; }

collect_files() {
  local dir="$1"
  local focus="$2"

  if [[ -n "$focus" ]]; then
    IFS=',' read -ra FOCUS_DIRS <<< "$focus"
    for d in "${FOCUS_DIRS[@]}"; do
      find "$dir" -path "*/$d/*.py" -not -path "*/test*" -not -path "*/.tox/*" -not -path "*/.git/*" 2>/dev/null
    done
  else
    find "$dir" -name "*.py" -not -path "*/test*" -not -path "*/.tox/*" -not -path "*/.git/*" 2>/dev/null
  fi | head -30
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
  fi

  log "Running bandit..."
  if command -v bandit &>/dev/null; then
    bandit -r "$TARGET_DIR" -x tests -f json > "$scan_dir/bandit.json" 2>/dev/null || true
  fi

  log "Running trivy..."
  if command -v trivy &>/dev/null; then
    trivy fs --format json "$TARGET_DIR" > "$scan_dir/trivy.json" 2>/dev/null || true
  fi

  # Triage with opencode
  local findings=""
  for f in "$scan_dir"/*.json; do
    [[ -f "$f" ]] || continue
    local name="$(basename "$f" .json)"
    findings+="--- $name ---\n$(head -2000 "$f")\n\n"
  done

  if [[ -n "$findings" ]]; then
    log "Triaging scanner results with opencode..."
    "$OPENCODE_BIN" run --dir "$TARGET_DIR" --model "$MODEL" --auto \
      "Review these security scanner findings. For each: confirm true positive or false positive, prioritize by exploitability, suggest fixes. Output a prioritized list.

Scanner results:
$findings" > "$OUTPUT"
    echo "" >> "$OUTPUT"
    echo "---" >> "$OUTPUT"
    echo "" >> "$OUTPUT"
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

log "Nemotron Security Analyzer (opencode)"
log "  Target: $TARGET_DIR"
log "  Model:  $MODEL"
log "  Output: $OUTPUT"
[[ -n "$FOCUS" ]] && log "  Focus:  $FOCUS"

# Header
cat > "$OUTPUT" <<EOF
# Security Analysis: $TARGET_NAME

**Date:** $(date -u +%Y-%m-%dT%H:%M:%SZ)
**Engine:** opencode ($OPENCODE_BIN)
**Model:** $MODEL
**Target:** $TARGET_DIR
$( [[ -n "$FOCUS" ]] && echo "**Focus:** $FOCUS" )

---

EOF

# Phase 1: Scanners (optional)
if [[ "$RUN_SCANNERS" == "true" ]]; then
  log "Phase 1: Running scanners..."
  run_scanners
fi

# Phase 2: AI code review
log "Phase 2: AI code review via opencode..."

files=()
while IFS= read -r f; do
  files+=("$f")
done < <(collect_files "$TARGET_DIR" "$FOCUS")

log "Found ${#files[@]} files to analyze"

echo "## AI Code Review" >> "$OUTPUT"
echo "" >> "$OUTPUT"

for i in "${!files[@]}"; do
  file="${files[$i]}"
  rel="${file#$TARGET_DIR/}"
  num=$((i + 1))
  log "  [$num/${#files[@]}] $rel"

  "$OPENCODE_BIN" run --dir "$TARGET_DIR" --model "$MODEL" --auto \
    "You are a senior security engineer. Analyze this file for vulnerabilities: SQL injection, XSS, hardcoded secrets, SSRF, path traversal, command injection, privilege escalation, insecure deserialization. For each finding: type, severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), line numbers, exploitation difficulty (Easy/Medium/Hard), fix recommendation. If no issues: say 'No security issues found.' Be specific, no generic warnings.

File to review: $rel" >> "$OUTPUT" 2>/dev/null

  echo "" >> "$OUTPUT"
  echo "---" >> "$OUTPUT"
  echo "" >> "$OUTPUT"
done

log "Report saved to: $OUTPUT"
