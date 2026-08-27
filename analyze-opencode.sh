#!/bin/bash
set -euo pipefail

# Security Analyzer — opencode version
# Uses opencode directly for security review with any configured model.
#
# Usage:
#   ./analyze-opencode.sh ~/repos/nova
#   ./analyze-opencode.sh ~/repos/nova --model openai/gpt-4o
#   ./analyze-opencode.sh ~/repos/nova --focus api,compute --scanners

TARGET_DIR="${1:?Usage: ./analyze-opencode.sh <target-dir> [--model MODEL] [--focus DIRS] [--scanners] [--output FILE] [--max-files N]}"
MODEL="${ANALYZE_MODEL:-local-spark/nemotron-3.5-light}"
FOCUS=""
OUTPUT=""
RUN_SCANNERS=false
MAX_FILES=30
OPENCODE_BIN="${OPENCODE_BIN:-opencode}"

shift
while [[ $# -gt 0 ]]; do
  case "$1" in
    --model)    MODEL="$2"; shift 2 ;;
    --focus)    FOCUS="$2"; shift 2 ;;
    --output)   OUTPUT="$2"; shift 2 ;;
    --scanners) RUN_SCANNERS=true; shift ;;
    --max-files) MAX_FILES="$2"; shift 2 ;;
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

  local all_files=()
  if [[ -n "$focus" ]]; then
    IFS=',' read -ra FOCUS_DIRS <<< "$focus"
    for d in "${FOCUS_DIRS[@]}"; do
      while IFS= read -r f; do
        all_files+=("$f")
      done < <(find "$dir" -path "*/$d/*.py" -not -path "*/test*" -not -path "*/tests/*" -not -path "*/.tox/*" -not -path "*/.git/*" -not -path "*/migrations/*" 2>/dev/null)
    done
  else
    while IFS= read -r f; do
      all_files+=("$f")
    done < <(find "$dir" -name "*.py" -not -path "*/test*" -not -path "*/tests/*" -not -path "*/.tox/*" -not -path "*/.git/*" -not -path "*/migrations/*" 2>/dev/null)
  fi

  # Sort by risk: files with auth/api/view/sql/upload/secret in name first
  printf '%s\n' "${all_files[@]}" | awk '{
    n = tolower($0)
    score = 0
    if (n ~ /auth|login|register|session/) score += 20
    if (n ~ /view|api|endpoint|route|handler/) score += 15
    if (n ~ /sql|query|database|db|cursor/) score += 15
    if (n ~ /upload|download|file|send/) score += 12
    if (n ~ /secret|key|token|password|crypto/) score += 12
    if (n ~ /exec|eval|shell|subprocess|command/) score += 12
    if (n ~ /serial|deserial|pickle|yaml/) score += 10
    if (n ~ /config|settings/) score += 8
    if (n ~ /template|render|response/) score += 5
    if (n ~ /middleware|permission|role/) score += 5
    print score "\t" $0
  }' | sort -t$'\t' -k1 -rn | cut -f2 | head -"$MAX_FILES"
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
$findings" > "$OUTPUT" || true
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

  content=$(head -c 40000 "$file" 2>/dev/null || echo "ERROR: could not read file")

  "$OPENCODE_BIN" run --dir "$TARGET_DIR" --model "$MODEL" --auto \
    "You are a senior application security engineer. Find real, exploitable vulnerabilities. Do NOT report generic warnings.

FOR EACH FINDING provide:
- Vulnerability type (specific, e.g. 'SQL injection via string formatting')
- Severity: CRITICAL / HIGH / MEDIUM / LOW / INFO
- Exact line numbers
- The vulnerable code snippet
- Exploitation scenario
- Fix with code

FOCUS ON: user input to dangerous sinks (exec, eval, shell, SQL, file paths, URLs), missing auth checks, hardcoded secrets, insecure deserialization, path traversal, SSRF, command injection, XSS, auth bypass, race conditions, weak crypto.

If NO real vulnerabilities: respond exactly 'No security issues found.'

File: $rel
---
$content" >> "$OUTPUT" 2>/dev/null || true

  echo "" >> "$OUTPUT"
  echo "---" >> "$OUTPUT"
  echo "" >> "$OUTPUT"
done

log "Report saved to: $OUTPUT"

# ---------------------------------------------------------------------------
# Summary generation
# ---------------------------------------------------------------------------

SUMMARY="${OUTPUT%.md}-summary.md"

# Count findings by severity from the full report
CRIT_COUNT=$(grep -ci "CRITICAL" "$OUTPUT" || true)
HIGH_COUNT=$(grep -ci "HIGH" "$OUTPUT" || true)
MED_COUNT=$(grep -ci "MEDIUM" "$OUTPUT" || true)
LOW_COUNT=$(grep -ci "LOW" "$OUTPUT" || true)
ISSUE_FILES=$(grep -c "^### " "$OUTPUT" || true)

# Ask the model for a concise executive summary from the full report
log "Generating executive summary..."
"$OPENCODE_BIN" run --dir "$TARGET_DIR" --model "$MODEL" --auto \
  "You are writing an executive security summary. Based on the full analysis report below, produce a concise markdown summary containing:
1. **Verdict**: overall security posture (1-2 sentences)
2. **Top risks**: top 5 highest-priority findings with file, severity, and one-line description
3. **Quick wins**: 3-5 cheap, high-impact fixes to do first
4. **Low-priority/INFO notes**: brief list

Use this exact structure:
# Security Summary: $TARGET_NAME

## Verdict
...

## Top Risks
1. [CRITICAL] path/to/file:line — description

## Quick Wins
- ...

## Notes
- ...

Keep it under 40 lines. Output ONLY the markdown.

Report:
$(head -c 30000 "$OUTPUT")" > "$SUMMARY" 2>/dev/null || true

# If model produced nothing, generate a stats-only fallback summary
if [[ ! -s "$SUMMARY" ]]; then
  log "Model summary empty, generating stats-only summary"
  cat > "$SUMMARY" <<EOF
# Security Summary: $TARGET_NAME

**Date:** $(date -u +%Y-%m-%dT%H:%M:%SZ)
**Engine:** opencode ($OPENCODE_BIN)
**Model:** $MODEL
**Target:** $TARGET_DIR

## Scope
- Files reviewed: $ISSUE_FILES
- Full report: $OUTPUT

## Findings by Severity (keyword count)
- CRITICAL: $CRIT_COUNT
- HIGH: $HIGH_COUNT
- MEDIUM: $MED_COUNT
- LOW: $LOW_COUNT

> Note: These are keyword-frequency counts. Run the analyzer and generate the model-based
> summary for a detailed executive overview.
EOF
fi

log "Summary saved to: $SUMMARY"
