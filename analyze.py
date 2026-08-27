#!/usr/bin/env python3
"""
Nemotron Security Analyzer — improved version.

Two-pass approach:
  1. Static analysis (semgrep/bandit) to find hotspots
  2. LLM review guided by scanner findings + full file content

Usage:
    export LITELLM_HOST=http://127.0.0.1:4000
    python3 analyze.py ~/repos/my-project
    python3 analyze.py ~/repos/my-project --model openai/gpt-4o
    python3 analyze.py ~/repos/my-project --scanners
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

try:
    import openai
except ImportError:
    print("ERROR: openai not installed. Run: pip install openai")
    sys.exit(1)


# ---------------------------------------------------------------------------
# File collection
# ---------------------------------------------------------------------------

HIGH_RISK_PATTERNS = [
    "views", "api", "auth", "login", "register", "upload", "download",
    "exec", "eval", "shell", "subprocess", "os.system", "paramiko",
    "sql", "query", "cursor", "execute", "raw", "format",
    "render", "template", "response", "redirect", "json",
    "serializ", "deserializ", "pickle", "marshal", "yaml.load",
    "config", "settings", "secret", "key", "token", "password",
    "crypto", "hash", "sign", "verify", "encrypt", "decrypt",
    "file", "open", "path", "read", "write", "send_file",
    "request", "form", "args", "cookies", "headers",
]

MEDIUM_RISK_PATTERNS = [
    "model", "form", "field", "clean", "validate",
    "middleware", "permission", "group", "role",
    "celery", "task", "queue", "worker",
    "cache", "session", "cookie",
]


def collect_files(target_dir: str, focus: str = None) -> list[str]:
    """Collect Python files, prioritizing high-risk ones."""
    cmd = [
        "find", target_dir,
        "-name", "*.py",
        "-not", "-path", "*/test*",
        "-not", "-path", "*/tests/*",
        "-not", "-path", "*/.tox/*",
        "-not", "-path", "*/node_modules/*",
        "-not", "-path", "*/.git/*",
        "-not", "-path", "*/migrations/*",
        "-not", "-path", "*/__pycache__/*",
    ]
    if focus:
        dirs = focus.split(",")
        cmd = ["find", target_dir]
        for d in dirs:
            cmd += ["-path", f"*/{d}/*.py"]
        cmd += [
            "-not", "-path", "*/test*",
            "-not", "-path", "*/tests/*",
            "-not", "-path", "*/.git/*",
        ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    files = [f for f in result.stdout.strip().split("\n") if f]

    def risk_score(filepath: str):
        name = Path(filepath).name.lower()
        score = 0
        for p in HIGH_RISK_PATTERNS:
            if p in name:
                score += 10
        for p in MEDIUM_RISK_PATTERNS:
            if p in name:
                score += 5
        # Smaller files are easier to analyze fully
        try:
            size = os.path.getsize(filepath)
            if size < 5000:
                score += 3
            elif size < 15000:
                score += 1
        except OSError:
            pass
        return score

    files.sort(key=risk_score, reverse=True)
    return files[:50]


# ---------------------------------------------------------------------------
# Scanner integration
# ---------------------------------------------------------------------------

def run_scanners(target_dir: str) -> dict:
    """Run semgrep, bandit, trivy and collect results."""
    scan_dir = Path("/tmp/nemotron-scans")
    scan_dir.mkdir(exist_ok=True)
    results = {}

    scanners = [
        (["semgrep", "--config=auto", "--json", target_dir], "semgrep.json"),
        (["bandit", "-r", target_dir, "-x", "tests", "-f", "json"], "bandit.json"),
        (["trivy", "fs", "--format", "json", target_dir], "trivy.json"),
    ]

    for cmd, filename in scanners:
        name = filename.replace(".json", "")
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            fpath = scan_dir / filename
            if fpath.exists():
                content = fpath.read_text()
                # Parse and extract key findings, not raw JSON
                try:
                    data = json.loads(content)
                    findings = summarize_findings(name, data)
                    if findings:
                        results[name] = findings
                except json.JSONDecodeError:
                    results[name] = content[:3000]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    return results


def summarize_findings(scanner: str, data) -> str:
    """Extract actionable findings from scanner JSON output."""
    lines = []

    if scanner == "semgrep" and isinstance(data, dict):
        for r in data.get("results", [])[:30]:
            sev = r.get("extra", {}).get("severity", "INFO")
            msg = r.get("extra", {}).get("message", "")
            path = r.get("path", "")
            line = r.get("start", {}).get("line", "?")
            rule = r.get("check_id", "")
            lines.append(f"[{sev}] {path}:{line} — {rule}: {msg}")

    elif scanner == "bandit" and isinstance(data, dict):
        for r in data.get("results", [])[:30]:
            sev = r.get("issue_severity", "LOW")
            text = r.get("issue_text", "")
            path = r.get("filename", "")
            line = r.get("line_number", "?")
            test = r.get("test_id", "")
            lines.append(f"[{sev}] {path}:{line} — {test}: {text}")

    elif scanner == "trivy" and isinstance(data, dict):
        for result in data.get("Results", [])[:10]:
            target = result.get("Target", "")
            vulns = result.get("Vulnerabilities", [])
            for v in vulns[:10]:
                vid = v.get("VulnerabilityID", "")
                sev = v.get("Severity", "UNKNOWN")
                pkg = v.get("PkgName", "")
                lines.append(f"[{sev}] {target} — {pkg}: {vid}")

    return "\n".join(lines) if lines else ""


# ---------------------------------------------------------------------------
# LLM analysis
# ---------------------------------------------------------------------------

LITELLM_HOST = os.environ.get("LITELLM_HOST", "http://127.0.0.1:4000")


def get_client():
    return openai.OpenAI(base_url=f"{LITELLM_HOST}/v1", api_key="not-needed")


def ai_analyze(model: str, prompt: str, max_tokens: int = 2000) -> str:
    """Send prompt to model via litellm proxy."""
    client = get_client()
    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        max_tokens=max_tokens,
    )
    return response.choices[0].message.content


def analyze_project_context(model: str, target_dir: str) -> str:
    """First pass: understand the project to guide analysis."""
    # Gather project metadata
    meta_parts = []

    for f in ["requirements.txt", "setup.py", "setup.cfg", "pyproject.toml"]:
        fp = Path(target_dir) / f
        if fp.exists():
            try:
                content = fp.read_text()[:2000]
                meta_parts.append(f"--- {f} ---\n{content}")
            except Exception:
                pass

    for f in ["manage.py", "wsgi.py", "asgi.py", "app.py", "main.py"]:
        fp = Path(target_dir) / f
        if fp.exists():
            try:
                content = fp.read_text()[:1000]
                meta_parts.append(f"--- {f} ---\n{content}")
            except Exception:
                pass

    if not meta_parts:
        return "No project metadata found."

    prompt = f"""You are a security architect. Analyze this project's metadata and identify:
1. What framework is used (Django, Flask, FastAPI, etc.)
2. Key security-relevant components (auth, API endpoints, file handling, DB queries)
3. Highest-risk areas to focus security review on
4. Common vulnerability patterns for this specific framework

Be concise. Output a prioritized list of areas to investigate.

Project metadata:
{chr(10).join(meta_parts)}"""

    return ai_analyze(model, prompt, max_tokens=1000)


def analyze_file_with_context(
    model: str, filepath: str, target_dir: str,
    scanner_findings: str = "", project_context: str = ""
) -> str:
    """Analyze a file with full content and context."""
    rel_path = os.path.relpath(filepath, target_dir)

    try:
        content = Path(filepath).read_text(errors="ignore")
    except Exception as e:
        return f"Error reading file: {e}"

    if len(content) > 40000:
        content = content[:40000] + "\n... (truncated)"

    context_block = ""
    if project_context:
        context_block = f"\nProject context: {project_context[:500]}\n"
    scanner_block = ""
    if scanner_findings:
        scanner_block = f"\nRelated scanner findings:\n{scanner_findings[:2000]}\n"

    prompt = f"""You are a senior application security engineer performing a code review.

TASK: Find real, exploitable vulnerabilities in this file. Do NOT report generic warnings.

FOR EACH FINDING, provide:
- Vulnerability type (be specific: e.g., "SQL injection via string formatting" not just "SQL injection")
- Severity: CRITICAL / HIGH / MEDIUM / LOW / INFO
- Exact line numbers
- The vulnerable code snippet (copy the actual lines)
- Exploitation scenario (how an attacker would trigger this)
- Fix recommendation with code

FOCUS ON:
- User input reaching dangerous sinks (exec, eval, shell, SQL, file paths, URLs)
- Missing authorization/permission checks
- Hardcoded secrets, tokens, API keys
- Insecure deserialization (pickle, yaml.load, eval of user data)
- Path traversal in file operations
- SSRF via user-controlled URLs
- Command injection via subprocess/os.system with user input
- XSS via unescaped output
- Authentication bypass patterns
- Race conditions in security-critical code
- Unsafe temporary file creation
- Cryptographic weaknesses (weak algorithms, hardcoded keys)

If NO real vulnerabilities found, respond exactly: "No security issues found."
Do not invent issues. Only report what you can clearly trace from input to sink.{context_block}{scanner_block}File: {rel_path}
---
{content}"""

    return ai_analyze(model, prompt, max_tokens=2000)


def analyze_scanners(model: str, scanner_results: dict) -> str:
    """Triage scanner findings with AI."""
    findings = "\n\n".join(
        f"=== {name} ===\n{data}" for name, data in scanner_results.items()
    )

    prompt = f"""You are a security analyst triaging static analysis scanner results.

For each finding:
1. Is it a TRUE POSITIVE or FALSE POSITIVE? (explain why)
2. Real-world exploitability (Easy / Medium / Hard / Not exploitable)
3. Prioritize: which findings need immediate attention?
4. Suggest specific fixes

Scanner results:
{findings}"""

    return ai_analyze(model, prompt, max_tokens=2000)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="AI-powered security analyzer")
    parser.add_argument("target_dir", help="Repository to analyze")
    parser.add_argument("--model", default="local-spark/qwen3.6-36b",
                        help="Model name (default: local-spark/qwen3.6-36b)")
    parser.add_argument("--focus", help="Comma-separated dirs to focus on")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--scanners", action="store_true",
                        help="Run semgrep/bandit/trivy first")
    parser.add_argument("--max-files", type=int, default=30,
                        help="Max files to analyze (default: 30)")
    args = parser.parse_args()

    target_dir = os.path.expanduser(args.target_dir)
    if not os.path.isdir(target_dir):
        print(f"ERROR: Directory not found: {target_dir}")
        sys.exit(1)

    target_name = os.path.basename(target_dir.rstrip("/"))
    script_dir = Path(__file__).parent
    output = Path(args.output or script_dir / "reports" / f"{target_name}.md")
    output.parent.mkdir(parents=True, exist_ok=True)

    print(f"==> Target:  {target_dir}")
    print(f"==> Model:   {args.model}")
    print(f"==> Proxy:   {LITELLM_HOST}")
    print(f"==> Output:  {output}")
    if args.focus:
        print(f"==> Focus:   {args.focus}")

    # Write header
    with open(output, "w") as f:
        f.write(f"# Security Analysis: {target_name}\n\n")
        f.write(f"**Date:** {subprocess.getoutput('date -u +%Y-%m-%dT%H:%M:%SZ')}\n")
        f.write(f"**Model:** {args.model}\n")
        f.write(f"**Target:** {target_dir}\n")
        if args.focus:
            f.write(f"**Focus:** {args.focus}\n")
        f.write("\n---\n\n")

    # Phase 1: Scanners
    scanner_findings_text = ""
    scanner_results = {}
    if args.scanners:
        print("==> Phase 1: Running scanners...")
        scanner_results = run_scanners(target_dir)
        if scanner_results:
            scanner_findings_text = "\n\n".join(
                f"=== {name} ===\n{data}"
                for name, data in scanner_results.items()
            )
            print(f"==> Scanner findings: {len(scanner_results)} tools reported results")
            print("==> Phase 1b: Triaging scanner results...")
            triage = analyze_scanners(args.model, scanner_results)
            with open(output, "a") as f:
                f.write("## Scanner Triage\n\n")
                f.write(triage)
                f.write("\n\n---\n\n")

    # Phase 2: Project context
    print("==> Phase 2: Analyzing project context...")
    try:
        project_context = analyze_project_context(args.model, target_dir)
        print(f"==> Project context: {project_context[:100]}...")
    except Exception as e:
        print(f"==> Project context failed: {e}")
        project_context = ""

    # Phase 3: File-by-file review (guided by scanners + context)
    print("==> Phase 3: AI code review...")
    files = collect_files(target_dir, args.focus)
    files = files[:args.max_files]
    print(f"==> Found {len(files)} files to analyze (risk-sorted)")

    with open(output, "a") as f:
        f.write("## AI Code Review\n\n")

    findings_count = 0
    for i, filepath in enumerate(files, 1):
        rel = os.path.relpath(filepath, target_dir)
        print(f"  [{i}/{len(files)}] {rel}")
        try:
            result = analyze_file_with_context(
                args.model, filepath, target_dir,
                scanner_findings=scanner_findings_text,
                project_context=project_context,
            )
            if result and "No security issues found" not in result:
                findings_count += 1
        except Exception as e:
            result = f"Error: {e}"

        with open(output, "a") as f:
            f.write(f"### {rel}\n\n")
            f.write(result)
            f.write("\n\n---\n\n")

    # Summary
    with open(output, "a") as f:
        f.write(f"## Summary\n\n")
        f.write(f"- Files analyzed: {len(files)}\n")
        f.write(f"- Findings: {findings_count}\n")
        f.write(f"- Model: {args.model}\n")

    print(f"==> Report saved to: {output}")
    print(f"==> Findings: {findings_count}/{len(files)} files")

    # ------------------------------------------------------------------
    # Generate executive summary markdown
    # ------------------------------------------------------------------
    summary_path = output.with_name(f"{output.stem}-summary.md")
    print(f"==> Generating executive summary...")

    try:
        report_text = output.read_text(errors="ignore")[:30000]
        summary_prompt = f"""You are writing an executive security summary. Based on the full analysis report below, produce a concise markdown summary containing:
1. **Verdict**: overall security posture (1-2 sentences)
2. **Top risks**: top 5 highest-priority findings with file, severity, and one-line description
3. **Quick wins**: 3-5 cheap, high-impact fixes to do first
4. **Low-priority/INFO notes**: brief list

Use this exact structure:
# Security Summary: {target_name}

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
{report_text}"""
        summary = ai_analyze(args.model, summary_prompt, max_tokens=1500)

        if not summary or "Verdict" not in summary:
            raise ValueError("Model did not produce a valid summary")

        with open(summary_path, "w") as f:
            f.write(summary.rstrip() + "\n")
        print(f"==> Summary saved to: {summary_path}")
    except Exception as e:
        print(f"==> Model summary failed ({e}); writing stats-only summary")
        with open(summary_path, "w") as f:
            f.write(f"# Security Summary: {target_name}\n\n")
            f.write(f"**Date:** {subprocess.getoutput('date -u +%Y-%m-%dT%H:%M:%SZ')}\n")
            f.write(f"**Model:** {args.model}\n")
            f.write(f"**Target:** {target_dir}\n\n")
            f.write(f"## Scope\n\n")
            f.write(f"- Files reviewed: {len(files)}\n")
            f.write(f"- Files with findings: {findings_count}\n")
            f.write(f"- Full report: {output}\n")
        print(f"==> Summary saved to: {summary_path}")


if __name__ == "__main__":
    main()
