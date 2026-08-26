#!/usr/bin/env python3
"""
Nemotron Security Analyzer — litellm version.

Connects to a litellm proxy (e.g., localhost:4000) for unified access to
Ollama, OpenAI, Anthropic, Azure, Bedrock, etc.

Usage:
    # Set the litellm proxy host
    export LITELLM_HOST=http://192.168.1.100:4000

    python3 analyze.py ~/repos/my-project
    python3 analyze.py ~/repos/my-project --model ollama/nemotron-3.5-lightning
    python3 analyze.py ~/repos/my-project --model openai/gpt-4o
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


def collect_files(target_dir: str, focus: str = None) -> list[str]:
    """Collect Python files from target directory, excluding tests."""
    cmd = [
        "find", target_dir,
        "-name", "*.py",
        "-not", "-path", "*/test*",
        "-not", "-path", "*/.tox/*",
        "-not", "-path", "*/node_modules/*",
        "-not", "-path", "*/.git/*",
    ]
    if focus:
        dirs = focus.split(",")
        cmd = ["find", target_dir]
        for d in dirs:
            cmd += ["-path", f"*/{d}/*.py"]
        cmd += ["-not", "-path", "*/test*"]

    result = subprocess.run(cmd, capture_output=True, text=True)
    files = [f for f in result.stdout.strip().split("\n") if f]
    return files[:50]  # cap at 50 files


def run_scanners(target_dir: str) -> dict:
    """Run semgrep, bandit, trivy and collect results."""
    scan_dir = Path("/tmp/nemotron-scans")
    scan_dir.mkdir(exist_ok=True)
    results = {}

    # semgrep
    try:
        subprocess.run(
            ["semgrep", "--config=auto", "--json", target_dir],
            capture_output=True, text=True, timeout=120
        )
        sf = scan_dir / "semgrep.json"
        if sf.exists():
            results["semgrep"] = sf.read_text()[:3000]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # bandit
    try:
        subprocess.run(
            ["bandit", "-r", target_dir, "-x", "tests", "-f", "json"],
            capture_output=True, text=True, timeout=120
        )
        bf = scan_dir / "bandit.json"
        if bf.exists():
            results["bandit"] = bf.read_text()[:3000]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # trivy
    try:
        subprocess.run(
            ["trivy", "fs", "--format", "json", target_dir],
            capture_output=True, text=True, timeout=120
        )
        tf = scan_dir / "trivy.json"
        if tf.exists():
            results["trivy"] = tf.read_text()[:3000]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return results


LITELLM_HOST = os.environ.get("LITELLM_HOST", "http://127.0.0.1:4000")


def ai_analyze(model: str, prompt: str) -> str:
    """Send prompt to model via litellm proxy."""
    import openai

    client = openai.OpenAI(
        base_url=f"{LITELLM_HOST}/v1",
        api_key="not-needed",
    )
    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3,
    )
    return response.choices[0].message.content


def analyze_file(model: str, filepath: str, target_dir: str) -> str:
    """Analyze a single file for security vulnerabilities."""
    rel_path = os.path.relpath(filepath, target_dir)
    content = Path(filepath).read_text(errors="ignore")

    if len(content) > 30000:
        content = content[:30000] + "\n... (truncated)"

    prompt = f"""You are a senior security engineer reviewing code for vulnerabilities.

Analyze the following file for security issues. For each finding:
- Type: (e.g., SQL injection, XSS, hardcoded secret, SSRF, path traversal, insecure deserialization, command injection, privilege escalation)
- Severity: CRITICAL / HIGH / MEDIUM / LOW / INFO
- Line numbers
- Exploitation difficulty: Easy / Medium / Hard
- Fix recommendation (code snippet if possible)

If no issues found, respond with: "No security issues found."

Be specific. Do not flag generic warnings. Only report real, exploitable vulnerabilities.

File: {rel_path}
---
{content}"""

    return ai_analyze(model, prompt)


def analyze_scanners(model: str, scanner_results: dict) -> str:
    """Triage scanner findings with AI."""
    findings = ""
    for name, data in scanner_results.items():
        findings += f"--- {name} ---\n{data}\n\n"

    prompt = f"""You are a security analyst triaging scanner results.

Review these findings from static analysis tools. For each:
- Confirm if true positive or false positive
- Provide context specific to this codebase
- Prioritize by exploitability
- Suggest fixes

Output a prioritized list with severity and confidence.

Scanner results:
{findings}"""

    return ai_analyze(model, prompt)


def main():
    parser = argparse.ArgumentParser(description="AI-powered security analyzer")
    parser.add_argument("target_dir", help="Repository to analyze")
    parser.add_argument("--model", default="nemotron-3.5-lightning",
                        help="Model name as configured in litellm proxy (default: nemotron-3.5-lightning)")
    parser.add_argument("--focus", help="Comma-separated dirs to focus on (e.g., api,compute)")
    parser.add_argument("--output", help="Output file (default: reports/<name>.md)")
    parser.add_argument("--scanners", action="store_true", help="Also run semgrep/bandit/trivy")
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

    # Phase 1: Scanners (optional)
    if args.scanners:
        print("==> Phase 1: Running scanners...")
        scanner_results = run_scanners(target_dir)
        if scanner_results:
            print(f"==> Analyzing {len(scanner_results)} scanner results...")
            triage = analyze_scanners(args.model, scanner_results)
            with open(output, "a") as f:
                f.write("## Scanner Triage\n\n")
                f.write(triage)
                f.write("\n\n---\n\n")

    # Phase 2: AI code review
    print("==> Phase 2: AI code review...")
    files = collect_files(target_dir, args.focus)
    print(f"==> Found {len(files)} files to analyze")

    with open(output, "a") as f:
        f.write("## AI Code Review\n\n")

    for i, filepath in enumerate(files, 1):
        rel = os.path.relpath(filepath, target_dir)
        print(f"  [{i}/{len(files)}] {rel}")
        try:
            result = analyze_file(args.model, filepath, target_dir)
        except Exception as e:
            result = f"Error: {e}"

        with open(output, "a") as f:
            f.write(f"### {rel}\n\n")
            f.write(result)
            f.write("\n\n---\n\n")

    print(f"==> Report saved to: {output}")


if __name__ == "__main__":
    main()
