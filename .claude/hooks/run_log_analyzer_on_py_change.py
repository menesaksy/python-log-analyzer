#!/usr/bin/env python3
"""PostToolUse hook: after Edit/Write touches a .py file, re-run log_analyzer.py
against sample_auth.log so regressions in parsing/counting show up immediately."""
import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def main():
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return

    file_path = data.get("tool_input", {}).get("file_path", "")
    if not file_path.endswith(".py"):
        return

    try:
        result = subprocess.run(
            [sys.executable, "log_analyzer.py", "sample_auth.log", "-t", "1"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        output = "test zaman aşımına uğradı"

    print(json.dumps({"systemMessage": f"log_analyzer.py sample_auth.log -t 1:\n{output}"}))


if __name__ == "__main__":
    main()
