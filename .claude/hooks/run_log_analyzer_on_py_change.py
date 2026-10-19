#!/usr/bin/env python3
"""PostToolUse hook: after Edit/Write touches a .py file, run the test suite
so a regression in parsing/counting shows up immediately after the change
that caused it. On failure, exit 2 with the test output on stderr so Claude
sees it and can fix it."""
import json
import re
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
            [sys.executable, "-m", "unittest", "test_log_analyzer", "-v"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        print("test zaman aşımına uğradı", file=sys.stderr)
        sys.exit(2)

    output = result.stdout + result.stderr

    if result.returncode == 0:
        match = re.search(r"Ran (\d+) tests?", output)
        count = match.group(1) if match else "?"
        print(json.dumps({"systemMessage": f"✅ {count} test geçti"}))
    else:
        print(output, file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
