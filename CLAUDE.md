# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single-file Python CLI tool, `log_analyzer.py`, that parses Linux SSH/`auth.log` files, counts failed login attempts per IP address, and flags IPs at or above a threshold as suspicious. No build system, package manifest, or test suite exists yet — it's a standalone script run directly with `python`.

## Running the tool

```
python log_analyzer.py <logfile> [-t|--threshold N] [-o|--output report.csv]
```

- `logfile` (positional, required): path to the auth log to analyze.
- `-t/--threshold` (default `5`): minimum failed-attempt count for an IP to be marked suspicious.
- `-o/--output`: also writes the report as CSV (`ip,attempts,suspicious`).

`sample_auth.log` in the repo root is a hand-built fixture for manual testing/verification — it deliberately includes paired `Invalid user ...` / `Failed password for invalid user ...` lines for the same login attempt (same pid, same timestamp) to exercise the dedup behavior described below, plus a log-injection attack line (a forged `from 9.9.9.9 port 1` embedded in the username, followed by the real `from 6.6.6.6 port 2222 ssh2` suffix sshd appends) to exercise the anchoring behavior described below.

## Architecture

The whole pipeline lives in `log_analyzer.py` as four pure-ish steps chained in `main()`:

1. `FAILED_PASSWORD_PATTERN` (single regex) — matches only `Failed password for [invalid user] <user> from <ip> port <port> ssh2` lines, anchored to end of line.
2. `count_failed_attempts(lines)` — returns a `Counter` of IP → attempt count.
3. `build_report(counts, threshold)` — turns the counter into a list of `{ip, attempts, suspicious}` dicts, sorted by attempt count descending.
4. `print_report(...)` / `write_csv(...)` — render the report to stdout and, optionally, to a CSV file.

**Important parsing detail:** real sshd logs emit a separate `Invalid user X from <ip> port <port>` line *and* a `Failed password for invalid user X from <ip> port <port> ssh2` line for the same failed attempt. Only the `Failed password` line is matched/counted — do not add an `Invalid user` pattern back in, or attempts will be double-counted.

stdout is reconfigured to UTF-8 in `main()` (`sys.stdout.reconfigure(encoding="utf-8")`) because the report text contains Turkish characters (e.g. `ŞÜPHELİ`) that otherwise get mangled on Windows consoles.

**Log injection:** the username field in `Failed password for <user> from <ip> port <port> ssh2` is attacker-controlled, so `FAILED_PASSWORD_PATTERN` deliberately uses greedy `.+` for the username (not `\S+`) and anchors the pattern to end-of-line with `ssh2$`. This makes the regex always resolve to the *last* `from <ip> port <port> ssh2` on the line — the real suffix sshd appends — even if the attacker stuffs a fake `from 9.9.9.9 port 1` into their own username to spoof a different source IP. Do not revert to `\S+` or drop the `ssh2$` anchor: either change reopens the spoofing hole (or, with `\S+` and no anchor, can cause a forged `from <ip> port <port>` substring earlier in the line to be matched instead of the genuine one).
