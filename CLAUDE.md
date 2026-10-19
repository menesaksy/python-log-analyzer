# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single-file Python CLI tool, `log_analyzer.py`, that parses Linux SSH/`auth.log` files, counts failed login attempts per IP address, flags IPs at or above a threshold as suspicious, and flags an IP as a probable breach ("OLASI İHLAL") if a successful login follows threshold-or-more failed attempts from that same IP. No build system or package manifest; tests are `unittest`-based in `test_log_analyzer.py` (stdlib only, no extra dependencies) — run with `python -m unittest test_log_analyzer -v`.

## Running the tool

```
python log_analyzer.py <logfile> [-t|--threshold N] [-o|--output report.csv]
```

- `logfile` (positional, required): path to the auth log to analyze.
- `-t/--threshold` (default `5`): minimum failed-attempt count for an IP to be marked suspicious.
- `-o/--output`: also writes the report as CSV (`ip,attempts,suspicious,breach`).

`sample_auth.log` in the repo root is a hand-built fixture for manual testing/verification — it deliberately includes paired `Invalid user ...` / `Failed password for invalid user ...` lines for the same login attempt (same pid, same timestamp) to exercise the dedup behavior described below, a log-injection attack line (a forged `from 9.9.9.9 port 1` embedded in the username, followed by the real `from 6.6.6.6 port 2222 ssh2` suffix sshd appends) to exercise the anchoring behavior described below, and a 5-failures-then-1-success sequence from `45.33.22.11` so the default threshold (5) actually produces an "OLASI İHLAL" row when you run the CLI against it.

## Architecture

`log_analyzer.py`'s `main()` chains these steps:

1. `FAILED_PASSWORD_PATTERN` / `ACCEPTED_PASSWORD_PATTERN` (regexes) — match only full syslog lines of the form `<mon> <day> <HH:MM:SS> <host> sshd[<pid>]: Failed password for <user> from <ip> port <port> ssh2` / `... Accepted password for ...`, anchored to the *start* of the line (`^`) through the syslog/sshd prefix and to end of line (`ssh2$`) (see Security notes).
2. `analyze(lines, threshold)` — the single pass `main()` actually uses: walks `lines` once, keeping a running (never-reset) failed-attempt count per IP, and whenever an `Accepted password` line for an IP arrives, flags that IP as breached if its running failed count has already reached `threshold`. Returns `(failed_counts, breached_ips)`. Order matters — a success recorded *before* the failures that would clear the threshold does not count as a breach.
3. `count_failed_attempts(lines)` — the original failed-only counter, kept only for backward compatibility with its existing tests; `main()` no longer calls it (superseded by `analyze`).
4. `build_report(counts, threshold, breached_ips=frozenset())` — turns the counts into a list of `{ip, attempts, suspicious, breach}` dicts, sorted by attempt count descending.
5. `print_report(...)` / `write_csv(...)` — render the report to stdout and, optionally, to a CSV file. Status priority in the printed report is `OLASI İHLAL` (breach) > `ŞÜPHELİ` (suspicious) > `normal`.

`main()` passes the open file object straight into `analyze(f, ...)` rather than materializing it with `list(f)`/`readlines()` — this keeps the one-pass, constant-memory read. Don't change `analyze` to require two passes (e.g. by calling `count_failed_attempts` and a separate breach-detection function on the same `lines`) without also changing `main()` to materialize the lines first, since a file object can only be iterated once.

**Important parsing detail:** real sshd logs emit a separate `Invalid user X from <ip> port <port>` line *and* a `Failed password for invalid user X from <ip> port <port> ssh2` line for the same failed attempt. Only the `Failed password` line is matched/counted — do not add an `Invalid user` pattern back in, or attempts will be double-counted.

stdout is reconfigured to UTF-8 in `main()` (`sys.stdout.reconfigure(encoding="utf-8")`) because the report text contains Turkish characters (e.g. `ŞÜPHELİ`) that otherwise get mangled on Windows consoles.

## Security notes

The username in `Failed password for <user> from <ip> port <port> ssh2` is attacker-controlled — an attacker can set their own username to arbitrary text, including something shaped like a fake `from <ip> port <port>` fragment. `FAILED_PASSWORD_PATTERN` is deliberately written as greedy `.+` for the username, anchored to end-of-line with `ssh2$`, to defend against this:

- **Why not `\S+` for the username:** `\S+` cannot cross whitespace, so a forged username like `a from 9.9.9.9 port 1` only matches the single token `a`, leaving the rest of that forged text unconsumed. Combined with the `ssh2$` anchor, the regex then fails to match the line at all — the real attempt (and its real source IP) silently disappears from the report. This is an evasion bug, not a fix: it lets an attacker hide their real IP by poisoning their own username.
- **Why not an unanchored regex:** without `ssh2$`, `re.search` returns the *first* `from <ip> port <port>` substring it finds. A forged username like `a from 9.9.9.9 port 1` puts a fake match earlier in the line than the real `from <ip> port <port> ssh2` suffix sshd appends, so the fake IP gets captured and counted — an innocent IP (`9.9.9.9` in `sample_auth.log`'s attack line) gets blamed while the real attacker (`6.6.6.6`) goes uncounted. This is IP spoofing via log injection.
- **Why greedy `.+` + `ssh2$` together works:** greedy `.+` first tries to consume the rest of the line, then backtracks from the end to find the *last* possible `from <ip> port <port> ssh2$` match. Since sshd always appends the genuine source info as the true suffix of the line, this is always the real one, regardless of what the attacker stuffs into the username earlier in the line.

Do not reintroduce `\S+` or drop the `ssh2$` anchor in `FAILED_PASSWORD_PATTERN` — either change reopens one of the two holes above.

**Equivalent mutant (deliberately untested):** a mutation-testing pass confirmed that dropping the trailing `$` from `FAILED_PASSWORD_PATTERN` (keeping `ssh2` but not anchoring it to end-of-line) is not caught by any test, and no test was added for it. This is an *equivalent mutant* for this codebase's actual threat model, not a real gap: the only way the `$` could matter is a line with extra content *after* the genuine `ssh2` — but `ssh2` is the literal suffix sshd itself appends as the true end of the line, after the attacker-controlled username, so the attacker has no field left to control that would place text after it. Don't chase 100% mutation-kill on this one; if `main()`'s line-reading ever changes to join/concatenate raw lines before matching (instead of matching one syslog line at a time), revisit this assumption.

**The `^` start-of-line syslog-prefix anchor.** Both regexes additionally require the full syslog prefix (`^\S+\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s+sshd\[\d+\]: `, see `SYSLOG_SSHD_PREFIX`) anchored with `^` — not just present anywhere via `.search()`, but at the true start of the line. Without `^`, a forged username on a `Failed password` line could contain a bare `sshd[1]: Accepted password for x from <ip> port <port> ssh2` fragment anywhere mid-line, and `.search()` would happily find it, fabricating a fake successful login for `<ip>` (potentially forging an "OLASI İHLAL" that never happened).

`^` closes this completely, including the nested-forgery case (attacker also fakes their own `sshd[<pid>]: ` prefix inside the username): the **real** syslog prefix is always the first thing on a genuine log line, written by syslog itself — never something the attacker-controlled username can precede. Any text the attacker stuffs into their own username is necessarily positioned *after* the real prefix and the real `Failed password for ` literal, i.e. never at position 0. So a forged `sshd[<pid>]: Accepted password for ...` fragment can never satisfy `^`, no matter how convincingly it mimics the real prefix (see `test_fake_accepted_in_username_not_treated_as_breach` and `test_nested_forged_prefix_in_username_not_treated_as_breach`).

One consequence verified directly: with `^` anchoring in place, a line can satisfy *at most one* of `FAILED_PASSWORD_PATTERN` / `ACCEPTED_PASSWORD_PATTERN` (a line starts with either `Failed` or `Accepted` right after the prefix, never both) — so the order in which `analyze()` checks them no longer affects correctness. (Checking `ACCEPTED_PASSWORD_PATTERN` before `FAILED_PASSWORD_PATTERN` was tried as an experiment and the full test suite still passed, confirming this.) Do not drop the `^` anchor on either pattern — that's what makes this order-independence (and the nested-forgery defense) hold.
