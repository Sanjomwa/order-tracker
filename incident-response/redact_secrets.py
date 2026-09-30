"""Redact / detect key-like secret values in evidence (stdlib only).

    python3 redact_secrets.py filter <path-hint>   < in > out   # redact one file's text
    python3 redact_secrets.py filter-diff          < in > out   # redact a unified diff (per-file rules)
    python3 redact_secrets.py scan <dir>                          # exit 1 and print file:line on any hit

A "key-like" name contains PASSWORD, PASSWD, SECRET, TOKEN, API_KEY/APIKEY or PRIVATE_KEY
(case-insensitive). Only literal VALUES are redacted, so code stays readable:

* config-style files (YAML, env, Dockerfile, CI, JSON, shell, ...): the value after
  `KEY: value` or `KEY=value` (quoted or bare);
* Python, JS/TS, HTML and Markdown: only quoted string literals (`KEY = "value"`, `KEY: str = "value"`, `"KEY": "value"`,
  `KEY="value"`), never expressions such as `token_hash=secret_hash(token)`.

Placeholders are left alone: `${...}`, `<...>`, `change-me`, values already `[REDACTED]`, numbers,
JSON structure (`{`, `[`) and SQL bind placeholders (`%(name)s`, `$1`, `?`, `:name`);
matches inside `#` comments of config/shell files are skipped (prose, not values).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REDACTED = "[REDACTED]"
KEY = r"[A-Za-z0-9_.\-]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY)[A-Za-z0-9_.\-]*"

# Config style: optional quote around the key, ':' or '=', optional quote around the value.
CONFIG_RE = re.compile(
    rf"""(?ix)
    (?P<pre>(?<![A-Za-z0-9_{{$])["']?{KEY}["']?[ \t]*[:=][ \t]*)
    (?P<q>["']?)
    (?P<val>(?!\$\{{|<|\[REDACTED\])[^\s"',}}#]+)
    (?P=q)
    """
)
# Python: only string literals.
PY_RE = re.compile(
    rf"""(?ix)
    (?P<pre>(?<![A-Za-z0-9_{{$])["']?{KEY}["']?[ \t]*(?::[ \t]*[A-Za-z_][A-Za-z0-9_\[\]|., ]*?[ \t]*)?[:=][ \t]*)
    (?P<q>["'])
    (?P<val>(?!\$\{{|<|\[REDACTED\])[^"'\n]+)
    (?P=q)
    """
)
# Keys that look secret-like but whose values are not secrets (evidence metadata).
BENIGN_VALUES = {"passed", "failed", "true", "false", "null", "none", "str", "int", "bytes", "bool", "float", "optional", "change-me", "changeme"}


# Code and prose: only quoted literals are values (never expressions or sentences).
LITERAL_ONLY_SUFFIXES = (".py", ".js", ".ts", ".html", ".md")


def _in_comment(line: str, start: int) -> bool:
    """True if a '#' comment starts before `start` on this line (config/shell files)."""

    hash_at = line.find("#")
    return 0 <= hash_at < start and not line[:hash_at].rstrip().endswith(("'", '"'))


# Not literal values: JSON structure, and SQL bind placeholders as recorded in trace
# db.statement attributes (`agents.token_hash = %(token_hash_1)s::VARCHAR`, `$1`, `?`, `:name`).
NON_VALUE_PREFIXES = ("{", "[", "%(", "%s", "$", "?", ":")
NUMERIC_RE = re.compile(r"^-?\d+(\.\d+)?$")  # counts such as "input_tokens": 13256 are not secrets


def _skip(m: re.Match[str], line: str, literal_only: bool) -> bool:
    val = m.group("val")
    return (val.lower() in BENIGN_VALUES or NUMERIC_RE.match(val) is not None
            or val.startswith(NON_VALUE_PREFIXES)
            or (not literal_only and _in_comment(line, m.start())))


def _sub_line(regex: re.Pattern[str], line: str, literal_only: bool) -> str:
    def repl(m: re.Match[str]) -> str:
        if _skip(m, line, literal_only):
            return m.group(0)
        return f"{m.group('pre')}{m.group('q')}{REDACTED}{m.group('q')}"
    return regex.sub(repl, line)


def _sub(regex: re.Pattern[str], text: str, literal_only: bool = False) -> str:
    return "".join(_sub_line(regex, line, literal_only) for line in text.splitlines(keepends=True))


def literal_only(path: str) -> bool:
    return path.endswith(LITERAL_ONLY_SUFFIXES)


def regex_for(path: str) -> re.Pattern[str]:
    return PY_RE if literal_only(path) else CONFIG_RE


def redact_text(text: str, path: str) -> str:
    return _sub(regex_for(path), text, literal_only(path))


def redact_diff(text: str) -> str:
    out, path = [], ""
    for line in text.splitlines(keepends=True):
        if line.startswith("diff --git "):
            path = line.rsplit(" b/", 1)[-1].strip()
        elif line.startswith(("+", "-", " ")) and not line.startswith(("+++", "---")):
            line = line[0] + redact_text(line[1:], path)
        out.append(line)
    return "".join(out)


def find_hits(root: Path) -> list[str]:
    hits = []
    for file in sorted(p for p in root.rglob("*") if p.is_file()):
        try:
            text = file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        name = str(file)
        regex = regex_for(name)
        lit = literal_only(name)
        for lineno, line in enumerate(text.splitlines(), 1):
            for m in regex.finditer(line):
                if not _skip(m, line, lit):
                    hits.append(f"{file.relative_to(root)}:{lineno}")
                    break
    return hits


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[0] == "filter":
        sys.stdout.write(redact_text(sys.stdin.read(), argv[1]))
        return 0
    if argv == ["filter-diff"]:
        sys.stdout.write(redact_diff(sys.stdin.read()))
        return 0
    if len(argv) == 2 and argv[0] == "scan":
        hits = find_hits(Path(argv[1]))
        for hit in hits:
            print(hit)
        return 1 if hits else 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except BrokenPipeError:
        # A downstream `head -n N` closed the pipe; the truncated output is intended.
        import os

        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
