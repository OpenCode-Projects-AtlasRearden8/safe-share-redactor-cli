#!/usr/bin/env python3
"""share-redactor: privacy-first text redaction, review, and undo.

Spots emails, phone numbers, dates of birth, account numbers, and names
from your own blocklist; you review every finding, then it saves a
redacted copy plus a local undo map. Pure stdlib; nothing leaves the
machine.

Copyright (c) 2026 Asdale Dynamics, LLC. MIT licensed.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.0.0"
PROG = "share-redactor"
MAP_FORMAT = "share-redactor-undo-map"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_ABORTED = 2

# ---------- detection ----------

EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}"
)

# US-style phones: (555) 123-4567 / 555-123-4567 / 555.123.4567 / +1 555...
PHONE_RE = re.compile(
    r"(?<!\d)"
    r"(?:\+?1[ \.-]?)?"
    r"(?:\(\d{3}\)[ \.-]?|\d{3}[ \.-])"
    r"\d{3}[ \.-]\d{4}"
    r"(?!\d)"
)

MONTH = r"(?i:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[A-Za-z]*"

DATE_PAT = (
    r"\d{1,2}\s?[/\-.]\s?\d{1,2}\s?[/\-.]\s?(?:\d{4}|\d{2})"  # 01/31/1980, 1-31-80
    r"|\d{4}[.\-/]\d{1,2}[.\-/]\d{1,2}"  # 1980-01-31
    rf"|{MONTH}\.?\s+\d{{1,2}},?\s+\d{{4}}"  # March 3, 1990
    rf"|\d{{1,2}}\s+{MONTH}\.?,?\s+\d{{4}}"  # 3 March 1990
)

# DOB is only flagged when a birth-context label introduces the date.
DOB_RE = re.compile(
    r"(?<![\w])"
    r"(?i:(?:(?:d\.?o\.?b\.?)|date\s+of\s+birth|birth\s+date|birthday|born(?:\s+on)?))"
    r"\b[ \t]*[:\-]?[ \t]*"
    rf"(?:{DATE_PAT})(?!\d)"
)

# Account numbers gated behind an "account/acct" label; digits validated in code.
ACCOUNT_RE = re.compile(
    r"(?i)(?<![\w])"
    r"(?:account(?:\s+number|\s+num|\s+id)?|acct\.?|acct\s+no\.?|acct\s*#?)"
    r"\s*(?:no\.?|num|number|nbr|id)?\s*[#:]?[ \t]*"
    r"(?<!\d)(\d(?:[\s\-]{0,2}\d){5,15})(?!\d)"
)

TYPE_ORDER = {"EMAIL": 0, "PHONE": 1, "DOB": 2, "ACCOUNT": 3, "NAME": 4}

PLACEHOLDER = {
    "EMAIL": "[EMAIL]",
    "PHONE": "[PHONE]",
    "DOB": "[DOB]",
    "ACCOUNT": "[ACCOUNT]",
    "NAME": "[NAME]",
}

LITERAL_TOKEN_RE = re.compile(r"\[(?:EMAIL|PHONE|DOB|ACCOUNT|NAME)\]")


def _digit_run_around(text: str, start: int, end: int) -> tuple[int, int, int]:
    """Expand a span outward over digits and hand-written run-on separators
    (dashes, dots, parens). Spaces stop the expansion so neighbouring
    items (e.g. two phones '555-1-2 555-3-4') stay independent. Returns
    (new_start, new_end, digit_count) of the connected digit run."""
    s, e = start, end
    n = len(text)
    while s > 0 and (text[s - 1].isdigit() or text[s - 1] in "-.()"):
        s -= 1
    while e < n and (text[e].isdigit() or text[e] in "-.()"):
        e += 1
    digits = sum(1 for ch in text[s:e] if ch.isdigit())
    return s, e, digits


def _phone_ok(text: str, start: int, end: int) -> bool:
    """Reject phones that sit inside a longer digit chain
    (credit cards, serial numbers, timestamps)."""
    _, _, digits = _digit_run_around(text, start, end)
    return digits <= 11  # '+1' plus 10 digits max


def _make_finder(regex, rtype, matcher=None):
    def find(text):
        for m in regex.finditer(text):
            if matcher and not matcher(text, m.start(), m.end()):
                continue
            yield {"type": rtype, "start": m.start(), "end": m.end(),
                   "text": m.group()}
    return find


def _account_finder(text):
    for m in ACCOUNT_RE.finditer(text):
        digits = sum(1 for ch in m.group() if ch.isdigit())
        if 6 <= digits <= 16:
            yield {"type": "ACCOUNT", "start": m.start(), "end": m.end(),
                   "text": m.group()}


def _make_name_finder(patterns):
    def find(text):
        for pat in patterns:
            for m in pat.finditer(text):
                yield {"type": "NAME", "start": m.start(), "end": m.end(),
                       "text": m.group()}
    return find


def find_all(text, name_patterns):
    finders = [
        _make_finder(EMAIL_RE, "EMAIL"),
        _make_finder(PHONE_RE, "PHONE", _phone_ok),
        _make_finder(DOB_RE, "DOB"),
        _account_finder,
        _make_name_finder(name_patterns),
    ]
    out = []
    for f in finders:
        out.extend(f(text))
    return out


def resolve_overlaps(findings):
    """Remove overlapping findings, earlier + longer + higher-precedence win."""
    ordered = sorted(
        findings,
        key=lambda f: (f["start"], -(f["end"] - f["start"]),
                       TYPE_ORDER.get(f["type"], 9)),
    )
    kept = []
    for f in ordered:
        if all(f["end"] <= k["start"] or f["start"] >= k["end"] for k in kept):
            kept.append(f)
    kept.sort(key=lambda f: f["start"])
    return kept


def detect_all(text, name_patterns):
    return resolve_overlaps(find_all(text, name_patterns))


def compile_blocklist(path):
    """Read a blocklist file: one name per line; blank lines and #-comments ignored."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"blocklist not found: {path}")
    raw = p.read_text(encoding="utf-8-sig", errors="strict")
    names = []
    for i, line in enumerate(raw.splitlines(), 1):
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        names.append(entry)
    patterns = [re.compile(r"(?<!\w)" + re.escape(n) + r"(?!\w)", re.IGNORECASE)
                for n in names]
    return names, patterns


# ---------- text helpers ----------

def read_text_file(path):
    p = Path(path)
    if not p.is_file():
        return None, f"file not found: {path}"
    raw = p.read_bytes()
    if b"\x00" in raw:
        return None, f"skipping {path}: looks like a binary file"
    try:
        return raw.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, f"skipping {path}: not valid UTF-8 text"


def line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def context_snippet(text, start, end, width=64):
    half = max((width - (end - start)) // 2, 10)
    left = max(0, start - half)
    right = min(len(text), end + half)
    if left > 0:
        nl = text.rfind("\n", 0, left)
        left = nl + 1
    pre = ("\u2026" if left > 0 else "") + text[left:start]
    mid = text[start:end]
    post = text[end:right] + ("\u2026" if right < len(text) else "")
    flat = (pre + "[" + mid + "]" + post).replace("\n", "\\n").replace("\t", "\\t")
    if len(flat) > width + len(mid) + 4:
        flat = flat[: width + len(mid) + 1] + "\u2026"
    return flat


# ---------- interactive review ----------

def review(text, findings, auto=None):
    """Choose which findings to redact.

    Returns list of chosen findings, or None if the user quit/aborted.
    """
    if auto == "all":
        return list(findings)
    if auto == "none":
        return []

    print(f"\nFound {len(findings)} candidate item(s). Decide one at a time.\n")
    kept = []
    decisions = {}  # type -> "ask" | "all" | "none"

    for idx, f in enumerate(findings, 1):
        rtype = f["type"]
        mode = decisions.get(rtype, "ask")
        if mode == "all":
            kept.append(f)
            print(f"{idx}/{len(findings)}  {rtype}  ^ accepted with the rest")
            continue
        if mode == "none":
            continue
        snippet = context_snippet(text, f["start"], f["end"]).strip()
        print(f"{idx}/{len(findings)}  {rtype}  line {line_of(text, f['start'])}")
        print(f"    {snippet}")
        prompt = "    redact? [Y]es / [n]o / [A]ll remaining %s / [S]kip all %s / [q]uit: " % (
            rtype, rtype,
        )
        while True:
            try:
                ans = input(prompt).strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return None
            if ans == "":
                ans = "y"
            if ans in ("y", "n", "a", "s", "q"):
                break
            print("    answer with one letter: y / n / a / s / q")
        if ans == "y":
            kept.append(f)
        elif ans == "n":
            pass
        elif ans == "a":
            kept.append(f)
            decisions[rtype] = "all"
            print(f"    (accepting remaining {rtype} items)")
        elif ans == "s":
            decisions[rtype] = "none"
            print(f"    (skipping remaining {rtype} items)")
        elif ans == "q":
            print("\nAborted. Nothing was written.")
            return None
    return kept


# ---------- redact / undo maps ----------

def build_redacted(text, kept):
    """Apply replacements back-to-front; return (redacted_text, entries)."""
    redacted = text
    entries = []
    for f in sorted(kept, key=lambda f: f["start"], reverse=True):
        token = PLACEHOLDER[f["type"]]
        redacted = redacted[: f["start"]] + token + redacted[f["end"]:]
        entries.append({
            "type": f["type"],
            "start": f["start"],
            "end": f["end"],
            "original": f["text"],
            "line": line_of(text, f["start"]),
        })
    entries.reverse()  # ascending original order
    return redacted, entries


def default_paths(src):
    src = Path(src)
    out = src.with_name(src.stem + ".redacted" + src.suffix)
    mapp = out.with_name(out.name + ".map.json")
    return out, mapp


def write_map(mapp, src, out, entries):
    data = {
        "format": MAP_FORMAT,
        "version": 1,
        "tool": PROG,
        "tool_version": VERSION,
        "created": datetime.now(timezone.utc).isoformat(),
        "original_file": str(Path(src).resolve()),
        "redacted_file": str(Path(out).resolve()),
        "placeholder_count": len(entries),
        "entries": entries,
    }
    with open(mapp, "w", encoding="utf-8", newline="") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def load_map(path):
    p = Path(path)
    if not p.is_file():
        return None, f"undo map not found: {path}"
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, f"cannot parse undo map: {path}"
    if not isinstance(data, dict) or data.get("format") != MAP_FORMAT:
        return None, f"{path} is not a {PROG} undo map"
    entries = data.get("entries")
    if not isinstance(entries, list):
        return None, f"undo map is missing 'entries': {path}"
    for e in entries:
        if not all(k in e for k in ("type", "original")):
            return None, f"undo map entry is malformed in {path}"
        if e["type"] not in PLACEHOLDER:
            return None, f"unknown type '{e["type"]}' in {path}"
    return data, None


def apply_undo(text, entries):
    """Replace the k-th placeholder occurrence of each type with the k-th
    recorded original of that type. Raises ValueError on count mismatch."""
    queues = {}
    for e in entries:
        queues.setdefault(e["type"], deque()).append(e["original"])

    tokens = []
    for t in queues:
        for m in re.finditer(re.escape(PLACEHOLDER[t]), text):
            tokens.append((m.start(), t))
    tokens.sort()

    for t, q in queues.items():
        actual = sum(1 for _, tt in tokens if tt == t)
        if actual != len(q):
            raise ValueError(
                f"undo mismatch for {t}: map records {len(q)}, "
                f"redacted text contains {actual} {PLACEHOLDER[t]} token(s). "
                "The document changed after redaction; undo map may be stale."
            )

    pieces = []
    pos = 0
    for start, t in tokens:
        pieces.append(text[pos:start])
        pieces.append(queues[t].popleft())
        pos = start + len(PLACEHOLDER[t])
    pieces.append(text[pos:])
    return "".join(pieces)


# ---------- CLI commands ----------

def cmd_redact(args):
    text, err = read_text_file(args.file)
    if err:
        print(f"error: {err}", file=sys.stderr)
        return EXIT_ERROR

    name_patterns = []
    if args.blocklist:
        try:
            _, name_patterns = compile_blocklist(args.blocklist)
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR

    out = Path(args.out) if args.out else default_paths(args.file)[0]
    mapp = Path(args.map) if args.map else default_paths(args.file)[1]
    if out.resolve() == Path(args.file).resolve():
        print("error: output must differ from the source file", file=sys.stderr)
        return EXIT_ERROR

    findings = detect_all(text, name_patterns)
    literal_count = len(LITERAL_TOKEN_RE.findall(text))
    if literal_count:
        print(
            f"note: source already contains {literal_count} "
            "placeholder-like token(s) (e.g. literal [EMAIL] text); "
            "undo counts could be confused by those.",
            file=sys.stderr,
        )

    kept = review(text, findings, auto=args.auto)
    if kept is None:
        return EXIT_ABORTED

    redacted, entries = build_redacted(text, kept)
    out.write_text(redacted, encoding="utf-8", newline="")
    write_map(mapp, args.file, out, entries)

    counts = {}
    for e in entries:
        counts[e["type"]] = counts.get(e["type"], 0) + 1
    tally = ", ".join(f"{v} {k}" for k, v in counts.items()) or "no findings"
    print(f"\n{args.file}: {tally}")
    print(f"redacted copy: {out}")
    print(f"undo map     : {mapp}")
    print(f"restore later with: {PROG} undo {out}")
    return EXIT_OK


def cmd_scan(args):
    text, err = read_text_file(args.file)
    if err:
        print(f"error: {err}", file=sys.stderr)
        return EXIT_ERROR

    name_patterns = []
    if args.blocklist:
        try:
            _, name_patterns = compile_blocklist(args.blocklist)
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR

    findings = detect_all(text, name_patterns)
    print(f"{args.file}: {len(findings)} candidate item(s)")
    for i, f in enumerate(findings, 1):
        snippet = context_snippet(text, f["start"], f["end"]).strip()
        print(f"{i:4d}  {f['type']:<8} line {line_of(text, f['start']):<4} {snippet}")
    if not findings:
        print("nothing flagged.")
    return EXIT_OK


def cmd_undo(args):
    mapp = Path(args.map) if args.map else Path(str(args.file) + ".map.json")
    data, err = load_map(mapp)
    if err:
        print(f"error: {err}", file=sys.stderr)
        return EXIT_ERROR

    redacted_path = Path(args.file)
    if not redacted_path.is_file():
        print(f"error: file not found: {args.file}", file=sys.stderr)
        return EXIT_ERROR

    out = Path(args.out) if args.out else Path(data["original_file"])
    if not out.is_absolute():
        out = (Path.cwd() / out).resolve()
    if out.exists() and not args.force:
        if sys.stdin.isatty():
            try:
                ans = input(f"overwrite existing {out}? [y/N]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                ans = None
            if ans != "y":
                print("aborted. Tip: use --out PATH or --force.")
                return EXIT_ABORTED
        else:
            print(
                f"error: {out} already exists; use --force or --out PATH",
                file=sys.stderr,
            )
            return EXIT_ERROR
    if out.resolve() == redacted_path.resolve():
        print("error: output must differ from the redacted file", file=sys.stderr)
        return EXIT_ERROR

    text, err = read_text_file(redacted_path)
    if err:
        print(f"error: {err}", file=sys.stderr)
        return EXIT_ERROR

    entries = [e for e in data.get("entries", []) if isinstance(e, dict)]
    try:
        restored = apply_undo(text, entries)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    out.write_text(restored, encoding="utf-8", newline="")
    print(f"restored {len(entries)} item(s) -> {out}")
    return EXIT_OK


# ---------- argument parsing ----------

def build_parser():
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "Redact a document before you share it. Finds emails, phone "
            "numbers, dates of birth, account numbers, and names from your "
            "own blocklist. You review each finding; a local undo map "
            "remembers where everything went."
        ),
        epilog=(
            "examples:\n"
            "  %(prog)s notes.txt\n"
            "  %(prog)s redact notes.txt --blocklist names.txt --auto all\n"
            "  %(prog)s scan notes.txt --blocklist names.txt\n"
            "  %(prog)s undo notes.redacted.txt\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    sub = parser.add_subparsers(dest="command", required=False)

    p_redact = sub.add_parser("redact", help="review and redact a document")
    p_redact.add_argument("file", help="text file to redact")
    p_redact.add_argument("-b", "--blocklist", metavar="FILE",
                          help="file with one name per line to also redact")
    p_redact.add_argument("-o", "--out", metavar="FILE",
                          help="(redacted output path; default: NAME.redacted.EXT)")
    p_redact.add_argument("-m", "--map", metavar="FILE",
                          help="undo map path (default: <out>.map.json)")
    p_redact.add_argument("--auto", choices=("all", "none"), metavar="MODE",
                          help="skip the interactive review: 'all' redacts "
                               "every finding, 'none' redacts nothing")

    p_scan = sub.add_parser("scan", help="list findings without changing anything")
    p_scan.add_argument("file", help="text file to inspect")
    p_scan.add_argument("-b", "--blocklist", metavar="FILE",
                        help="file with one name per line")

    p_undo = sub.add_parser("undo", help="restore a redacted copy via its map")
    p_undo.add_argument("file", help="redacted file (e.g. NAME.redacted.EXT)")
    p_undo.add_argument("-m", "--map", metavar="FILE",
                        help="undo map path (default: <file>.map.json)")
    p_undo.add_argument("-o", "--out", metavar="FILE",
                        help="where to write the restored copy "
                             "(default: original path recorded in the map)")
    p_undo.add_argument("--force", action="store_true",
                        help="overwrite the output file if it exists")
    return parser


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] not in ("redact", "scan", "undo") and not argv[0].startswith("-"):
        argv.insert(0, "redact")

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "undo":
        return cmd_undo(args)
    if args.command == "redact":
        return cmd_redact(args)
    parser.print_help()
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
