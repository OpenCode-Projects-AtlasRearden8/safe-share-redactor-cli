# STATUS.md — share-redactor

## What was built

`share-redactor` — a privacy-first command-line tool that redacts a
document before you share it with an AI, a stranger, or a support inbox.
Implemented as a single-file Python CLI (`share_redactor.py`), pure
standard library; no network access, no secrets, nothing leaves the
machine.

- **Auto-spotting** for emails, US-style phone numbers, dates of birth
  (birth-label gated: `DOB:`, `Date of Birth:`, `born on`, `birthday`),
  account numbers (label gated: `Account #`/`acct no:`, 6–16 digits), and
  whole-word case-insensitive names loaded from a user blocklist file
  (`#` comments and blanks ignored).
- **Interactive review**: each finding is shown with type, line number, and
  a context window; choose `y` (accept), `n` (skip), `a` (accept all
  remaining of that type), `s` (skip all remaining of that type), `q`
  (quit; nothing is written). Blank input = accept. Invalid input re-prompts.
- **Non-interactive modes** for pipelines: `--auto all` (redact everything)
  and `--auto none` (change nothing) skip the prompts.
- **Outputs written beside the source**: `intake.txt` → `intake.redacted.txt`
  plus `intake.redacted.txt.map.json`. Redacted items become stable
  placeholders: `[EMAIL]`, `[PHONE]`, `[DOB]`, `[ACCOUNT]`, `[NAME]`.
- **Undo map** (JSON, `format: "share-redactor-undo-map"`, v1): records each
  finding's type, original offsets, original text, and line number. `undo`
  restores the k-th placeholder occurrence of each type to the k-th recorded
  original; a count mismatch between map and file is an error, never a
  silent mis-rebuild.
- **Extras**: `scan` subcommand (list candidates, write nothing); binary and
  non-UTF-8 files are refused with a clear message; overwrite of an existing
  undo target requires confirmation (interactive) or `--force`; literal
  `[EMAIL]`-style tokens already in a source file trigger a warning (they
  could confuse undo counting); bare-file invocation
  (`share_redactor.py file.txt`) is shorthand for `redact`.

## How to run it

```bash
Python 3.10+ (tested on 3.13), no dependencies.

python3 share_redactor.py scan docs.txt --blocklist names.txt   # preview
python3 share_redactor.py redact docs.txt --blocklist names.txt # review + redact
python3 share_redactor.py redact docs.txt --auto all            # unattended
python3 share_redactor.py undo docs.redacted.txt                # restore (-o PATH to redirect)
```

## Verification results (2026-10-27)

- `python3 -m pytest tests` → **63 passed, 0 failed, 0 skipped** in ~0.1 s.
- `python3 -W error::SyntaxWarning -m py_compile share_redactor.py` → clean.
- Manual end-to-end smoke test on a 12-line demo intake document with 10
  planted items (2 emails, 3 phones, 2 DOBs, 1 account, 2 blocklist names):
  scan listed all 10; `redact --auto all` redacted exactly those; SSN-shaped
  `123-45-6789`, card `1234 5678 9012 3454`, and short/overlong account
  digits were correctly ignored; `undo` reproduced the original file
  **byte-for-byte** (`diff` clean, including CRLF round-trip).
- Interactive flow exercised via piped stdin (`y`/`n`/`a`/`s`/`q`, blank,
  invalid answers, and EOF) — abort paths write no files and return exit
  code 2.

## Known gaps / honest limitations

- Phone and email patterns are conservative: US-style phone formats only
  (no international variants like `+44 20 7946 0018`); exotic email forms
  (quoted local parts, IP-literal domains) are not caught. Use the
  blocklist for names/IDs the regexes can't see.
- Single-letter TLDs (`a@b.c`) are deliberately not treated as emails.
- A legal SSN or a driver's license number without a label followed by a
  phone-shaped dash group could still be flagged as a PHONE candidate —
  review exists for exactly this; flag, then skip.
- Literal placeholder-shaped text already present in a source document
  (e.g. the words `[EMAIL]` in a template) makes undo count-verification
  refuse; the tool warns at redact time instead of guessing.
- Undo needs the map to stay untouched along with the redacted copy — the
  map contains the originals, so handle both with equal care when sharing.
- Only flat UTF-8 text files (one file per run); no PDF/DOCX/CSV parsing.
- No automated test for terminal width/very long context lines in
  interactive mode; cosmetic truncation is applied but not asserted.

## Repo

- Committed on the existing git identity (`Dylan Asdale`), plain commit
  message, no co-authored-by trailers; not pushed anywhere.
