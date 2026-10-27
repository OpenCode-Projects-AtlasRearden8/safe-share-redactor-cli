# share-redactor

Privacy-first CLI that redacts a document before you share it with an AI, a
stranger, or a support inbox. It auto-spots emails, phone numbers, dates of
birth, account numbers, and names from your own blocklist — then you review
each finding one at a time: accept or skip. It saves a redacted copy *beside*
a local **undo map**, so you can put everything back later if you change your
mind. Pure Python standard library. Nothing ever leaves your machine.

Part of the beginner-friendly, local-first toolkit from
**Asdale Dynamics, LLC** (Dylan Asdale, *The Massive AI Manual*).

## Why another redactor?

Most "anonymize this" tools either send your text somewhere you can't see, or
sweep everything away and leave you with a useless, unrevivable document.
share-redactor does the opposite:

- You see every candidate and decide, item by item (or in batches per type).
- Over-redacting a document is annoying; under-redacting it is a leak. With
  the local undo map you can always step back.
- It's a plain single-file Python script. One file, no dependencies, no
  network calls, works offline anywhere Python 3 runs.

## Quick start

```bash
# look before you leap: list candidates, change nothing
python3 share_redactor.py scan intake.txt --blocklist names.txt

# review each finding interactively
python3 share_redactor.py redact intake.txt --blocklist names.txt

# accept/skip everything without prompts (great for pipelines)
python3 share_redactor.py redact intake.txt --blocklist names.txt --auto all
python3 share_redactor.py redact intake.txt --auto none

# later: put the original back
python3 share_redactor.py undo intake.redacted.txt            # back to intake.txt
python3 share_redactor.py undo intake.redacted.txt -o copy.txt
```

For `intake.txt` the redacted copy is written next to it as
`intake.redacted.txt`, with the undo map at `intake.redacted.txt.map.json`.

## Commands

```text
  y      redact this one (or press Enter)
  n      skip this one
  A      redact this one and all remaining of this type (accept-all)
  S      skip this one and all remaining of this type (skip-all)
  q      quit now; writes nothing
```

- `redact FILE [--blocklist FILE] [-o FILE] [--map FILE] [--auto all|none]` —
  find, review, write the redacted copy and the undo map.
- `scan FILE [--blocklist FILE]` — print candidates with lines and context; writes nothing.
- `undo FILE [-m FILE] [-o FILE] [--force]` — restore using the undo map.

`python3 share_redactor.py intake.txt` also works: giving it a plain file path
is shorthand for `redact`.

## The blocklist

```text
# one name (or phrase) per line; blanks and #comments are ignored
Jo White
White & Co Accounting
Acme Corp
```

Matching is whole-word and case-insensitive, so `Jo White` matches
`jo white` but not `Jo Whitener`. Put anything else you don't want leaving
the house in there — client names, your street address, the name of your
book series, whatever.

## What it spots (and how carefully)

| Type    | Examples it catches                      | Guardrails |
|---------|------------------------------------------|------------|
| EMAIL   | `jo.white@mail.example.com`, `a@b.co`    | needs a real-looking domain; trailing periods excluded |
| PHONE   | `(555) 010-4466`, `555.019.8877`, `+1 800-555-0199` | ignores SSN-shaped `123-45-6789` and dash-chained long numbers |
| DOB     | `DOB: 04/02/1988`, `Date of Birth: March 3, 1990`, `born on 1980-01-31` | birth labels only — random dates are left alone |
| ACCOUNT | `Account #0044-1123-9988`, `acct no: 0043-2198-7654` | account/acct label, 6–16 digits |
| NAME    | anything from your blocklist             | case-insensitive whole words |

Every redacted item is replaced by a stable placeholder: `[EMAIL]`,
`[PHONE]`, `[DOB]`, `[ACCOUNT]`, `[NAME]`.

## The undo map

The map is an ordinary JSON file with an exportable `format` marker:

```json
{
  "format": "share-redactor-undo-map",
  "version": 1,
  "original_file": "/home/you/intake.txt",
  "redacted_file": "/home/you/intake.redacted.txt",
  "entries": [
    { "type": "EMAIL", "start": 42, "original": "josie.white@example.com", "line": 4 }
  ]
}
```

It carries, for each finding, the placeholder type, its original position,
the original text, and the line number — enough to `undo` exactly, using an
ordinary JSON file you can inspect by eye. If the redacted copy no longer
matches the map (counts differ), undo refuses with a clear error rather than
guessing.

## Privacy and safety notes

- Everything runs locally with the Python standard library only; there are no
  network calls, telemetry, or accounts anywhere in this script.
- The undo map contains the originals — that's the point — so **treat
  `*.map.json` with the same care as the document itself** when sharing
  folders, and store it only where you keep the original.
- Never edit the redacted copy (add/remove placeholders) if you plan to undo;
  run scan again or re-redact from the original instead.
- This is a helper, not a lawyer: a review pass is still a person's decision.

## Running the tests

```bash
python3 -m pytest tests
```

## Files

- `share_redactor.py` — the tool (single file, stdlib only)
- `tests/test_share_redactor.py` — pytest suite: regex edges, review flow, undo maps
- `LICENSE` — MIT
- `STATUS.md` — current state, verification results, known gaps

## License

MIT. Copyright (c) 2026 Asdale Dynamics, LLC.
