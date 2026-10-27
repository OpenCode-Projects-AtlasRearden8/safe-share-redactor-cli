"""Tests for share_redactor: regex edge cases, review flow, undo maps."""

import json

import pytest

import share_redactor as sr


def write(tmp_path, name, text=""):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8", newline="")
    return p


def types_of(findings):
    return [(f["type"], f["text"]) for f in findings]


# ---------- emails ----------

def test_email_basic():
    fs = sr.detect_all("mail me at alice@example.com thanks", [])
    assert types_of(fs) == [("EMAIL", "alice@example.com")]


def test_email_edge_formats():
    text = "a.b+%tag@sub.deep.example.co.uk i_am@localhost a@b.co a@b.c"
    got = {f["text"] for f in sr.detect_all(text, [])}
    assert "a.b+%tag@sub.deep.example.co.uk" in got
    assert "i_am@localhost" not in got  # no TLD, not an address
    assert "a@b.co" in got
    assert "a@b.c" not in got  # single-letter TLD is not a domain


def test_email_trailing_period_not_included():
    fs = sr.detect_all("write to bob@example.com. See you!", [])
    assert types_of(fs) == [("EMAIL", "bob@example.com")]


def test_email_double_at_keeps_tail_only():
    fs = sr.detect_all("weird a@b@c.com case", [])
    assert types_of(fs) == [("EMAIL", "b@c.com")]


# ---------- phones ----------

@pytest.mark.parametrize("phone", [
    "(555) 123-4567",
    "555-123-4567",
    "555.123.4567",
    "555 123 4567",
    "+1 555-123-4567",
    "1-800-555-0199",
])
def test_phone_formats(phone):
    assert types_of(sr.detect_all(phone, [])) == [("PHONE", phone)]


@pytest.mark.parametrize("not_phone", [
    "123-45-6789",            # SSN shape
    "1234 5678 9012 3454",    # credit-card digit chain
    "10/05/1975",             # date with slashes
    "123456",                 # bare digits, no separators
    "2026-10-27",             # ISO date
])
def test_phone_non_matches(not_phone):
    assert sr.detect_all(not_phone, []) == []


def test_phone_inside_longer_dash_chain_rejected():
    text = "contract 0044-555-123-4567 signed"
    assert sr.detect_all(text, []) == []


def test_consecutive_phones_both_flagged():
    text = "call 555-111-2222 or 555-333-4444"
    assert types_of(sr.detect_all(text, [])) == [
        ("PHONE", "555-111-2222"), ("PHONE", "555-333-4444")]


# ---------- dates of birth ----------

@pytest.mark.parametrize("line", [
    "DOB: 01/31/1980",
    "dob 1-31-80",
    "Date of Birth: March 3, 1990",
    "date of birth 1980-01-31",
    "Born on 3 March 1990",
    "Birthday: 12/12/1999",
])
def test_dob_labels_flag(line):
    findings = sr.detect_all(line, [])
    assert findings and findings[0]["type"] == "DOB"


@pytest.mark.parametrize("line", [
    "meeting on 01/31/1980",        # no birth label
    "invoice due 3 March 1990",
    "Date issued: 05/12/2010",
    "reborn 1980-01-31",
])
def test_dates_without_birth_label_not_flagged(line):
    assert sr.detect_all(line, []) == []


# ---------- account numbers ----------

@pytest.mark.parametrize("line", [
    "Account #1234567890",
    "acct no: 0043-2198-7654",
    "account number 98765432",
    "My acct 123456",
])
def test_account_variants(line):
    findings = sr.detect_all(line, [])
    assert findings and findings[0]["type"] == "ACCOUNT"


@pytest.mark.parametrize("line", [
    "account 12345",                       # too few digits
    "Account #1234567890123456789012345",  # too many digits
    "there were 6 accounts last week",     # no number after the label
])
def test_account_non_matches(line):
    assert sr.detect_all(line, []) == []


# ---------- blocklist names ----------

def test_blocklist_matching(tmp_path):
    bl = write(tmp_path, "names.txt", "Alice Chen\n# comment\n\nBob\n")
    _, patterns = sr.compile_blocklist(bl)
    text = "Contact Alice Chen (alice chen) but not Alice Chenoweth or Bobert."
    fs = sr.detect_all(text, patterns)
    assert types_of(fs) == [("NAME", "Alice Chen"), ("NAME", "alice chen")]


def test_blocklist_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        sr.compile_blocklist(tmp_path / "nope.txt")


# ---------- overlap resolution ----------

def test_email_wins_over_blocklist_name_inside_it():
    import re
    patterns = [re.compile(r"(?<!\w)smith(?!\w)", re.IGNORECASE)]
    fs = sr.detect_all("email smith.j@acme.com now", patterns)
    assert types_of(fs) == [("EMAIL", "smith.j@acme.com")]


def test_resolve_overlaps_keeps_longer_and_earlier():
    findings = [
        {"type": "NAME", "start": 4, "end": 7, "text": "Lee"},
        {"type": "NAME", "start": 0, "end": 7, "text": "Ann Lee"},
    ]
    kept = sr.resolve_overlaps(findings)
    assert [(f["start"], f["type"]) for f in kept] == [(0, "NAME")]


# ---------- redact + map ----------

def test_redact_auto_all_creates_out_and_map(tmp_path):
    src = write(tmp_path, "notes.txt",
                "Reach me at alice@example.com or 555-123-4567.\n")
    rc = sr.main(["redact", str(src), "--auto", "all"])
    assert rc == 0
    out = tmp_path / "notes.redacted.txt"
    mapp = tmp_path / "notes.redacted.txt.map.json"
    assert out.read_text().startswith("Reach me at [EMAIL] or [PHONE]")
    data = json.loads(mapp.read_text())
    assert data["format"] == sr.MAP_FORMAT
    assert data["placeholder_count"] == 2
    assert [e["type"] for e in data["entries"]] == ["EMAIL", "PHONE"]
    assert "alice@example.com" in json.dumps(data["entries"])
    assert "alice@example.com" not in out.read_text()


def test_redact_auto_none_changes_nothing(tmp_path):
    src = write(tmp_path, "notes.txt", "bob@example.com\n")
    assert sr.main(["redact", str(src), "--auto", "none"]) == 0
    assert (tmp_path / "notes.redacted.txt").read_text() == "bob@example.com\n"
    data = json.loads((tmp_path / "notes.redacted.txt.map.json").read_text())
    assert data["entries"] == []


def test_redact_with_blocklist_and_mixed_types(tmp_path):
    write(tmp_path, "names.txt", "Jo White\n")
    src = write(
        tmp_path,
        "chart.txt",
        "Pt Jo White DOB: 04/02/1988 acct 0044-1122-3344 jo@clinic.org 555-010-2233\n",
    )
    rc = sr.main([
        "redact", str(src), "--blocklist", str(tmp_path / "names.txt"),
        "--auto", "all",
    ])
    assert rc == 0
    out = (tmp_path / "chart.redacted.txt").read_text()
    for token in ("[NAME]", "[DOB]", "[ACCOUNT]", "[EMAIL]", "[PHONE]"):
        assert token in out
        assert token != "" and out.count(token) == 1
    for secret in ("Jo White", "04/02/1988", "0044-1122-3344",
                   "jo@clinic.org", "555-010-2233"):
        assert secret not in out


def test_redact_same_output_path_rejected(tmp_path):
    src = write(tmp_path, "notes.txt", "bob@example.com\n")
    assert sr.main(["redact", str(src), "--out", str(src)]) == 1


def test_redact_missing_file(tmp_path, capsys):
    assert sr.main(["redact", str(tmp_path / "ghost.txt")]) == 1
    assert "file not found" in capsys.readouterr().err


def test_redact_binary_file_rejected(tmp_path, capsys):
    p = tmp_path / "blob.txt"
    p.write_bytes(b"hello\x00world")
    assert sr.main(["redact", str(p)]) == 1
    assert "binary" in capsys.readouterr().err


def test_redact_warns_on_literal_placeholders(tmp_path, capsys):
    src = write(tmp_path, "notes.txt", "placeholder [EMAIL] already here\n")
    assert sr.main(["redact", str(src), "--auto", "none"]) == 0
    assert "placeholder-like token" in capsys.readouterr().err


# ---------- interactive review ----------

def test_review_y_n_choices(tmp_path, monkeypatch, capsys):
    src = write(tmp_path, "notes.txt", "a@x.com 555-123-4567 b@y.com\n")
    answers = iter(["n", "y", ""])  # skip email 1, take phone, blank means yes
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    assert sr.main(["redact", str(src)]) == 0
    out = (tmp_path / "notes.redacted.txt").read_text()
    assert out == "a@x.com [PHONE] [EMAIL]\n"


def test_review_all_and_skip_all_between_lists(tmp_path, monkeypatch):
    src = write(tmp_path, "notes.txt", "1@x.com 2@y.com 555-111-2222 555-333-4444\n")
    answers = iter(["S", "a"])  # skip remaining emails, accept all phones
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    assert sr.main(["redact", str(src)]) == 0
    out = (tmp_path / "notes.redacted.txt").read_text()
    assert out == "1@x.com 2@y.com [PHONE] [PHONE]\n"


def test_review_quit_aborts_writes_nothing(tmp_path, monkeypatch):
    src = write(tmp_path, "notes.txt", "a@x.com\n")
    monkeypatch.setattr("builtins.input", lambda prompt="": "q")
    assert sr.main(["redact", str(src)]) == 2
    out = tmp_path / "notes.redacted.txt"
    mapp = tmp_path / "notes.redacted.txt.map.json"
    assert not out.exists() and not mapp.exists()


def test_review_invalid_answer_reprompts(tmp_path, monkeypatch):
    src = write(tmp_path, "notes.txt", "a@x.com\n")
    answers = iter(["maybe", "zz", "y"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    assert sr.main(["redact", str(src)]) == 0
    assert (tmp_path / "notes.redacted.txt").read_text() == "[EMAIL]\n"


def test_review_eof_aborts_writes_nothing(tmp_path, monkeypatch):
    src = write(tmp_path, "notes.txt", "a@x.com\n")

    def boom(prompt=""):
        raise EOFError
    monkeypatch.setattr("builtins.input", boom)
    assert sr.main(["redact", str(src)]) == 2
    assert not (tmp_path / "notes.redacted.txt").exists()


# ---------- scan ----------

def test_scan_lists_findings_without_writing(tmp_path, capsys):
    src = write(tmp_path, "notes.txt", "a@x.com and 555-123-4567\n")
    assert sr.main(["scan", str(src)]) == 0
    outtxt = capsys.readouterr().out
    assert "2 candidate item(s)" in outtxt
    assert "EMAIL" in outtxt and "PHONE" in outtxt
    assert not (tmp_path / "notes.redacted.txt").exists()


# ---------- undo ----------

def test_undo_restores_exact_original(tmp_path):
    original = (
        "Name: Jo White\nDOB: 04/02/1988\nCard 1234 5678 9012 3454 stays.\n"
        "acct 0044-1122 acct 0055-2233\n"
    )
    src = write(tmp_path, "note2.txt", original)
    write(tmp_path, "names.txt", "Jo White\n")
    assert sr.main(["redact", str(src), "--blocklist", str(tmp_path / "names.txt"),
                    "--auto", "all"]) == 0
    restored = tmp_path / "note2.txt.restored"
    assert sr.main(["undo", str(tmp_path / "note2.redacted.txt"),
                    "-o", str(restored)]) == 0
    assert restored.read_text(newline="") == original


def test_undo_multiline_and_punctuated_edits(tmp_path):
    original = "line1 a@x.com line2\n\nline3 b@y.com, then!\n"
    src = write(tmp_path, "m.txt", original)
    assert sr.main(["redact", str(src), "--auto", "all"]) == 0
    restored = tmp_path / "m.txt.restored"
    assert sr.main(["undo", str(tmp_path / "m.redacted.txt"), "-o", str(restored)]) == 0
    assert restored.read_text(newline="") == original


def test_undo_count_mismatch_is_an_error(tmp_path, capsys):
    src = write(tmp_path, "note3.txt", "a@x.com\n")
    assert sr.main(["redact", str(src), "--auto", "all"]) == 0
    mapp = tmp_path / "note3.redacted.txt.map.json"
    redacted = tmp_path / "note3.redacted.txt"
    redacted.write_text("extra [EMAIL] here\n", encoding="utf-8")
    assert sr.main(["undo", str(redacted)]) == 1
    assert "mismatch" in capsys.readouterr().err
    assert mapp.exists()


def test_undo_without_map_fails(tmp_path, capsys):
    p = write(tmp_path, "plain.redacted.txt", "x")
    assert sr.main(["undo", str(p)]) == 1
    assert "undo map not found" in capsys.readouterr().err


def test_undo_corrupt_map_fails(tmp_path, capsys):
    p = write(tmp_path, "c.redacted.txt", "x")
    (tmp_path / "c.redacted.txt.map.json").write_text("{not json")
    assert sr.main(["undo", str(p)]) == 1
    assert "cannot parse" in capsys.readouterr().err


def test_undo_foreign_map_fails(tmp_path, capsys):
    p = write(tmp_path, "f.redacted.txt", "x")
    (tmp_path / "f.redacted.txt.map.json").write_text(json.dumps({"format": "other"}))
    assert sr.main(["undo", str(p)]) == 1
    assert "not a share-redactor undo map" in capsys.readouterr().err


def test_undo_refuses_existing_target_without_force(tmp_path, capsys):
    src = write(tmp_path, "note4.txt", "a@x.com\n")
    assert sr.main(["redact", str(src), "--auto", "all"]) == 0
    target = write(tmp_path, "occupied.txt", "keep me")
    assert sr.main(["undo", str(tmp_path / "note4.redacted.txt"),
                    "-o", str(target)]) == 1
    assert target.read_text() == "keep me"
    assert "--force" in capsys.readouterr().err


def test_undo_force_overwrites(tmp_path):
    src = write(tmp_path, "note5.txt", "a@x.com\n")
    assert sr.main(["redact", str(src), "--auto", "all"]) == 0
    target = write(tmp_path, "note5_target.txt", "old")
    assert sr.main(["undo", str(tmp_path / "note5.redacted.txt"),
                    "-o", str(target), "--force"]) == 0
    assert target.read_text(newline="") == "a@x.com\n"


# ---------- misc CLI ----------

def test_bare_file_defaults_to_redact(tmp_path):
    src = write(tmp_path, "notes.txt", "a@x.com\n")
    assert sr.main([str(src), "--auto", "all"]) == 0
    assert (tmp_path / "notes.redacted.txt").exists()


def test_no_args_prints_help_and_errors(capsys):
    assert sr.main([]) == 1
    assert "usage" in capsys.readouterr().out.lower()


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        sr.main(["--version"])
    assert exc.value.code == 0
    assert sr.VERSION in capsys.readouterr().out


def test_preserves_newline_styles(tmp_path):
    original = "a\r\nb c@x.com\r\n"
    src = write(tmp_path, "crlf.txt", original)
    assert sr.main(["redact", str(src), "--auto", "all"]) == 0
    out = (tmp_path / "crlf.redacted.txt").read_text(newline="")
    assert out == "a\r\nb [EMAIL]\r\n"
