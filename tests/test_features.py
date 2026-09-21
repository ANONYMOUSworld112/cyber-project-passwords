"""Feature tests: vault, incidents, fim, hashdb, logs."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from csp.auth import (
    clear_lockout,
    set_session,
    unlock,
    write_initial_blobs,
)
from csp.crypto.memzero import SecretBuffer


@pytest.fixture
def session(tmp_data_dir: Path):
    write_initial_blobs(
        username="alice",
        password="GoodPass1234!",
        hint_question="What is my recovery phrase?",
        hint_answer="fluffy unicorn",
    )
    clear_lockout("alice")
    s, _payload = unlock("alice", "GoodPass1234!")
    set_session(s)
    yield s
    s.wipe()
    set_session(None)


def test_credential_crud(session):
    from csp.features.vault import (
        add_credential,
        delete_credential,
        get_credential,
        list_credentials,
        search_credentials,
        update_credential,
    )
    c = add_credential("github", "alice", "secret1", url="https://github.com", notes="work")
    assert c["title"] == "github"
    assert c["password"] == "secret1"
    assert len(list_credentials()) == 1
    update_credential(c["id"], password="newpass")
    assert get_credential(c["id"])["password"] == "newpass"
    assert len(search_credentials("github")) == 1
    assert len(search_credentials("nope")) == 0
    delete_credential(c["id"])
    assert list_credentials() == []


def test_generate_password(session):
    from csp.features.vault import generate_password
    p = generate_password(20)
    assert len(p) == 20
    # at least 3 classes
    classes = sum([
        any(c.islower() for c in p),
        any(c.isupper() for c in p),
        any(c.isdigit() for c in p),
        any(not c.isalnum() for c in p),
    ])
    assert classes >= 3


def test_incident_crud(session):
    from csp.features.incidents import (
        add_incident,
        close_incident,
        get_incident,
        list_incidents,
        update_incident,
    )
    inc = add_incident("phishing attempt", "high", notes="received malicious email", iocs=["evil@x.com"])
    assert inc["status"] == "open"
    assert inc["severity"] == "high"
    assert len(list_incidents()) == 1
    update_incident(inc["id"], notes="updated")
    assert "updated" in get_incident(inc["id"])["notes"]
    close_incident(inc["id"])
    assert get_incident(inc["id"])["status"] == "closed"
    assert list_incidents(include_closed=False) == []


def test_fim_baseline_and_scan(tmp_data_dir: Path, session):
    from csp.features.fim import fim_baseline, fim_scan, fim_watch_list
    root = tmp_data_dir / "tree"
    root.mkdir()
    (root / "a.txt").write_text("alpha")
    (root / "b.txt").write_text("beta")
    res = fim_baseline(str(root))
    assert res["files"] == 2
    assert str(root.resolve()) in fim_watch_list()

    # No changes.
    report = fim_scan()
    assert report["total_changes"] == 0

    # Modify one file.
    (root / "a.txt").write_text("alpha-modified")
    report = fim_scan()
    assert report["total_changes"] == 1
    assert report["scans"][0]["changed"] == ["a.txt"]

    # Add a new file.
    (root / "c.txt").write_text("gamma")
    report = fim_scan()
    assert report["total_changes"] == 2
    assert report["scans"][0]["added"] == ["c.txt"]

    # Remove a file.
    (root / "b.txt").unlink()
    report = fim_scan()
    assert report["total_changes"] == 3
    assert report["scans"][0]["removed"] == ["b.txt"]


def test_hashdb_import_and_lookup(session, tmp_data_dir: Path):
    from csp.features.hashdb import hashdb_import, hashdb_lookup, hash_file
    f = tmp_data_dir / "hashes.txt"
    f.write_text(
        "# comment line\n"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,evil1\n"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,evil2\n"
        "not-a-hash\n"
    )
    res = hashdb_import(str(f), "malicious")
    assert res["added"] == 2
    assert res["skipped"] == 1

    assert hashdb_lookup("a" * 64)["status"] == "malicious"
    assert hashdb_lookup("b" * 64)["status"] == "malicious"
    assert hashdb_lookup("c" * 64)["status"] == "unknown"


def test_hashdb_lookup_by_file(session, tmp_data_dir: Path):
    from csp.features.hashdb import hashdb_import, hashdb_lookup, hash_file
    f = tmp_data_dir / "h.txt"
    f.write_text("hello world")
    expected = hash_file(str(f))
    # Import the hash, then look it up.
    tmp = tmp_data_dir / "list.txt"
    tmp.write_text(expected + ",known-bad")
    hashdb_import(str(tmp), "malicious")
    out = hashdb_lookup(expected)
    assert out["status"] == "malicious"


def test_logs_analyze(session, tmp_data_dir: Path):
    from csp.features.logs import logs_analyze, list_log_runs
    f = tmp_data_dir / "auth.log"
    f.write_text(
        "Jun  6 10:00:00 host sshd[1]: Failed password for invalid user root from 1.2.3.4\n"
        "Jun  6 10:00:01 host sshd[1]: Failed password for invalid user admin from 1.2.3.4\n"
        "Jun  6 10:00:02 host sshd[1]: Accepted password for alice from 5.6.7.8\n"
        "Jun  6 10:00:03 host sshd[1]: session opened for user alice\n"
    )
    summary = logs_analyze(str(f))
    assert summary["lines"] == 4
    assert summary["format"] in ("syslog", "plain")
    assert "AUTH_FAIL" in summary["levels"] or "ERROR" in summary["levels"]
    runs = list_log_runs()
    assert len(runs) == 1
    assert runs[0]["id"] == summary["id"]
