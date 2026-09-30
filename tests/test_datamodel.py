"""Data-model round-trip + audit-log immutability tests."""

import sqlite3

import pytest

from common.logging_setup import utc_now_iso
from storage.db import Store
from storage.models import AuditEntry, Evidence, Finding


@pytest.fixture()
def store(tmp_path):
    s = Store(str(tmp_path / "test.db"))
    yield s
    s.close()


def test_finding_evidence_round_trip(store):
    now = utc_now_iso()
    finding = Finding.new(
        target="127.0.0.1",
        title="Open port 22/tcp (SSH)",
        severity="info",
        first_seen=now,
        remediation="Use key-based auth.",
    )
    stored = store.upsert_finding(finding)
    ev = Evidence(
        id=None, finding_id=stored.id, timestamp=now, collector="discovery.tcp",
        excerpt="SSH-2.0-OpenSSH", excerpt_hash="abc123",
        detail={"host": "127.0.0.1", "port": 22},
    )
    store.add_evidence(ev)

    fetched = store.get_finding(stored.id)
    assert fetched is not None
    assert fetched.target == "127.0.0.1"
    assert fetched.title == "Open port 22/tcp (SSH)"
    assert fetched.status == "suspected"  # discovery alone only suspects
    assert fetched.remediation == "Use key-based auth."
    assert len(fetched.evidence) == 1
    assert fetched.evidence[0].excerpt == "SSH-2.0-OpenSSH"
    assert fetched.evidence[0].detail["port"] == 22


def test_upsert_dedupes_and_appends_retest_history(store):
    now = utc_now_iso()
    first = store.upsert_finding(Finding.new(
        target="127.0.0.1", title="Open port 80/tcp (HTTP)", first_seen=now))
    second = store.upsert_finding(Finding.new(
        target="127.0.0.1", title="Open port 80/tcp (HTTP)", first_seen=now))

    assert first.id == second.id  # stable identity across re-runs
    fetched = store.get_finding(first.id)
    assert len(fetched.retest_history) == 1
    assert fetched.retest_history[0]["event"] == "re-observed"
    assert len(store.list_findings()) == 1  # no duplicate rows


def test_audit_log_is_immutable(store):
    store.audit(AuditEntry(
        id=None, timestamp=utc_now_iso(), event="discovery.attempt",
        scope_file="/tmp/scope.yaml", scope_hash="deadbeef",
        authorization_acknowledged=False, target_count=1,
        decision="allow", reason="test",
    ))
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        store._conn.execute("UPDATE audit_log SET reason='x' WHERE id=1")
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        store._conn.execute("DELETE FROM audit_log WHERE id=1")
    assert len(store.list_audit()) == 1  # row survived


def test_list_findings_filters(store):
    now = utc_now_iso()
    store.upsert_finding(Finding.new(
        target="127.0.0.1", title="Open port 23/tcp (Telnet)",
        severity="medium", first_seen=now))
    store.upsert_finding(Finding.new(
        target="127.0.0.1", title="Open port 80/tcp (HTTP)",
        severity="info", first_seen=now))
    assert len(store.list_findings(severity="medium")) == 1
    assert len(store.list_findings(target="127.0.0.1")) == 2
