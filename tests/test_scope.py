"""Scope-enforcement tests (core safety requirement)."""

import textwrap

import pytest
import yaml

from agent.scope import ScopeError, load_scope


def write_scope(tmp_path, targets, ack=False):
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.safe_dump({
        "version": 1,
        "authorization_acknowledged": ack,
        "targets": targets,
    }))
    return str(p)


def test_missing_scope_file_refused(tmp_path):
    with pytest.raises(ScopeError, match="not found"):
        load_scope(str(tmp_path / "nope.yaml"))


def test_empty_targets_refused(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.safe_dump({"version": 1, "targets": []}))
    with pytest.raises(ScopeError, match="no targets"):
        load_scope(str(p))


def test_target_without_authorized_flag_refused(tmp_path):
    scope = write_scope(tmp_path, [{"target": "127.0.0.1"}])  # no authorized: true
    with pytest.raises(ScopeError, match="not explicitly authorized"):
        load_scope(scope)


def test_default_localhost_scope_allowed(tmp_path):
    scope = write_scope(tmp_path, [{"target": "127.0.0.1", "authorized": True}])
    decision = load_scope(scope)
    assert decision.allowed
    assert decision.targets == ["127.0.0.1"]


def test_wildcard_refused_without_ack(tmp_path):
    scope = write_scope(tmp_path, [{"target": "0.0.0.0/0", "authorized": True}])
    with pytest.raises(ScopeError, match="Refusing to run"):
        load_scope(scope)


def test_public_ip_refused_without_ack(tmp_path):
    scope = write_scope(tmp_path, [{"target": "8.8.8.8", "authorized": True}])
    with pytest.raises(ScopeError, match="public"):
        load_scope(scope)


def test_public_ip_allowed_with_ack_and_authorized(tmp_path):
    scope = write_scope(
        tmp_path, [{"target": "8.8.8.8", "authorized": True}], ack=True)
    decision = load_scope(scope)
    assert decision.allowed
    assert decision.targets == ["8.8.8.8"]
    assert decision.authorization_acknowledged is True


def test_private_lan_cidr_allowed_without_ack(tmp_path):
    scope = write_scope(
        tmp_path, [{"target": "192.168.1.0/30", "authorized": True}])
    decision = load_scope(scope)
    assert decision.allowed
    assert decision.targets == ["192.168.1.1", "192.168.1.2"]


def test_huge_network_refused_by_absolute_cap(tmp_path):
    scope = write_scope(
        tmp_path, [{"target": "0.0.0.0/0", "authorized": True}], ack=True)
    with pytest.raises(ScopeError, match="absolute cap"):
        load_scope(scope)


def test_malformed_yaml_refused(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(textwrap.dedent("targets: [unclosed"))
    with pytest.raises(ScopeError, match="not valid YAML"):
        load_scope(str(p))
