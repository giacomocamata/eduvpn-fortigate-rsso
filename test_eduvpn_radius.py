#!/usr/bin/env python3
"""Self-checks for eduvpn-radius pure logic. No framework, no pyrad, no network.

Run: python3 test_eduvpn_radius.py
"""
import importlib.util
import os
import tempfile

_spec = importlib.util.spec_from_file_location(
    "eduvpn_radius", os.path.join(os.path.dirname(__file__), "eduvpn-radius.py")
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


def test_parse_kv():
    kv = mod.parse_kv(
        'event=connect user=alice profile="staff people" conn=abc123 tunnel_ip4=10.20.0.5'
    )
    assert kv["event"] == "connect"
    assert kv["user"] == "alice"
    assert kv["profile"] == "staff people"   # quoted value with spaces
    assert kv["conn"] == "abc123"
    assert kv["tunnel_ip4"] == "10.20.0.5"
    assert mod.parse_kv("") == {}


def test_state_roundtrip():
    tmp_dir = tempfile.mkdtemp()
    mod.state_path = os.path.join(tmp_dir, "sub", "state.json")
    mod.sessions = {
        "peerA": {"user": "alice", "ip4": "10.20.0.5", "ip6": "-",
                  "profile": "staff", "acct_session_id": "deadbeef00000001"}
    }
    mod._save_state()
    assert os.path.isfile(mod.state_path)          # atomic save created the dir + file
    assert mod._load_state() == mod.sessions

    mod.state_path = os.path.join(tmp_dir, "does-not-exist.json")
    assert mod._load_state() == {}                  # missing file -> {}, no crash


def test_load_state_rejects_malformed_content():
    tmp_dir = tempfile.mkdtemp()

    # Valid JSON but wrong top-level type (e.g. hand-edited or truncated file)
    mod.state_path = os.path.join(tmp_dir, "list.json")
    with open(mod.state_path, "w", encoding="utf-8") as f:
        f.write("[1, 2, 3]")
    assert mod._load_state() == {}

    # Not valid JSON at all
    mod.state_path = os.path.join(tmp_dir, "garbage.json")
    with open(mod.state_path, "w", encoding="utf-8") as f:
        f.write("{not json")
    assert mod._load_state() == {}


def test_save_state_with_bare_relative_path():
    # A state_path with no directory component must not crash os.makedirs("")
    tmp_dir = tempfile.mkdtemp()
    cwd = os.getcwd()
    try:
        os.chdir(tmp_dir)
        mod.state_path = "bare-state.json"
        mod.sessions = {"peerA": {"user": "alice", "ip4": "10.20.0.5", "ip6": "-",
                                   "profile": "staff", "acct_session_id": "deadbeef00000001"}}
        mod._save_state()
        assert os.path.isfile("bare-state.json")
    finally:
        os.chdir(cwd)


def test_recover_and_replace_tolerate_incomplete_session():
    # A session dict missing keys (e.g. an older state-file format, or manual
    # edits) must not raise KeyError — recover_sessions() runs at startup,
    # before any of the log-follower's exception handling is in place.
    mod.radius_client = None
    mod.state_path = os.path.join(tempfile.mkdtemp(), "state.json")

    mod.sessions = {"peerA": {"acct_session_id": "deadbeef00000001"}}  # no user/ip4/profile
    mod.recover_sessions()  # must not raise

    mod.sessions = {"peerA": {"acct_session_id": "deadbeef00000001"}}
    mod.handle_connect({"conn": "peerA", "user": "alice", "tunnel_ip4": "10.20.0.9",
                         "tunnel_ip6": "-", "profile": "staff"})  # must not raise
    assert mod.sessions["peerA"]["ip4"] == "10.20.0.9"


def test_parse_config_missing_section_exits_cleanly():
    import configparser

    p = configparser.ConfigParser()
    p.read_string("[wrong-section]\nfoo = bar\n")
    try:
        mod._parse_config(p, "test.conf")
        assert False, "expected SystemExit for missing [radius] section"
    except SystemExit as e:
        assert e.code == 1


def test_handle_connect_rapid_reconnect():
    mod.radius_client = None      # _send() short-circuits -> False, harmlessly
    mod.state_path = os.path.join(tempfile.mkdtemp(), "state.json")
    mod.sessions = {}

    mod.handle_connect({"conn": "peerA", "user": "alice", "tunnel_ip4": "10.20.0.5",
                         "tunnel_ip6": "-", "profile": "staff"})
    assert "peerA" in mod.sessions
    first_id = mod.sessions["peerA"]["acct_session_id"]

    # Rapid reconnect: same conn (WireGuard pubkey) — old session must be replaced
    mod.handle_connect({"conn": "peerA", "user": "alice", "tunnel_ip4": "10.20.0.9",
                         "tunnel_ip6": "-", "profile": "staff"})
    assert mod.sessions["peerA"]["ip4"] == "10.20.0.9"
    assert mod.sessions["peerA"]["acct_session_id"] != first_id
    assert len(mod.sessions) == 1


def test_handle_disconnect():
    mod.radius_client = None
    mod.state_path = os.path.join(tempfile.mkdtemp(), "state.json")
    mod.sessions = {
        "peerA": {"user": "alice", "ip4": "10.20.0.5", "ip6": "-",
                  "profile": "staff", "acct_session_id": "deadbeef00000001"}
    }

    mod.handle_disconnect({"conn": "peerA", "user": "alice"})
    assert "peerA" not in mod.sessions

    # Disconnect for an untracked session (daemon was down when it connected) must not crash
    mod.handle_disconnect({"conn": "unknown-peer", "user": "bob"})
    assert mod.sessions == {}


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
