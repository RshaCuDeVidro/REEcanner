"""Checkpoint save/load round-trip tests (offline: network discovery is stubbed)."""
import json

import pytest

import reecanner.scanner as scanner_mod
from reecanner.scanner import Scanner
from reecanner.utils import BlacklistManager, InclusionManager


@pytest.fixture
def scanner(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner_mod, "get_net_info", lambda: (None, None, None))
    monkeypatch.setattr(Scanner, "_get_local_ip", lambda self: "127.0.0.1")
    inc = InclusionManager(["203.0.113.0/24"], seed=1234)
    bl = BlacklistManager(include_recommended=False, allow_private=True)
    return Scanner(ports=[80], rate_limit=100, inclusion_manager=inc,
                   blacklist_manager=bl, checkpoint_file=str(tmp_path / "scan.ckpt"))


def test_checkpoint_roundtrip(scanner):
    # simulate progress: 100 packets sent from worker 0
    scanner.sent_array[0] = 100
    scanner._save_checkpoint()

    with open(scanner.checkpoint_file, "r") as f:
        data = json.load(f)
    assert data["index"] == scanner.start_index + 100
    assert data["seed"] == 1234


def test_checkpoint_prefers_worker_indices(scanner):
    # exact per-worker indices (python fallback) win over the sent-count estimate
    scanner.sent_array[0] = 100
    scanner.cur_idx_array[0] = 250
    scanner._save_checkpoint()

    with open(scanner.checkpoint_file, "r") as f:
        data = json.load(f)
    assert data["index"] == 250


def test_checkpoint_load_in_main_format(scanner, tmp_path):
    """The on-disk format must match what __main__ reads back on resume."""
    scanner.sent_array[0] = 7
    scanner._save_checkpoint()

    path = tmp_path / "scan.ckpt"
    with open(path, "r") as f:
        ckpt_data = json.load(f)
    start_index = ckpt_data.get("index", 0)
    start_seed = ckpt_data.get("seed")
    assert start_index == 7
    assert start_seed == 1234
