"""CLI argument validation: bad values must exit(1) with a clear error."""
import sys

import pytest

import reecanner.__main__ as cli


def _run_main(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["reecanner"] + argv)
    with pytest.raises(SystemExit) as exc:
        cli.main()
    return exc.value.code


def test_negative_rate_rejected(monkeypatch):
    assert _run_main(monkeypatch, ["203.0.113.0/24", "--rate-limit=-5"]) == 1


def test_zero_workers_rejected(monkeypatch):
    assert _run_main(monkeypatch, ["203.0.113.0/24", "--workers", "0"]) == 1


def test_zero_shards_rejected(monkeypatch):
    assert _run_main(monkeypatch, ["203.0.113.0/24", "--shards", "0"]) == 1


def test_shard_id_out_of_range_rejected(monkeypatch):
    assert _run_main(monkeypatch,
                     ["203.0.113.0/24", "--shards", "2", "--shard-id", "2"]) == 1


def test_zero_retries_rejected(monkeypatch):
    assert _run_main(monkeypatch, ["203.0.113.0/24", "--retries", "0"]) == 1


def test_zero_batch_size_rejected(monkeypatch):
    assert _run_main(monkeypatch, ["203.0.113.0/24", "--batch-size", "0"]) == 1


def test_high_rate_without_override_rejected(monkeypatch):
    assert _run_main(monkeypatch, ["203.0.113.0/24", "-r", "50000"]) == 1


def test_bad_port_list_rejected(monkeypatch):
    assert _run_main(monkeypatch, ["203.0.113.0/24", "-p", "not-a-port"]) == 1
