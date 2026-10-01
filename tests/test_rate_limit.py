"""Rate fan-out, adaptive hysteresis, and ResultSink tests (offline)."""
import json
import queue

import pytest

import reecanner.scanner as scanner_mod
from reecanner.scanner import Response, ResultSink, Scanner
from reecanner.utils import BlacklistManager, InclusionManager


@pytest.fixture
def make_scanner(monkeypatch):
    monkeypatch.setattr(scanner_mod, "get_net_info", lambda: (None, None, None))
    monkeypatch.setattr(Scanner, "_get_local_ip", lambda self: "127.0.0.1")

    def _make(**kwargs):
        inc = InclusionManager(["203.0.113.0/24"], seed=1234)
        bl = BlacklistManager(include_recommended=False, allow_private=True)
        kwargs.setdefault("ports", [80])
        return Scanner(inclusion_manager=inc, blacklist_manager=bl, **kwargs)
    return _make


def test_per_worker_rate_floor(make_scanner):
    # 10 pps across 32 workers must never collapse to 0 (= unlimited)
    s = make_scanner(rate_limit=10, workers=32)
    assert s._per_worker_rate() == 1


def test_per_worker_rate_unlimited(make_scanner):
    s = make_scanner(rate_limit=0, workers=4)
    assert s._per_worker_rate() == 0


def test_set_rate_limit_fans_out(make_scanner):
    s = make_scanner(rate_limit=1000, workers=4)
    s._set_rate_limit(100)
    assert list(s.rate_limit_array) == [25, 25, 25, 25]


def test_adaptive_reduces_on_send_failures(make_scanner):
    s = make_scanner(rate_limit=1000, workers=2, adaptive=True)
    s._adapt_last = 0.0
    s.fail_array[0] = 5
    s._adaptive_tick(now=100.0, start_time=0.0, curr_pps=900.0,
                     last_warning_time=0.0)
    assert s.rate_limit == 800
    assert list(s.rate_limit_array) == [400, 400]


def test_adaptive_respects_min_rate(make_scanner):
    s = make_scanner(rate_limit=Scanner.ADAPT_MIN_RATE, workers=1, adaptive=True)
    s._adapt_last = 0.0
    s.fail_array[0] = 3
    s._adaptive_tick(now=100.0, start_time=0.0, curr_pps=90.0,
                     last_warning_time=0.0)
    assert s.rate_limit == Scanner.ADAPT_MIN_RATE


def test_adaptive_ramps_up_after_clear_streak(make_scanner):
    s = make_scanner(rate_limit=1000, workers=1, adaptive=True)
    # force a reduction first
    s._adapt_last = 0.0
    s.fail_array[0] = 1
    s._adaptive_tick(now=100.0, start_time=0.0, curr_pps=0.0,
                     last_warning_time=0.0)
    reduced = s.rate_limit
    assert reduced < 1000
    # clear windows must climb back, but never past the initial limit
    now = 100.0
    for _ in range(Scanner.ADAPT_CLEAR_WINDOWS + 1):
        now += Scanner.ADAPT_INTERVAL
        s._adaptive_tick(now=now, start_time=0.0, curr_pps=0.0,
                         last_warning_time=0.0)
    assert reduced < s.rate_limit <= 1000


def test_adaptive_grace_period_blocks_decisions(make_scanner):
    s = make_scanner(rate_limit=1000, workers=1, adaptive=True,
                     adaptive_grace=60)
    s.fail_array[0] = 100
    s._adaptive_tick(now=30.0, start_time=0.0, curr_pps=0.0,
                     last_warning_time=0.0)
    assert s.rate_limit == 1000


def test_sink_emit_queues_and_streams(tmp_path):
    q = queue.Queue()
    stream_path = tmp_path / "live.jsonl"
    sink = ResultSink(quiet=True, results_queue=q,
                      stream_path=str(stream_path))
    sink.emit(Response(ip="203.0.113.9", ip_int=0xCB007109, port=80,
                       proto="tcp", ttl=64, window=5840))
    sink.close()
    record = q.get_nowait()
    assert record["ip"] == "203.0.113.9"
    assert record["port"] == 80
    assert record["proto"] == "tcp"
    with open(stream_path) as f:
        streamed = json.loads(f.readline())
    assert streamed == record


def test_sink_simple_output(capsys):
    sink = ResultSink(quiet=False, simple=True)
    sink.emit(Response(ip="203.0.113.10", ip_int=0, port=22, proto="tcp"))
    sink.close()
    assert "203.0.113.10:22" in capsys.readouterr().out


def test_sink_icmp_omits_port(capsys):
    sink = ResultSink(quiet=False, simple=True)
    sink.emit(Response(ip="203.0.113.11", ip_int=0, port=0, proto="icmp"))
    sink.close()
    out = capsys.readouterr().out
    assert "203.0.113.11" in out and ":0" not in out
