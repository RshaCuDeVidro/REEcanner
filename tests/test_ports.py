"""parse_ports_list tests."""
import pytest

from reecanner.utils import parse_ports_list


def test_simple_list():
    assert parse_ports_list("80,443") == [80, 443]


def test_range():
    assert parse_ports_list("1-5") == [1, 2, 3, 4, 5]


def test_mixed():
    assert parse_ports_list("22,80-82,443") == [22, 80, 81, 82, 443]


def test_duplicates_removed():
    assert parse_ports_list("80,80,80-82,81") == [80, 81, 82]


def test_boundaries():
    assert parse_ports_list("1,65535") == [1, 65535]
    assert parse_ports_list("1-1") == [1]
    assert parse_ports_list("65535-65535") == [65535]


def test_whitespace_and_empty_parts():
    assert parse_ports_list(" 80 , , 443 ,") == [80, 443]


def test_inverted_range_raises():
    with pytest.raises(ValueError, match="greater"):
        parse_ports_list("5-1")


def test_out_of_bounds_raises():
    with pytest.raises(ValueError):
        parse_ports_list("0")
    with pytest.raises(ValueError):
        parse_ports_list("65536")
    with pytest.raises(ValueError):
        parse_ports_list("0-100")
    with pytest.raises(ValueError):
        parse_ports_list("1-65536")


def test_garbage_raises():
    with pytest.raises(ValueError):
        parse_ports_list("abc")
    with pytest.raises(ValueError):
        parse_ports_list("80-xyz")
    with pytest.raises(ValueError):
        parse_ports_list("80.5")


def test_empty_string():
    assert parse_ports_list("") == []
