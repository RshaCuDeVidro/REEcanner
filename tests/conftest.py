"""Shared pytest fixtures and path setup."""
import os
import sys

import pytest

# make the package importable when running pytest from anywhere
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def shuffler():
    """FeistelShuffler factory."""
    from reecanner.utils import FeistelShuffler
    return FeistelShuffler


@pytest.fixture
def empty_blacklist():
    """BlacklistManager with no ranges: everything is public."""
    from reecanner.utils import BlacklistManager
    return BlacklistManager(include_recommended=False, allow_private=True)


@pytest.fixture
def sample_results():
    """Synthetic scan results for output writers."""
    return [
        {"ip": "203.0.113.7", "port": 443, "proto": "tcp", "os": "Linux",
         "service": "https", "tls_domains": ["example.com"]},
        {"ip": "203.0.113.8", "port": 22, "proto": "tcp", "os": "Linux",
         "service": "ssh", "banner": "SSH-2.0-OpenSSH_8.9p1"},
    ]
