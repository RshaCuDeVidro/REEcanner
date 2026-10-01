"""FeistelShuffler permutation and convergence tests."""
import pytest

from reecanner.utils import FeistelShuffler

FULL_PERMUTATION_SIZES = [1, 2, 255, 256, 65535]
SAMPLED_SIZES = [2 ** 24]


@pytest.mark.parametrize("max_val", FULL_PERMUTATION_SIZES)
def test_full_permutation(max_val):
    """get() must be a bijection over [0, max_val) for small domains."""
    fs = FeistelShuffler(key=0xDEADBEEF, max_val=max_val)
    outputs = [fs.get(i) for i in range(max_val)]
    assert sorted(outputs) == list(range(max_val))


@pytest.mark.parametrize("max_val", FULL_PERMUTATION_SIZES)
@pytest.mark.parametrize("key", [0, 1, 0x12345678, 0xFFFFFFFF])
def test_permutation_various_keys(max_val, key):
    """The permutation property must hold for any key, including 0."""
    fs = FeistelShuffler(key=key, max_val=max_val)
    outputs = {fs.get(i) for i in range(max_val)}
    assert outputs == set(range(max_val))


@pytest.mark.parametrize("max_val", SAMPLED_SIZES)
def test_large_domain_sampled(max_val):
    """For huge domains, sample: outputs stay in range and are unique."""
    fs = FeistelShuffler(key=0xABCD1234, max_val=max_val)
    n = 20000
    outputs = set()
    for i in range(n):
        x = fs.get(i)
        assert 0 <= x < max_val
        outputs.add(x)
    assert len(outputs) == n  # injective on the sample


@pytest.mark.parametrize("max_val", FULL_PERMUTATION_SIZES)
def test_convergence(max_val):
    """cycle walking must terminate and land inside the domain."""
    fs = FeistelShuffler(key=42, max_val=max_val)
    for i in range(max_val):
        x = fs._encrypt(i)
        steps = 0
        while x >= max_val:
            x = fs._encrypt(x)
            steps += 1
            assert steps < 100, "cycle walking did not converge"
        assert x == fs.get(i)


def test_deterministic():
    """Same key and index must always give the same output."""
    a = FeistelShuffler(key=7, max_val=1000)
    b = FeistelShuffler(key=7, max_val=1000)
    assert [a.get(i) for i in range(100)] == [b.get(i) for i in range(100)]


def test_different_keys_differ():
    """Different keys should (overwhelmingly likely) permute differently."""
    a = FeistelShuffler(key=1, max_val=1000)
    b = FeistelShuffler(key=2, max_val=1000)
    assert [a.get(i) for i in range(100)] != [b.get(i) for i in range(100)]
