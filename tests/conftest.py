import pytest

from footprint import config as config_mod
from footprint.sources import base

_ENV_KEYS = [v for k, v in vars(config_mod).items()
             if k.startswith("ENV_") and isinstance(v, str)]


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Per-host spacing is real behaviour, but it must not slow the suite.

    ``base._next_slot`` is process-global, so one test's HIBP call would
    otherwise make the next one sleep. The limiter has its own test.
    """
    base._next_slot.clear()


@pytest.fixture(autouse=True)
def isolated_config_dir(tmp_path, monkeypatch):
    """Never read or write the developer's real config, watchlist, or cache.

    ``config_dir()`` reads these at call time, so redirecting them covers every
    module that derives a path from it. Key variables are cleared too: the
    environment now beats the config file, so an exported key would otherwise
    change what the suite tests.
    """
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    for name in _ENV_KEYS:
        monkeypatch.delenv(name, raising=False)
