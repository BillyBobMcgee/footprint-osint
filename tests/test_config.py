import importlib

import footprint.config as config_mod


def _isolate(tmp_path, monkeypatch):
    """Point the config dir at a temp location for both POSIX and Windows."""
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    importlib.reload(config_mod)
    return config_mod


def test_save_and_resolve_profile(tmp_path, monkeypatch):
    cfg_mod = _isolate(tmp_path, monkeypatch)
    cfg = cfg_mod.Config(hibp_api_key="secret-key", tor=True, profile="work")
    cfg.save_profile("work")

    resolved = cfg_mod.Config.resolve(profile="work")
    assert resolved.hibp_api_key == "secret-key"
    assert resolved.tor is True


def test_masked_hides_keys(tmp_path, monkeypatch):
    cfg_mod = _isolate(tmp_path, monkeypatch)
    cfg = cfg_mod.Config(hibp_api_key="abcdefgh")
    masked = cfg.masked()
    assert masked["hibp_api_key"] != "abcdefgh"
    assert "abcdefgh" not in str(masked)


def test_proxies_only_when_tor(tmp_path, monkeypatch):
    cfg_mod = _isolate(tmp_path, monkeypatch)
    assert cfg_mod.Config(tor=False).proxies is None
    assert cfg_mod.Config(tor=True).proxies["https"].startswith("socks5")
