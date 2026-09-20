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
    cfg = cfg_mod.Config(hibp_api_key="secret-key", profile="work")
    cfg.save_profile("work")

    resolved = cfg_mod.Config.resolve(profile="work")
    assert resolved.hibp_api_key == "secret-key"


def test_masked_hides_keys(tmp_path, monkeypatch):
    cfg_mod = _isolate(tmp_path, monkeypatch)
    cfg = cfg_mod.Config(hibp_api_key="abcdefgh")
    masked = cfg.masked()
    assert masked["hibp_api_key"] != "abcdefgh"
    assert "abcdefgh" not in str(masked)


def test_defaults_are_sane(tmp_path, monkeypatch):
    cfg_mod = _isolate(tmp_path, monkeypatch)
    cfg = cfg_mod.Config()
    assert cfg.timeout > 0
    assert cfg.webhooks == []
    assert cfg.cache_enabled is False


def test_env_var_beats_the_config_file(tmp_path, monkeypatch):
    cfg_mod = _isolate(tmp_path, monkeypatch)
    cfg_mod.Config(hibp_api_key="from-file").save_profile("default")
    monkeypatch.setenv("HIBP_API_KEY", "from-env")

    assert cfg_mod.Config.resolve().hibp_api_key == "from-env"


def test_config_file_timeout_is_used_when_no_flag_is_given(tmp_path, monkeypatch):
    cfg_mod = _isolate(tmp_path, monkeypatch)
    cfg = cfg_mod.Config(timeout=42.0)
    cfg.save_profile("default")

    assert cfg_mod.Config.resolve().timeout == 42.0
    assert cfg_mod.Config.resolve(timeout=3.0).timeout == 3.0


def test_a_junk_config_value_falls_back_instead_of_crashing(tmp_path, monkeypatch):
    cfg_mod = _isolate(tmp_path, monkeypatch)
    cfg_mod.config_file().write_text(
        '{"profiles": {"default": {"timeout": null, "cache_ttl": "soon"}}}',
        encoding="utf-8",
    )

    resolved = cfg_mod.Config.resolve()
    assert resolved.timeout == 15.0
    assert resolved.cache_ttl == 3600
