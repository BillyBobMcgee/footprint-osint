"""Runtime configuration: CLI flags, environment variables, and a config file.

Config is resolved with this precedence (later wins):
    config-file profile  <  environment variables  <  explicit CLI flags
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

USER_AGENT = "footprint-osint/0.3 (+https://github.com/BillyBobMcgee/footprint)"
DEFAULT_TOR_PROXY = "socks5h://127.0.0.1:9050"

# Environment variable names for API keys.
ENV_HIBP_KEY = "HIBP_API_KEY"
ENV_DEHASHED_EMAIL = "DEHASHED_EMAIL"
ENV_DEHASHED_KEY = "DEHASHED_API_KEY"
ENV_INTELX_KEY = "INTELX_API_KEY"
ENV_HUNTER_KEY = "HUNTER_API_KEY"
ENV_EMAILREP_KEY = "EMAILREP_API_KEY"
# Comma- or whitespace-separated list of webhook URLs.
ENV_WEBHOOKS = "FOOTPRINT_WEBHOOKS"


def config_dir() -> Path:
    """Per-OS directory for footprint's config, cache, and watch state."""
    if os.name == "nt":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
            os.path.expanduser("~"), ".config"
        )
    d = Path(base) / "footprint"
    d.mkdir(parents=True, exist_ok=True)
    return d


def config_file() -> Path:
    return config_dir() / "config.json"


@dataclass
class Webhook:
    """One delivery target, and whether it is currently switched on."""

    url: str
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {"url": self.url, "enabled": self.enabled}


@dataclass
class Config:
    """Everything the sources need to run a lookup."""

    # Credentials
    hibp_api_key: str | None = None
    dehashed_email: str | None = None
    dehashed_api_key: str | None = None
    intelx_api_key: str | None = None
    hunter_api_key: str | None = None
    emailrep_api_key: str | None = None

    # Networking
    timeout: float = 15.0
    max_retries: int = 3
    user_agent: str = USER_AGENT
    tor: bool = False
    tor_proxy: str = DEFAULT_TOR_PROXY

    # Caching
    cache_enabled: bool = False
    cache_ttl: int = 3600

    # Delivery targets (Discord, or any JSON endpoint). Treated as secrets:
    # anyone holding one can post to that channel.
    webhooks: list[Webhook] = field(default_factory=list)

    profile: str = "default"

    def __post_init__(self) -> None:
        # Accept bare URL strings so Config(webhooks=["https://..."]) works.
        # Tested against str rather than Webhook: a module reload creates a new
        # Webhook class, and an isinstance check would then re-wrap live objects.
        self.webhooks = [
            Webhook(url=w) if isinstance(w, str) else w for w in self.webhooks
        ]

    @property
    def active_webhooks(self) -> list[Webhook]:
        """Only the switched-on targets. Delivery always goes through this."""
        return [w for w in self.webhooks if w.enabled]

    @property
    def proxies(self) -> dict[str, str] | None:
        if self.tor:
            return {"http": self.tor_proxy, "https": self.tor_proxy}
        return None

    # ------------------------------------------------------------------ load
    @classmethod
    def resolve(
        cls,
        *,
        profile: str | None = None,
        api_key: str | None = None,
        timeout: float | None = None,
        tor: bool | None = None,
        cache: bool | None = None,
    ) -> Config:
        """Build a Config from file + env + explicit overrides."""
        file_data = _load_file_profile(profile)

        def pick(file_key: str, env_name: str) -> str | None:
            return file_data.get(file_key) or os.environ.get(env_name) or None

        cfg = cls(
            hibp_api_key=api_key or pick("hibp_api_key", ENV_HIBP_KEY),
            dehashed_email=pick("dehashed_email", ENV_DEHASHED_EMAIL),
            dehashed_api_key=pick("dehashed_api_key", ENV_DEHASHED_KEY),
            intelx_api_key=pick("intelx_api_key", ENV_INTELX_KEY),
            hunter_api_key=pick("hunter_api_key", ENV_HUNTER_KEY),
            emailrep_api_key=pick("emailrep_api_key", ENV_EMAILREP_KEY),
            timeout=timeout if timeout is not None else float(file_data.get("timeout", 15.0)),
            tor=tor if tor is not None else bool(file_data.get("tor", False)),
            tor_proxy=file_data.get("tor_proxy", DEFAULT_TOR_PROXY),
            cache_enabled=cache if cache is not None else bool(file_data.get("cache", False)),
            cache_ttl=int(file_data.get("cache_ttl", 3600)),
            webhooks=_parse_webhooks(
                file_data.get("webhooks") or os.environ.get(ENV_WEBHOOKS)
            ),
            profile=profile or _default_profile_name(),
        )
        return cfg

    # ------------------------------------------------------------------ save
    def save_profile(self, profile: str | None = None) -> Path:
        """Persist credential/network settings to the config file profile."""
        name = profile or self.profile or "default"
        path = config_file()
        doc = _read_config_doc()
        doc.setdefault("profiles", {})
        doc.setdefault("default_profile", name)
        doc["profiles"][name] = {
            "hibp_api_key": self.hibp_api_key,
            "dehashed_email": self.dehashed_email,
            "dehashed_api_key": self.dehashed_api_key,
            "intelx_api_key": self.intelx_api_key,
            "hunter_api_key": self.hunter_api_key,
            "emailrep_api_key": self.emailrep_api_key,
            "timeout": self.timeout,
            "tor": self.tor,
            "tor_proxy": self.tor_proxy,
            "cache": self.cache_enabled,
            "cache_ttl": self.cache_ttl,
            "webhooks": [w.to_dict() for w in self.webhooks],
        }
        path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        return path

    def masked(self) -> dict[str, Any]:
        """A dict of settings safe to display (keys masked)."""
        out = asdict(self)
        for k, v in out.items():
            if k.endswith("_api_key") and v:
                out[k] = v[:4] + "…" + v[-2:] if len(v) > 6 else "set"
        # A webhook URL grants posting rights, so never display it in full.
        from footprint.notify import redact

        out["webhooks"] = [
            {"url": redact(w.url), "enabled": w.enabled} for w in self.webhooks
        ]
        return out


def _parse_webhooks(value: Any) -> list[Webhook]:
    """Build the webhook list from config or the environment.

    Accepts three shapes so older config files keep working: a delimited string
    (env var), a list of bare URLs, or a list of {"url", "enabled"} objects.
    """
    if not value:
        return []
    if isinstance(value, str):
        items: list[Any] = value.replace(",", " ").split()
    else:
        items = list(value)

    out: list[Webhook] = []
    for item in items:
        if isinstance(item, dict):
            url = str(item.get("url", "")).strip()
            enabled = bool(item.get("enabled", True))
        else:
            url, enabled = str(item).strip(), True
        if url.startswith(("http://", "https://")):
            out.append(Webhook(url=url, enabled=enabled))
    return out


def _read_config_doc() -> dict[str, Any]:
    path = config_file()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _default_profile_name() -> str:
    return _read_config_doc().get("default_profile", "default")


def _load_file_profile(profile: str | None) -> dict[str, Any]:
    doc = _read_config_doc()
    profiles = doc.get("profiles", {})
    name = profile or doc.get("default_profile", "default")
    return profiles.get(name, {}) or {}
