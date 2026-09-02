from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from campus_connect.models import AppConfig

APP_DIR_NAME = ".campus-auto-connect"
CONFIG_NAME = "config.yaml"
EXAMPLE_NAME = "config.example.yaml"


def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def user_data_dir() -> Path:
    return Path.home() / APP_DIR_NAME


def default_config_path() -> Path:
    cwd_cfg = Path.cwd() / CONFIG_NAME
    if cwd_cfg.is_file():
        return cwd_cfg
    root_cfg = project_root() / CONFIG_NAME
    if root_cfg.is_file():
        return root_cfg
    if example_config_path().is_file():
        return root_cfg
    return user_data_dir() / CONFIG_NAME


def example_config_path() -> Path:
    return project_root() / EXAMPLE_NAME


def log_path() -> Path:
    directory = user_data_dir()
    directory.mkdir(parents=True, exist_ok=True)
    return directory / "campus-connect.log"


def _as_str_list(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    return [str(x) for x in value]


def load_config(path: Path | None = None) -> AppConfig:
    cfg_path = path or default_config_path()
    data: dict[str, Any] = {}
    if cfg_path.is_file():
        loaded = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, dict):
            raise ValueError(f"配置文件格式错误: {cfg_path}")
        data = loaded

    srun = data.get("srun") or {}
    ruijie = data.get("ruijie") or {}
    custom = data.get("custom") or {}
    vpn = data.get("vpn") or {}
    watch = data.get("watch") or {}
    logging_cfg = data.get("logging") or {}

    return AppConfig(
        backend=str(data.get("backend") or "auto"),
        username=str(data.get("username") or ""),
        password=str(data.get("password") or ""),
        portal_url=str(data.get("portal_url") or ""),
        click_only=bool(data.get("click_only", False)),
        bind_campus_nic=bool(data.get("bind_campus_nic", True)),
        campus_ip_prefixes=_as_str_list(data.get("campus_ip_prefixes"))
        or AppConfig().campus_ip_prefixes,
        campus_nic_name=str(data.get("campus_nic_name") or ""),
        srun_ac_id=str(srun.get("ac_id") or ""),
        srun_double_stack=bool(srun.get("double_stack", False)),
        ruijie_service=str(ruijie.get("service") or ""),
        custom_method=str(custom.get("method") or "POST"),
        custom_url=str(custom.get("url") or ""),
        custom_body=str(custom.get("body") or ""),
        custom_headers=dict(custom.get("headers") or {}),
        custom_success_contains=str(custom.get("success_contains") or ""),
        bypass_proxy=bool(vpn.get("bypass_proxy", True)),
        clash_auto=bool(vpn.get("clash_auto", True)),
        clash_api=str(vpn.get("clash_api") or ""),
        clash_secret=str(vpn.get("clash_secret") or ""),
        clash_switch_direct=bool(vpn.get("clash_switch_direct", True)),
        clash_disable_tun=bool(vpn.get("clash_disable_tun", True)),
        disable_system_proxy=bool(vpn.get("disable_system_proxy", True)),
        pre_commands=_as_str_list(vpn.get("pre_commands")),
        post_commands=_as_str_list(vpn.get("post_commands")),
        watch_interval=int(watch.get("interval_seconds") or 15),
        startup_delay=int(watch.get("startup_delay_seconds") or 8),
        link_up_delay=int(watch.get("link_up_delay_seconds") or 5),
        log_level=str(logging_cfg.get("level") or "INFO"),
        raw=data,
    )


def save_config(cfg: AppConfig, path: Path | None = None) -> Path:
    cfg_path = path or default_config_path()
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "backend": cfg.backend,
        "username": cfg.username,
        "password": cfg.password,
        "portal_url": cfg.portal_url,
        "click_only": cfg.click_only,
        "bind_campus_nic": cfg.bind_campus_nic,
        "campus_ip_prefixes": cfg.campus_ip_prefixes,
        "campus_nic_name": cfg.campus_nic_name,
        "srun": {"ac_id": cfg.srun_ac_id, "double_stack": cfg.srun_double_stack},
        "ruijie": {"service": cfg.ruijie_service},
        "custom": {
            "method": cfg.custom_method,
            "url": cfg.custom_url,
            "body": cfg.custom_body,
            "headers": cfg.custom_headers,
            "success_contains": cfg.custom_success_contains,
        },
        "vpn": {
            "bypass_proxy": cfg.bypass_proxy,
            "clash_auto": cfg.clash_auto,
            "clash_api": cfg.clash_api,
            "clash_secret": cfg.clash_secret,
            "clash_switch_direct": cfg.clash_switch_direct,
            "clash_disable_tun": cfg.clash_disable_tun,
            "disable_system_proxy": cfg.disable_system_proxy,
            "pre_commands": cfg.pre_commands,
            "post_commands": cfg.post_commands,
        },
        "watch": {
            "interval_seconds": cfg.watch_interval,
            "startup_delay_seconds": cfg.startup_delay,
            "link_up_delay_seconds": cfg.link_up_delay,
        },
        "logging": {"level": cfg.log_level},
    }
    text = yaml.safe_dump(payload, allow_unicode=True, sort_keys=False)
    cfg_path.write_text(text, encoding="utf-8")
    try:
        os.chmod(cfg_path, 0o600)
    except OSError:
        pass
    return cfg_path
