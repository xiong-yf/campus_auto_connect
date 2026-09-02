from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class NicInfo:
    name: str
    ip: str
    is_tun: bool = False


@dataclass
class OnlineStatus:
    online: bool
    reason: str
    final_url: str = ""
    status_code: int | None = None
    body_snippet: str = ""


@dataclass
class PortalInfo:
    found: bool
    url: str = ""
    backend: str = "generic"
    html: str = ""
    query: str = ""
    ac_id: str = ""
    user_ip: str = ""
    notes: list[str] = field(default_factory=list)


@dataclass
class LoginResult:
    ok: bool
    message: str
    backend: str = ""
    already_online: bool = False
    portal_url: str = ""
    tun_held_off: bool = False
    diagnosis: str = ""


@dataclass
class AppConfig:
    backend: str = "auto"
    username: str = ""
    password: str = ""
    portal_url: str = ""
    click_only: bool = False
    bind_campus_nic: bool = True
    campus_ip_prefixes: list[str] = field(
        default_factory=lambda: [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ]
    )
    campus_nic_name: str = ""
    srun_ac_id: str = ""
    srun_double_stack: bool = False
    ruijie_service: str = ""
    custom_method: str = "POST"
    custom_url: str = ""
    custom_body: str = ""
    custom_headers: dict[str, str] = field(default_factory=dict)
    custom_success_contains: str = ""
    bypass_proxy: bool = True
    clash_auto: bool = True
    clash_api: str = ""
    clash_secret: str = ""
    clash_switch_direct: bool = True
    clash_disable_tun: bool = True
    disable_system_proxy: bool = True
    pre_commands: list[str] = field(default_factory=list)
    post_commands: list[str] = field(default_factory=list)
    watch_interval: int = 15
    startup_delay: int = 8
    link_up_delay: int = 5
    log_level: str = "INFO"
    raw: dict[str, Any] = field(default_factory=dict)
