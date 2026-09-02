from __future__ import annotations

import json
import logging
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator
from urllib.parse import urlparse

import requests

from campus_connect.models import AppConfig

log = logging.getLogger("campus_connect")

CLASH_PORTS = (9090, 9097, 9091, 9093, 9092, 9094)


@dataclass
class ClashSnapshot:
    mode: str = ""
    tun_enable: bool | None = None


class ClashController:
    def __init__(self, base: str, secret: str = ""):
        self.base = base.rstrip("/")
        self.secret = secret
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.proxies = {"http": "", "https": ""}
        if secret:
            self.session.headers["Authorization"] = f"Bearer {secret}"

    def get_configs(self) -> dict | None:
        try:
            resp = self.session.get(f"{self.base}/configs", timeout=0.45)
            if resp.status_code == 200:
                data = resp.json()
                return data if isinstance(data, dict) else None
        except requests.RequestException:
            return None
        return None

    def get_mode(self) -> str | None:
        data = self.get_configs()
        if data is None:
            return None
        return str(data.get("mode") or "")

    def snapshot(self) -> ClashSnapshot | None:
        data = self.get_configs()
        if data is None:
            return None
        tun = data.get("tun") if isinstance(data.get("tun"), dict) else {}
        enable = tun.get("enable")
        tun_enable = bool(enable) if isinstance(enable, bool) else None
        return ClashSnapshot(mode=str(data.get("mode") or ""), tun_enable=tun_enable)

    def _patch(self, payload: dict, timeout: float = 2.0) -> bool:
        try:
            resp = self.session.patch(
                f"{self.base}/configs",
                headers={"Content-Type": "application/json"},
                data=json.dumps(payload),
                timeout=timeout,
            )
            return resp.status_code in {200, 204, 207}
        except requests.RequestException:
            return False

    def set_mode(self, mode: str) -> bool:
        return self._patch({"mode": mode})

    def set_tun(self, enabled: bool) -> bool:
        return self._patch({"tun": {"enable": enabled}})

    def restore(self, snap: ClashSnapshot) -> None:
        if snap.mode:
            if not self.set_mode(snap.mode):
                log.warning("恢复 Clash 模式失败，请手动改回 %s", snap.mode)
        if snap.tun_enable is not None:
            if not self.set_tun(snap.tun_enable):
                log.warning("恢复 Clash TUN 失败，请在客户端里手动打开/关闭 TUN")


def discover_clash(cfg: AppConfig) -> ClashController | None:
    candidates: list[str] = []
    if cfg.clash_api:
        candidates.append(cfg.clash_api)
    if cfg.clash_auto:
        for port in CLASH_PORTS:
            url = f"http://127.0.0.1:{port}"
            if url not in candidates:
                candidates.append(url)
    secrets = [""]
    if cfg.clash_secret and cfg.clash_secret not in secrets:
        secrets.append(cfg.clash_secret)
    tried: list[tuple[str, str]] = []
    for base in candidates:
        for secret in secrets:
            key = (base, secret)
            if key in tried:
                continue
            tried.append(key)
            ctl = ClashController(base, secret or "")
            mode = ctl.get_mode()
            if mode is not None:
                log.info("发现 Clash API %s，当前模式 %s", base, mode or "(空)")
                return ctl
    return None


def _notify_wininet() -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes

        wininet = ctypes.windll.Wininet
        wininet.InternetSetOptionW(0, 39, 0, 0)  # SETTINGS_CHANGED
        wininet.InternetSetOptionW(0, 37, 0, 0)  # REFRESH
    except Exception:
        log.debug("无法通知 WinINET 刷新代理", exc_info=True)


class WindowsProxyGuard:
    def __init__(self) -> None:
        self.previous: int | None = None

    def disable(self) -> None:
        if sys.platform != "win32":
            return
        try:
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                0,
                winreg.KEY_ALL_ACCESS,
            )
            try:
                value, _typ = winreg.QueryValueEx(key, "ProxyEnable")
                self.previous = int(value)
                if self.previous:
                    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                    _notify_wininet()
                    log.info("已临时关闭 Windows 系统代理")
            finally:
                winreg.CloseKey(key)
        except OSError as exc:
            log.debug("读取/关闭系统代理失败: %s", exc)

    def restore(self) -> None:
        if sys.platform != "win32" or not self.previous:
            return
        try:
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                0,
                winreg.KEY_ALL_ACCESS,
            )
            try:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, self.previous)
                _notify_wininet()
                log.info("已恢复 Windows 系统代理")
            finally:
                winreg.CloseKey(key)
        except OSError as exc:
            log.warning("恢复系统代理失败: %s", exc)
        self.previous = None


def flush_dns() -> None:
    if sys.platform == "win32":
        try:
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=8, check=False)
            log.info("已刷新 DNS 缓存（避免 Fake-IP 残留）")
        except (OSError, subprocess.SubprocessError):
            pass


def _run_commands(commands: list[str], label: str) -> None:
    for cmd in commands:
        if not cmd.strip():
            continue
        log.info("执行%s命令: %s", label, cmd)
        try:
            subprocess.run(cmd, shell=True, timeout=20, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            log.warning("命令失败: %s", exc)


class VpnBypass:
    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        self.clash: ClashController | None = None
        self.snapshot: ClashSnapshot | None = None
        self.restore_clash = True
        self.proxy_guard = WindowsProxyGuard()

    def __enter__(self) -> "VpnBypass":
        if self.cfg.clash_switch_direct or self.cfg.clash_disable_tun:
            self.clash = discover_clash(self.cfg)
            if self.clash is not None:
                self.snapshot = self.clash.snapshot()
                changed = False
                if (
                    self.cfg.clash_switch_direct
                    and self.snapshot
                    and self.snapshot.mode
                    and self.snapshot.mode.lower() != "direct"
                ):
                    if self.clash.set_mode("direct"):
                        log.info("已将 Clash 临时切换为 Direct（原模式 %s）", self.snapshot.mode)
                        changed = True
                    else:
                        log.warning("无法切换 Clash 模式")
                if self.cfg.clash_disable_tun:
                    if self.clash.set_tun(False):
                        log.info("已临时关闭 Clash TUN（拔插网线后 TUN 经常把默认路由截死）")
                        changed = True
                        if self.snapshot and self.snapshot.tun_enable is None:
                            self.snapshot.tun_enable = True
                    else:
                        log.warning("无法关闭 Clash TUN，若上网失败请手动关 TUN")
                if changed:
                    time.sleep(1.3)
                    flush_dns()
        if self.cfg.disable_system_proxy:
            self.proxy_guard.disable()
        _run_commands(self.cfg.pre_commands, "认证前")
        return self

    def hold_tun_off(self) -> None:
        self.restore_clash = False
        if self.clash is not None:
            self.clash.set_tun(False)

    def __exit__(self, exc_type, exc, tb) -> None:
        _run_commands(self.cfg.post_commands, "认证后")
        self.proxy_guard.restore()
        if self.clash is None or self.snapshot is None:
            return
        if self.restore_clash:
            self.clash.restore(self.snapshot)
            log.info("已恢复 Clash 原来的模式/TUN")
        else:
            if self.snapshot.mode:
                self.clash.set_mode(self.snapshot.mode)
            self.clash.set_tun(False)
            log.warning("未恢复 Clash TUN：恢复后系统仍会上不了网。可在 Clash 里改用系统代理而不是 TUN")


@contextmanager
def vpn_bypass(cfg: AppConfig) -> Iterator[VpnBypass]:
    helper = VpnBypass(cfg)
    helper.__enter__()
    try:
        yield helper
    finally:
        helper.__exit__(None, None, None)


def origin_of(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return url
    return f"{parsed.scheme}://{parsed.netloc}"
