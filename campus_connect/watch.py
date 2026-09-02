from __future__ import annotations

import logging
import os
import sys
import time

from campus_connect.config import user_data_dir
from campus_connect.engine import connect_once
from campus_connect.models import AppConfig
from campus_connect.netutil import (
    campus_link_up_without_ip,
    format_nic_overview,
    nic_fingerprint,
    pick_campus_nic,
    wait_for_campus_ipv4,
)

log = logging.getLogger("campus_connect")


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == "win32":
        try:
            import ctypes

            handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
            if handle:
                ctypes.windll.kernel32.CloseHandle(handle)
                return True
            return False
        except Exception:
            return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def acquire_watch_lock() -> bool:
    directory = user_data_dir()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "watch.pid"
    if path.is_file():
        try:
            old = int(path.read_text(encoding="utf-8").strip())
        except ValueError:
            old = 0
        if _pid_alive(old) and old != os.getpid():
            log.warning("已有守护进程在运行 (pid=%s)，本次退出以免重复认证", old)
            return False
    path.write_text(str(os.getpid()), encoding="utf-8")
    return True


def run_watch(cfg: AppConfig, config_label: str) -> int:
    if not acquire_watch_lock():
        return 0
    delay = max(0, cfg.startup_delay)
    log.info("守护进程启动，%s 秒后开始（配置 %s）", delay, config_label)
    time.sleep(delay)
    log.info("本机网卡: %s", format_nic_overview())
    if cfg.campus_nic_name:
        log.info("已按 campus_nic_name=%s 选择网卡", cfg.campus_nic_name)

    last_fp = nic_fingerprint(cfg)
    had_campus = pick_campus_nic(cfg) is not None
    last_ok = False
    last_no_nic_log = 0.0

    while True:
        try:
            pending = campus_link_up_without_ip(cfg)
            if pending and pick_campus_nic(cfg) is None:
                wait = max(8, cfg.link_up_delay * 2)
                log.info("网卡 %s 已连接但还没有 IPv4，等待 %s 秒给 DHCP", pending, wait)
                wait_for_campus_ipv4(cfg, timeout=float(wait))

            fp = nic_fingerprint(cfg)
            campus = pick_campus_nic(cfg)
            link_up = campus is not None and not had_campus
            nic_changed = fp != last_fp
            if campus is None:
                now = time.time()
                if now - last_no_nic_log >= 20:
                    log.info(
                        "还没有校园网卡。当前网卡: %s。网线已插仍看不到物理网卡时，"
                        "在 config.yaml 设置 campus_nic_name（例如 以太网）后重跑 watch",
                        format_nic_overview(),
                    )
                    last_no_nic_log = now
                had_campus = False
                last_ok = False
                time.sleep(3)
                last_fp = fp
                continue
            if link_up or nic_changed:
                wait = max(1, cfg.link_up_delay)
                log.info("检测到网卡变化（%s → %s），等待 %s 秒给 DHCP", last_fp, fp, wait)
                time.sleep(wait)
            result = connect_once(cfg)
            last_ok = result.ok
            if result.ok:
                log.info("连接正常: %s", result.message)
            else:
                log.warning("连接失败: %s", result.message)
            had_campus = True
            last_fp = nic_fingerprint(cfg)
        except Exception:
            log.exception("watch 循环出错")
            last_ok = False
        time.sleep(5 if not last_ok else max(8, cfg.watch_interval))
