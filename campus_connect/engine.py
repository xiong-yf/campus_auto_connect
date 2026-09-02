from __future__ import annotations

import logging
import time

from campus_connect.auth import run_backend
from campus_connect.detect import detect_portal, guess_backend
from campus_connect.models import AppConfig, LoginResult, PortalInfo
from campus_connect.netutil import (
    check_online,
    clear_proxy_env,
    describe_connectivity,
    format_nic_overview,
    list_tun_nics,
    make_session,
    make_unbound_session,
    pick_campus_nic,
    restore_proxy_env,
)
from campus_connect.vpn import VpnBypass, discover_clash

log = logging.getLogger("campus_connect")


def _session_for(cfg: AppConfig):
    nic = pick_campus_nic(cfg) if cfg.bind_campus_nic else None
    source_ip = nic.ip if nic else None
    if nic:
        log.info("绑定校园网网卡 %s (%s) 发送认证请求", nic.name, nic.ip)
    elif cfg.bind_campus_nic:
        log.info(
            "未识别到校园网网卡，改用不绑定源地址的方式（仍绕过系统代理）。当前网卡: %s",
            format_nic_overview(),
        )
    return make_session(cfg, source_ip), nic


def connect_once(cfg: AppConfig) -> LoginResult:
    saved_env = clear_proxy_env() if cfg.bypass_proxy else {}
    try:
        return _connect_once_body(cfg)
    finally:
        restore_proxy_env(saved_env)


def _connect_once_body(cfg: AppConfig) -> LoginResult:
    bound, _nic = _session_for(cfg)
    unbound = make_unbound_session(cfg)
    tun_present = bool(list_tun_nics())

    unbound_st = check_online(unbound, timeout=4.0)
    bound_st = check_online(bound, timeout=4.0)
    diagnosis = describe_connectivity(bound_st.online, unbound_st.online, tun_present)
    log.info("连通性: %s（网卡直连=%s, 默认路由=%s, TUN=%s）", diagnosis, bound_st.online, unbound_st.online, tun_present)

    if unbound_st.online:
        return LoginResult(
            ok=True,
            already_online=True,
            message=unbound_st.reason,
            backend="none",
            diagnosis=diagnosis,
        )

    with VpnBypass(cfg) as bypass:
        time.sleep(0.4)
        unbound_after = check_online(unbound, timeout=4.0)
        if unbound_after.online:
            result = LoginResult(
                ok=True,
                already_online=True,
                message="校园网已认证；刚才是梯子挡住了默认路由，已临时绕过",
                backend="none",
                diagnosis=diagnosis,
            )
        else:
            result = _connect_inner(cfg, bound, unbound)
            result.diagnosis = result.diagnosis or diagnosis
        unbound_ok = check_online(unbound, timeout=4.0).online
        if result.ok and not unbound_ok:
            bypass.hold_tun_off()
            result.tun_held_off = True
            result.message += "；恢复梯子 TUN 后仍不通，已保持 TUN 关闭"

    if result.ok and not result.tun_held_off:
        # After restoring Clash, default route may die again on cable-replug.
        unbound_restored = check_online(unbound, timeout=4.0)
        if not unbound_restored.online:
            clash = discover_clash(cfg)
            if clash is not None and cfg.clash_disable_tun:
                if clash.set_tun(False):
                    time.sleep(0.8)
                    if check_online(unbound, timeout=4.0).online:
                        result.tun_held_off = True
                        result.message += "；重新打开 TUN 后又不通，已再次关闭 Clash TUN"
                        log.warning("恢复 Clash TUN 后默认路由再次失败，已保持 TUN 关闭")
    return result


def _connect_inner(cfg: AppConfig, session, unbound) -> LoginResult:
    status = check_online(session, timeout=4.0)
    unbound_st = check_online(unbound, timeout=4.0)
    if unbound_st.online:
        log.info("已经能上网: %s", unbound_st.reason)
        return LoginResult(ok=True, already_online=True, message=unbound_st.reason, backend="none")
    if status.online:
        log.info("校园网卡已能出网，系统默认路由仍不通: %s", unbound_st.reason)
        return LoginResult(
            ok=True,
            already_online=True,
            message="校园网已认证；系统默认路由仍被梯子影响",
            backend="none",
        )

    log.info("当前未认证: %s", status.reason)
    portal = detect_portal(session, cfg)
    if status.final_url and not portal.found:
        portal = PortalInfo(
            found=True,
            url=status.final_url,
            backend=guess_backend(status.final_url, status.body_snippet),
            html=status.body_snippet,
            notes=["使用探测跳转地址作为认证页"],
        )
    if not portal.found and not cfg.portal_url:
        return LoginResult(
            ok=False,
            message="没有找到校园网认证页。请先运行 campus-connect probe，或在 config.yaml 里填写 portal_url",
        )
    if not portal.found and cfg.portal_url:
        portal = PortalInfo(found=True, url=cfg.portal_url, backend=cfg.backend or "generic")

    wanted = (cfg.backend or "auto").lower()
    if cfg.click_only:
        order = ["generic"]
    elif wanted in {"srun", "ruijie", "drcom", "generic", "custom"}:
        order = [wanted]
    else:
        guessed = portal.backend or "generic"
        order = [guessed]
        for name in ("srun", "ruijie", "drcom", "generic"):
            if name not in order:
                order.append(name)

    last = LoginResult(ok=False, message="没有可用的认证方式", portal_url=portal.url)
    for name in order:
        if name != "generic" and name != "custom" and not cfg.username and not cfg.click_only:
            continue
        log.info("尝试认证方式: %s  认证页: %s", name, portal.url or "(自动)")
        result = run_backend(name, session, cfg, portal)
        last = result
        if result.ok:
            time.sleep(0.8)
            confirm_unbound = check_online(unbound, timeout=4.0)
            if confirm_unbound.online:
                result.message = f"{result.message}；确认系统已联网 ({confirm_unbound.reason})"
                return result
            confirm_bound = check_online(session, timeout=4.0)
            if confirm_bound.online:
                result.message = f"{result.message}；校园网卡已通，系统默认路由仍不通"
                return result
            log.warning("认证接口显示成功，但联网探测仍未通过: %s", confirm_unbound.reason)
            last = LoginResult(
                ok=False,
                message=f"{result.message}（联网探测未通过: {confirm_unbound.reason}）",
                backend=result.backend,
                portal_url=result.portal_url,
            )
            if wanted != "auto":
                return last
            continue
        log.info("%s 未成功: %s", name, result.message)
        if wanted != "auto":
            break
    return last
