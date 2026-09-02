from __future__ import annotations

import argparse
import getpass
import logging
import os
import sys
from pathlib import Path

from campus_connect.config import (
    default_config_path,
    load_config,
    log_path,
    save_config,
)
from campus_connect.detect import detect_portal
from campus_connect.engine import connect_once
from campus_connect.install import install_autostart, uninstall_autostart
from campus_connect.netutil import (
    check_online,
    clear_proxy_env,
    describe_connectivity,
    format_nic_overview,
    list_nics,
    list_tun_nics,
    make_session,
    make_unbound_session,
    pick_campus_nic,
    restore_proxy_env,
    windows_system_proxy,
)
from campus_connect.vpn import discover_clash
from campus_connect.watch import run_watch


def _configure_stdio() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def setup_logging(level: str) -> None:
    log_file = log_path()
    numeric = getattr(logging, (level or "INFO").upper(), logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    root = logging.getLogger("campus_connect")
    root.setLevel(numeric)
    root.handlers.clear()
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    root.addHandler(fh)
    root.addHandler(sh)
    logging.getLogger().handlers.clear()


def _load(args: argparse.Namespace) -> tuple[AppConfig, Path]:
    path = Path(args.config).expanduser() if getattr(args, "config", None) else default_config_path()
    return load_config(path if path.is_file() else None), path


def cmd_status(args: argparse.Namespace) -> int:
    cfg, path = _load(args)
    setup_logging(cfg.log_level)
    saved = clear_proxy_env() if cfg.bypass_proxy else {}
    try:
        nic = pick_campus_nic(cfg)
        bound = make_session(cfg, nic.ip if nic else None)
        unbound = make_unbound_session(cfg)
        bound_st = check_online(bound, timeout=4.0)
        unbound_st = check_online(unbound, timeout=4.0)
        tuns = list_tun_nics()
        diagnosis = describe_connectivity(bound_st.online, unbound_st.online, bool(tuns))
        print(f"配置文件: {path if path.is_file() else '(尚未创建，使用默认值)'}")
        print(f"校园网网卡: {f'{nic.name} {nic.ip}' if nic else '未识别到'}")
        print(f"TUN 虚拟网卡: {', '.join(f'{t.name}({t.ip})' for t in tuns) or '无'}")
        print(f"校园网卡直连: {'通' if bound_st.online else '不通'} — {bound_st.reason}")
        print(f"系统默认路由: {'通' if unbound_st.online else '不通'} — {unbound_st.reason}")
        print(f"诊断: {diagnosis}")
        return 0 if unbound_st.online else 2
    finally:
        restore_proxy_env(saved)


def cmd_probe(args: argparse.Namespace) -> int:
    cfg, path = _load(args)
    setup_logging(cfg.log_level)
    saved = clear_proxy_env() if cfg.bypass_proxy else {}
    try:
        print("== 本机网卡 ==")
        nics = list_nics()
        if not nics:
            print("  (没有解析到 IPv4 地址)")
        for nic in nics:
            tag = " [TUN/虚拟网卡]" if nic.is_tun else ""
            print(f"  {nic.name}: {nic.ip}{tag}")
        print(f"  总览: {format_nic_overview(nics)}")
        nic = pick_campus_nic(cfg)
        print(f"选定校园网网卡: {f'{nic.name} {nic.ip}' if nic else '无'}")
        if cfg.campus_nic_name:
            print(f"  campus_nic_name: {cfg.campus_nic_name}")
        if nic is None:
            print("  提示: 网线已插仍选不到时，在 config.yaml 设置 campus_nic_name: 以太网")
        print()
        print("== 代理 / 梯子 ==")
        env_proxy = {k: v for k, v in os.environ.items() if "proxy" in k.lower()}
        print(f"  进程环境代理: {env_proxy or '无'}")
        win_proxy = windows_system_proxy()
        if win_proxy:
            print("  Windows 系统代理:")
            print("  " + win_proxy.replace("\n", "\n  "))
        clash = discover_clash(cfg)
        if clash:
            snap = clash.snapshot()
            tun_state = "未知"
            if snap and snap.tun_enable is True:
                tun_state = "开"
            elif snap and snap.tun_enable is False:
                tun_state = "关"
            print(f"  Clash API: {clash.base}  模式={clash.get_mode()}  TUN={tun_state}")
        else:
            print("  未发现 Clash 控制端口（系统代理模式仍然可以绕过）")
        print()
        session = make_session(cfg, nic.ip if nic else None)
        unbound = make_unbound_session(cfg)
        bound_st = check_online(session, timeout=4.0)
        unbound_st = check_online(unbound, timeout=4.0)
        print("== 联网探测 ==")
        print(f"  校园网卡直连: {'通' if bound_st.online else '不通'} — {bound_st.reason}")
        print(f"  系统默认路由: {'通' if unbound_st.online else '不通'} — {unbound_st.reason}")
        print(f"  诊断: {describe_connectivity(bound_st.online, unbound_st.online, bool(list_tun_nics()))}")
        print()
        portal = detect_portal(session, cfg)
        print("== 认证页 ==")
        print(f"  找到: {portal.found}")
        print(f"  URL: {portal.url or '-'}")
        print(f"  识别类型: {portal.backend}")
        print(f"  ac_id: {portal.ac_id or '-'}")
        print(f"  校园网 IP: {portal.user_ip or '-'}")
        for note in portal.notes:
            print(f"  - {note}")
        dump = Path.cwd() / "portal-dump.html"
        if portal.html:
            dump.write_text(portal.html, encoding="utf-8", errors="replace")
            print(f"  已保存页面到 {dump}")
        print()
        print(f"配置文件路径: {path}")
        if not path.is_file():
            print("还没有 config.yaml。运行: campus-connect setup")
        return 0 if portal.found or unbound_st.online or bound_st.online else 2
    finally:
        restore_proxy_env(saved)


def cmd_login(args: argparse.Namespace) -> int:
    cfg, path = _load(args)
    setup_logging(cfg.log_level)
    if not path.is_file():
        print(f"未找到配置文件 {path}")
        print("请先复制 config.example.yaml 为 config.yaml，或运行: python -m campus_connect setup")
        return 1
    result = connect_once(cfg)
    prefix = "成功" if result.ok else "失败"
    extra = "（本来就已经能上网）" if result.already_online else ""
    print(f"[{prefix}] {result.message}{extra}")
    if result.diagnosis:
        print(f"诊断: {result.diagnosis}")
    if result.tun_held_off:
        print("注意: 已保持 Clash TUN 关闭。否则拔插网线后系统会再次上不了网。")
    if result.backend:
        print(f"认证方式: {result.backend}")
    if result.portal_url:
        print(f"认证页: {result.portal_url}")
    return 0 if result.ok else 1


def cmd_watch(args: argparse.Namespace) -> int:
    cfg, path = _load(args)
    setup_logging(cfg.log_level)
    return run_watch(cfg, str(path))


def cmd_setup(args: argparse.Namespace) -> int:
    _configure_stdio()
    target = Path(args.config).expanduser() if args.config else default_config_path()
    print("校园网自动连接 — 初始化")
    print("本脚本只用于登录你自己的校园网账号，请遵守学校网络规定。")
    print()
    cfg = load_config(target if target.is_file() else None)
    setup_logging(cfg.log_level)
    print("正在探测认证页（请先连上校园网 Wi-Fi / 网线）...")
    saved = clear_proxy_env() if cfg.bypass_proxy else {}
    try:
        nic = pick_campus_nic(cfg)
        session = make_session(cfg, nic.ip if nic else None)
        portal = detect_portal(session, cfg)
        status = check_online(session)
    finally:
        restore_proxy_env(saved)

    if status.online:
        print(f"现在已经能上网: {status.reason}")
    if portal.found:
        print(f"发现认证页: {portal.url}")
        print(f"类型猜测: {portal.backend}")
        cfg.portal_url = cfg.portal_url or portal.url
        if portal.backend in {"srun", "ruijie", "drcom", "generic"}:
            cfg.backend = "auto"
        if portal.ac_id:
            cfg.srun_ac_id = cfg.srun_ac_id or portal.ac_id
    else:
        print("这一步没有探测到认证页。也可以先把账号写进配置，连上校园网后再运行 probe / login。")

    print()
    username = input(f"学号/账号（一键连接可留空） [{cfg.username}]: ").strip()
    if username:
        cfg.username = username
    prompt = "密码（输入时不显示，直接回车表示不改）: " if cfg.password else "密码（输入时不显示，一键连接可留空）: "
    password = getpass.getpass(prompt)
    if password:
        cfg.password = password
    click = input("认证页是不是只需要点一下「连接」，不需要账号？ [y/N]: ").strip().lower()
    if click in {"y", "yes", "是"}:
        cfg.click_only = True
        cfg.backend = "generic"
    portal_in = input(f"认证页 URL（可留空自动探测） [{cfg.portal_url}]: ").strip()
    if portal_in:
        cfg.portal_url = portal_in
    nic_hint = cfg.campus_nic_name or (nic.name if nic else "")
    nic_in = input(
        f"校园网卡名称（有 VMware 虚拟网卡时建议填 以太网，可留空自动选） [{nic_hint}]: "
    ).strip()
    if nic_in:
        cfg.campus_nic_name = nic_in
    elif nic and not cfg.campus_nic_name:
        cfg.campus_nic_name = nic.name

    saved_path = save_config(cfg, target)
    print(f"\n已写入 {saved_path}")

    try_now = input("现在尝试连接一次？ [Y/n]: ").strip().lower()
    if try_now not in {"n", "no", "否"}:
        result = connect_once(cfg)
        print(("成功: " if result.ok else "失败: ") + result.message)

    auto = input("安装开机自动连接？ [Y/n]: ").strip().lower()
    if auto not in {"n", "no", "否"}:
        print(install_autostart(cfg, saved_path))
    print("\n常用命令:")
    print("  python -m campus_connect probe   # 探测认证页")
    print("  python -m campus_connect login   # 立即连接一次")
    print("  python -m campus_connect watch   # 后台守护，掉线自动重连")
    print(f"日志: {log_path()}")
    return 0


def cmd_install(args: argparse.Namespace) -> int:
    cfg, path = _load(args)
    if not path.is_file():
        print("请先运行 python -m campus_connect setup 生成配置")
        return 1
    print(install_autostart(cfg, path))
    return 0


def cmd_uninstall(args: argparse.Namespace) -> int:
    print(uninstall_autostart())
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="campus-connect",
        description="校园网认证页自动连接（开机自启，认证时绕过梯子）",
    )
    parser.add_argument("--config", help="config.yaml 路径")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("setup", help="交互式配置并安装开机自启")
    sub.add_parser("probe", help="探测认证页类型和梯子状态")
    sub.add_parser("status", help="查看当前是否已经能上网")
    sub.add_parser("login", help="立即认证一次")
    sub.add_parser("watch", help="后台守护，掉线后自动重连")
    sub.add_parser("install", help="安装开机自启")
    sub.add_parser("uninstall", help="取消开机自启")
    return parser


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        print("\n第一次使用请运行: python -m campus_connect setup")
        return 0
    handlers = {
        "setup": cmd_setup,
        "probe": cmd_probe,
        "status": cmd_status,
        "login": cmd_login,
        "watch": cmd_watch,
        "install": cmd_install,
        "uninstall": cmd_uninstall,
    }
    return handlers[args.command](args)
