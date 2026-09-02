from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

from campus_connect.config import project_root, user_data_dir
from campus_connect.models import AppConfig

TASK_NAME = "CampusAutoConnect"
STARTUP_VBS = "campus-auto-connect.vbs"
LINUX_UNIT = "campus-auto-connect.service"


def python_executable() -> str:
    venv_win = project_root() / ".venv" / "Scripts" / "python.exe"
    venv_unix = project_root() / ".venv" / "bin" / "python"
    if venv_win.is_file():
        return str(venv_win)
    if venv_unix.is_file():
        return str(venv_unix)
    return sys.executable


def _vbs_literal(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _write_watch_vbs(vbs_path: Path, config_path: Path) -> None:
    vbs_path.parent.mkdir(parents=True, exist_ok=True)
    root = project_root()
    py = python_executable()
    pyw = py.replace("python.exe", "pythonw.exe")
    if Path(pyw).is_file():
        py = pyw
    run_cmd = f'"{py}" -m campus_connect watch --config "{config_path}"'
    vbs = textwrap.dedent(
        f"""
        Set sh = CreateObject("WScript.Shell")
        sh.CurrentDirectory = {_vbs_literal(str(root))}
        sh.Run {_vbs_literal(run_cmd)}, 0, False
        """
    ).lstrip()
    vbs_path.write_text(vbs, encoding="utf-8")


def install_windows(cfg: AppConfig, config_path: Path) -> str:
    del cfg
    vbs_path = user_data_dir() / STARTUP_VBS
    _write_watch_vbs(vbs_path, config_path)
    notes = [f"守护脚本: {vbs_path}"]

    task_ok = False
    try:
        proc = subprocess.run(
            [
                "schtasks",
                "/Create",
                "/TN",
                TASK_NAME,
                "/SC",
                "ONLOGON",
                "/DELAY",
                "0000:15",
                "/RL",
                "LIMITED",
                "/F",
                "/TR",
                f'wscript.exe "{vbs_path}"',
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        notes.append(proc.stdout.strip() or proc.stderr.strip() or f"计划任务 exit {proc.returncode}")
        task_ok = proc.returncode == 0
    except OSError as exc:
        notes.append(f"未创建计划任务（{exc}）")

    startup = Path(os.environ.get("APPDATA", str(Path.home()))) / r"Microsoft\Windows\Start Menu\Programs\Startup"
    startup_vbs = startup / STARTUP_VBS
    if task_ok:
        if startup_vbs.exists():
            startup_vbs.unlink()
        notes.append("已用登录计划任务启动守护进程（不会再往「启动」文件夹里放一份，避免跑两个）。")
    else:
        startup.mkdir(parents=True, exist_ok=True)
        _write_watch_vbs(startup_vbs, config_path)
        notes.append(f"已写入开机启动文件夹: {startup_vbs}")

    notes.append("登录 Windows 后会自动处理校园网；拔插网线也会在守护进程里重试。")
    return "\n".join(notes)


def uninstall_windows() -> str:
    messages = []
    for vbs_path in (
        user_data_dir() / STARTUP_VBS,
        Path(os.environ.get("APPDATA", str(Path.home())))
        / r"Microsoft\Windows\Start Menu\Programs\Startup"
        / STARTUP_VBS,
    ):
        if vbs_path.exists():
            vbs_path.unlink()
            messages.append(f"已删除 {vbs_path}")
    try:
        proc = subprocess.run(
            ["schtasks", "/Delete", "/TN", TASK_NAME, "/F"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        messages.append(proc.stdout.strip() or proc.stderr.strip() or "计划任务已处理")
    except OSError:
        messages.append("没有删除计划任务（可能本来就没有）")
    return "\n".join(messages) or "没有需要卸载的开机项"


def install_linux(config_path: Path) -> str:
    unit_dir = Path.home() / ".config/systemd/user"
    unit_dir.mkdir(parents=True, exist_ok=True)
    unit_path = unit_dir / LINUX_UNIT
    py = python_executable()
    root = project_root()
    unit = textwrap.dedent(
        f"""
        [Unit]
        Description=Campus network auto connect
        After=network-online.target
        Wants=network-online.target

        [Service]
        Type=simple
        WorkingDirectory={root}
        ExecStart={py} -m campus_connect watch --config "{config_path}"
        Restart=always
        RestartSec=15

        [Install]
        WantedBy=default.target
        """
    ).lstrip()
    unit_path.write_text(unit, encoding="utf-8")
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
    proc = subprocess.run(
        ["systemctl", "--user", "enable", "--now", LINUX_UNIT],
        capture_output=True,
        text=True,
    )
    extra = (proc.stdout or "") + (proc.stderr or "")
    return f"已安装 systemd 用户服务: {unit_path}\n{extra.strip()}"


def uninstall_linux() -> str:
    subprocess.run(["systemctl", "--user", "disable", "--now", LINUX_UNIT], check=False)
    unit_path = Path.home() / ".config/systemd/user" / LINUX_UNIT
    if unit_path.exists():
        unit_path.unlink()
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
    return f"已移除 {unit_path}"


def install_macos(config_path: Path) -> str:
    agents = Path.home() / "Library/LaunchAgents"
    agents.mkdir(parents=True, exist_ok=True)
    plist_path = agents / "com.campus.auto-connect.plist"
    py = python_executable()
    logs = user_data_dir()
    logs.mkdir(parents=True, exist_ok=True)
    plist = textwrap.dedent(
        f"""
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key><string>com.campus.auto-connect</string>
            <key>WorkingDirectory</key><string>{project_root()}</string>
            <key>ProgramArguments</key>
            <array>
                <string>{py}</string>
                <string>-m</string>
                <string>campus_connect</string>
                <string>watch</string>
                <string>--config</string>
                <string>{config_path}</string>
            </array>
            <key>RunAtLoad</key><true/>
            <key>KeepAlive</key><true/>
            <key>StandardOutPath</key><string>{logs / "launchd.out.log"}</string>
            <key>StandardErrorPath</key><string>{logs / "launchd.err.log"}</string>
        </dict>
        </plist>
        """
    ).lstrip()
    plist_path.write_text(plist, encoding="utf-8")
    subprocess.run(["launchctl", "unload", str(plist_path)], check=False)
    proc = subprocess.run(["launchctl", "load", str(plist_path)], capture_output=True, text=True)
    extra = (proc.stdout or "") + (proc.stderr or "")
    return f"已安装 LaunchAgent: {plist_path}\n{extra.strip()}"


def uninstall_macos() -> str:
    plist_path = Path.home() / "Library/LaunchAgents/com.campus.auto-connect.plist"
    subprocess.run(["launchctl", "unload", str(plist_path)], check=False)
    if plist_path.exists():
        plist_path.unlink()
    return f"已移除 {plist_path}"


def install_autostart(cfg: AppConfig, config_path: Path) -> str:
    if sys.platform == "win32":
        return install_windows(cfg, config_path)
    if sys.platform == "darwin":
        return install_macos(config_path)
    return install_linux(config_path)


def uninstall_autostart() -> str:
    if sys.platform == "win32":
        return uninstall_windows()
    if sys.platform == "darwin":
        return uninstall_macos()
    return uninstall_linux()
