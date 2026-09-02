from __future__ import annotations

import base64
import ipaddress
import locale
import logging
import os
import re
import socket
import subprocess
import sys
import time
from urllib.parse import urlparse

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.exceptions import InsecureRequestWarning
from urllib3.poolmanager import PoolManager
from urllib3.util.retry import Retry

from campus_connect.models import AppConfig, NicInfo, OnlineStatus

log = logging.getLogger("campus_connect")

urllib3.disable_warnings(InsecureRequestWarning)

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)

DETECT_URLS = [
    ("http://www.msftconnecttest.com/connecttest.txt", "Microsoft Connect Test"),
    ("http://1.1.1.1/", ""),
    ("http://detectportal.firefox.com/canonical.html", "success"),
    ("http://connectivitycheck.gstatic.com/generate_204", ""),
    ("http://connect.rom.miui.com/generate_204", ""),
    ("http://captive.apple.com/hotspot-detect.html", "Success"),
]

DETECT_HOSTS = {
    "www.msftconnecttest.com",
    "msftconnecttest.com",
    "detectportal.firefox.com",
    "connectivitycheck.gstatic.com",
    "www.gstatic.com",
    "connect.rom.miui.com",
    "captive.apple.com",
    "www.apple.com",
}

COMMON_PORTAL_HINTS = [
    "http://1.1.1.1/",
    "http://10.0.0.55/",
    "http://10.0.0.1/",
    "http://123.123.123.123/",
    "http://172.30.0.1/",
]
GATEWAY_HOSTS = {"123.123.123.123"}
SKIP_NIC_HINTS = (
    "docker",
    "br-",
    "veth",
    "cni",
    "flannel",
    "virbr",
    "lxc",
    "podman",
    "kube",
    "nerdctl",
    "vmware",
    "vmnet",
    "virtualbox",
    "vbox",
    "hyper-v",
    "vethernet",
    "bluetooth",
    "loopback",
    "wsl",
    "npcap",
    "isatap",
    "teredo",
    "virtual adapter",
    "virtual network",
    "hosted network",
    "wi-fi direct",
    "zerotier",
    "hamachi",
    "softether",
)
PHYSICAL_NIC_HINTS = (
    "eth",
    "enp",
    "ens",
    "eno",
    "enx",
    "wlan",
    "wlp",
    "wls",
    "wi-fi",
    "wifi",
    "ethernet",
    "以太网",
    "乙太網路",
    "無線",
    "无线",
    "本地连接",
    "本地連線",
    "區域連線",
    "realtek",
    "intel",
    "killer",
    "broadcom",
    "qualcomm",
    "atheros",
    "marvell",
    "rtl81",
    "local area",
)

TUN_NAME_HINTS = (
    "meta",
    "clash",
    "mihomo",
    "tun",
    "utun",
    "singbox",
    "wintun",
    "wg",
    "wireguard",
    "tailscale",
    "tap-windows",
    "tap-win",
)
FAKE_IP_PREFIXES = ("198.18.", "198.19.")
PROXY_ENV_KEYS = (
    "http_proxy",
    "https_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "all_proxy",
)

_IPCONFIG_HEADER = re.compile(
    r"^(?:Ethernet adapter|Wireless LAN adapter|PPP adapter|"
    r"以太网适配器|無線區域網路適配器|无线局域网适配器|"
    r"以太網適配器|未知适配器)\s+(.+):\s*$",
    re.I,
)


class SourceAddressAdapter(HTTPAdapter):
    def __init__(self, source_address: str, **kwargs):
        self._source_address = (source_address, 0)
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs["source_address"] = self._source_address
        self.poolmanager = PoolManager(
            num_pools=connections, maxsize=maxsize, block=block, **pool_kwargs
        )


def clear_proxy_env() -> dict[str, str]:
    saved = {}
    for key in PROXY_ENV_KEYS:
        if key in os.environ:
            saved[key] = os.environ.pop(key)
    os.environ["NO_PROXY"] = "*"
    os.environ["no_proxy"] = "*"
    return saved


def restore_proxy_env(saved: dict[str, str]) -> None:
    os.environ.pop("NO_PROXY", None)
    os.environ.pop("no_proxy", None)
    os.environ.update(saved)


def decode_windows_text(raw: bytes) -> str:
    """ipconfig/netsh on Chinese Windows typically emit GBK, not UTF-8."""
    if not raw:
        return ""
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig")
    encodings: list[str] = []
    for enc in (
        locale.getpreferredencoding(False),
        "mbcs",
        "gb18030",
        "gbk",
        "cp936",
        "utf-8",
        "latin1",
    ):
        if enc and enc not in encodings:
            encodings.append(enc)
    for enc in encodings:
        try:
            return raw.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return raw.decode("utf-8", errors="replace")


def _run(cmd: list[str], timeout: int = 8) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    raw = (proc.stdout or b"") + b"\n" + (proc.stderr or b"")
    if sys.platform == "win32":
        return decode_windows_text(raw)
    return raw.decode("utf-8", errors="replace")


def _is_tun_name(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in TUN_NAME_HINTS)


def _is_ipv4(ip: str) -> bool:
    return bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip or ""))


def _usable_ipv4(ip: str) -> bool:
    if not _is_ipv4(ip):
        return False
    if ip.startswith("127.") or ip.startswith("169.254."):
        return False
    if ip.startswith(FAKE_IP_PREFIXES):
        return False
    return True


def _merge_nics(existing: list[NicInfo], extra: list[NicInfo]) -> list[NicInfo]:
    seen: set[tuple[str, str]] = {(n.name, n.ip) for n in existing}
    out = list(existing)
    for nic in extra:
        key = (nic.name, nic.ip)
        if key in seen:
            continue
        seen.add(key)
        out.append(nic)
    return out


def _parse_linux_addrs() -> list[NicInfo]:
    nics: list[NicInfo] = []
    out = _run(["ip", "-o", "-4", "addr", "show"])
    for line in out.splitlines():
        match = re.search(r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)", line)
        if match:
            nics.append(
                NicInfo(name=match.group(1), ip=match.group(2), is_tun=_is_tun_name(match.group(1)))
            )
    if nics:
        return nics
    out = _run(["ifconfig", "-a"])
    current = "unknown"
    for line in out.splitlines():
        head = re.match(r"^([A-Za-z0-9._-]+):", line)
        if head:
            current = head.group(1)
        match = re.search(r"inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)", line)
        if match and not match.group(1).startswith("127."):
            nics.append(NicInfo(name=current, ip=match.group(1), is_tun=_is_tun_name(current)))
    return nics


def parse_ipconfig(text: str) -> list[NicInfo]:
    nics: list[NicInfo] = []
    current = ""
    for line in text.splitlines():
        raw = line.rstrip("\r")
        header = _IPCONFIG_HEADER.match(raw.strip())
        if header:
            current = header.group(1).strip()
            continue
        stripped = raw.strip()
        if stripped.endswith(":") and ("adapter" in stripped.lower() or "适配器" in stripped or "適配器" in stripped):
            current = stripped[:-1]
            current = re.sub(
                r"^(?:Ethernet adapter|Wireless LAN adapter|PPP adapter|"
                r"以太网适配器|无线局域网适配器|無線區域網路適配器|以太網適配器|未知适配器)\s+",
                "",
                current,
                flags=re.I,
            ).strip()
            continue
        if not current:
            continue
        if "IPv4" in stripped or "IP Address" in stripped or "IPv4 地址" in stripped or "IPv4 位址" in stripped:
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)", stripped)
            if match:
                ip = match.group(1)
                if _usable_ipv4(ip) or ip.startswith("169.254."):
                    if not ip.startswith("127."):
                        nics.append(NicInfo(name=current, ip=ip, is_tun=_is_tun_name(current)))
    return nics


def _nics_from_ipconfig() -> list[NicInfo]:
    return parse_ipconfig(_run(["ipconfig"]))


def _nics_from_powershell() -> list[NicInfo]:
    """Emit UTF-8 names as base64 so GBK consoles cannot scramble 以太网."""
    ps = (
        "Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
        "ForEach-Object { "
        "$b=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($_.InterfaceAlias)); "
        "Write-Output ($b + '|' + $_.IPAddress) "
        "}"
    )
    out = _run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            ps,
        ],
        timeout=12,
    )
    nics: list[NicInfo] = []
    for line in out.splitlines():
        line = line.strip()
        if "|" not in line:
            continue
        encoded, ip = line.split("|", 1)
        ip = ip.strip()
        if not _is_ipv4(ip):
            continue
        name = encoded.strip()
        try:
            name = base64.b64decode(encoded.strip()).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            pass
        if not name:
            continue
        nics.append(NicInfo(name=name, ip=ip, is_tun=_is_tun_name(name)))
    return nics


def windows_adapter_status() -> list[tuple[str, str]]:
    """Return (name, status) for Windows adapters, including those without IPv4."""
    if sys.platform != "win32":
        return []
    ps = (
        "Get-NetAdapter -ErrorAction SilentlyContinue | "
        "ForEach-Object { "
        "$b=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($_.Name)); "
        "Write-Output ($b + '|' + $_.Status) "
        "}"
    )
    out = _run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
        timeout=12,
    )
    rows: list[tuple[str, str]] = []
    for line in out.splitlines():
        line = line.strip()
        if "|" not in line:
            continue
        encoded, status = line.split("|", 1)
        try:
            name = base64.b64decode(encoded.strip()).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            name = encoded.strip()
        if name:
            rows.append((name, status.strip()))
    if rows:
        return rows
    text = _run(["netsh", "interface", "show", "interface"])
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        admin, state = parts[0], parts[1]
        if admin not in ("Enabled", "Disabled", "已启用", "已停用", "启用", "禁用"):
            continue
        rows.append((" ".join(parts[3:]), state))
    return rows


def _nics_from_hostname() -> list[NicInfo]:
    found: list[NicInfo] = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip and _usable_ipv4(ip):
                found.append(NicInfo(name="unknown", ip=ip, is_tun=False))
    except socket.gaierror:
        pass
    return found


def list_nics() -> list[NicInfo]:
    if sys.platform == "win32":
        nics = _merge_nics(_nics_from_powershell(), _nics_from_ipconfig())
    else:
        nics = _parse_linux_addrs()
    if not nics:
        nics = _nics_from_hostname()
    unique: list[NicInfo] = []
    seen: set[tuple[str, str]] = set()
    for nic in nics:
        if nic.ip.startswith("127."):
            continue
        key = (nic.name, nic.ip)
        if key in seen:
            continue
        seen.add(key)
        unique.append(nic)
    return unique


def is_campus_ip(ip: str, prefixes: list[str]) -> bool:
    if ip.startswith(FAKE_IP_PREFIXES) or ip.startswith("127."):
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for prefix in prefixes:
        try:
            if "/" in prefix:
                if addr in ipaddress.ip_network(prefix, strict=False):
                    return True
            elif ip.startswith(prefix):
                return True
        except ValueError:
            continue
    return False


def _is_skipped_nic(name: str) -> bool:
    lowered = name.lower()
    if lowered in {"lo", "lo0"}:
        return True
    return any(hint in lowered for hint in SKIP_NIC_HINTS)


def _nic_score(nic: NicInfo) -> int:
    if nic.is_tun or _is_skipped_nic(nic.name):
        return -1
    lowered = nic.name.lower()
    if any(hint in lowered for hint in PHYSICAL_NIC_HINTS):
        return 2
    return 1


def format_nic_overview(nics: list[NicInfo] | None = None) -> str:
    nics = list_nics() if nics is None else nics
    bits: list[str] = []
    for nic in nics:
        tags: list[str] = []
        if nic.is_tun:
            tags.append("TUN")
        if _is_skipped_nic(nic.name):
            tags.append("虚拟")
        elif _nic_score(nic) >= 2:
            tags.append("物理")
        if nic.ip.startswith("169.254."):
            tags.append("未拿到DHCP")
        tag = f"[{'/'.join(tags)}]" if tags else ""
        bits.append(f"{nic.name}={nic.ip}{tag}")
    for name, status in windows_adapter_status():
        already = any(nic.name == name for nic in nics)
        if already:
            continue
        tag = "虚拟" if _is_skipped_nic(name) else "无IPv4"
        bits.append(f"{name}={status}[{tag}]")
    return "; ".join(bits) if bits else "没有解析到任何网卡"


def pick_campus_nic(cfg: AppConfig) -> NicInfo | None:
    nics = [nic for nic in list_nics() if _usable_ipv4(nic.ip)]
    hint = (cfg.campus_nic_name or "").strip().lower()
    if hint:
        named = [nic for nic in nics if hint in nic.name.lower() and _nic_score(nic) >= 0]
        if named:
            named.sort(
                key=lambda nic: (
                    -int(is_campus_ip(nic.ip, cfg.campus_ip_prefixes)),
                    -_nic_score(nic),
                    nic.ip,
                )
            )
            return named[0]
        log.debug("config campus_nic_name=%s 没有匹配到带 IPv4 的网卡", cfg.campus_nic_name)

    ignored = [
        nic
        for nic in list_nics()
        if is_campus_ip(nic.ip, cfg.campus_ip_prefixes) and _is_skipped_nic(nic.name)
    ]
    if ignored:
        log.debug(
            "已忽略虚拟网卡: %s",
            ", ".join(f"{nic.name}({nic.ip})" for nic in ignored),
        )

    candidates = [
        nic
        for nic in nics
        if is_campus_ip(nic.ip, cfg.campus_ip_prefixes) and _nic_score(nic) >= 0
    ]
    if candidates:
        candidates.sort(key=lambda nic: (-_nic_score(nic), nic.ip))
        return candidates[0]

    # Campus Ethernet may use a public (non-RFC1918) address.
    physical = [nic for nic in nics if _nic_score(nic) >= 2]
    if not physical:
        physical = [nic for nic in nics if _nic_score(nic) >= 0]
    if not physical:
        return None
    ethernet = [
        nic
        for nic in physical
        if any(h in nic.name.lower() for h in ("以太网", "ethernet", "本地连接", "本地連線", "eth"))
        and "wi-fi" not in nic.name.lower()
        and "wifi" not in nic.name.lower()
        and "无线" not in nic.name
    ]
    pool = ethernet or physical
    pool.sort(key=lambda nic: (-_nic_score(nic), nic.ip))
    chosen = pool[0]
    log.debug(
        "未匹配内网前缀，回退选用物理网卡 %s (%s)",
        chosen.name,
        chosen.ip,
    )
    return chosen


def wait_for_campus_ipv4(cfg: AppConfig, timeout: float = 12.0) -> NicInfo | None:
    deadline = time.time() + timeout
    nic = pick_campus_nic(cfg)
    if nic:
        return nic
    while time.time() < deadline:
        time.sleep(1.0)
        nic = pick_campus_nic(cfg)
        if nic:
            return nic
    return pick_campus_nic(cfg)


def campus_link_up_without_ip(cfg: AppConfig) -> str:
    """Adapter is Connected/Up but still has no usable IPv4 (DHCP lag)."""
    nics = list_nics()
    nics_with_ip = {nic.name for nic in nics if _usable_ipv4(nic.ip)}
    hint = (cfg.campus_nic_name or "").strip().lower()
    for nic in nics:
        if not nic.ip.startswith("169.254."):
            continue
        if _is_skipped_nic(nic.name) or _is_tun_name(nic.name) or _nic_score(nic) < 0:
            continue
        if hint and hint not in nic.name.lower():
            continue
        if hint or _nic_score(nic) >= 2:
            return nic.name
    for name, status in windows_adapter_status():
        if _is_skipped_nic(name) or _is_tun_name(name):
            continue
        if name in nics_with_ip:
            continue
        connected = status.lower() in {"up", "connected", "已连接", "已連線"}
        if not connected:
            continue
        if hint and hint not in name.lower():
            continue
        if hint or any(h in name.lower() for h in PHYSICAL_NIC_HINTS):
            return name
    return ""


def list_tun_nics() -> list[NicInfo]:
    return [nic for nic in list_nics() if nic.is_tun]


def nic_fingerprint(cfg: AppConfig) -> str:
    campus = pick_campus_nic(cfg)
    physical = [nic for nic in list_nics() if _nic_score(nic) >= 0]
    bits = [f"{nic.name}:{nic.ip}" for nic in sorted(physical, key=lambda item: item.name)]
    campus_ip = campus.ip if campus else "-"
    return f"{campus_ip}|{','.join(bits)}"


def describe_connectivity(bound_online: bool, unbound_online: bool, tun_present: bool) -> str:
    if unbound_online:
        return "系统默认路由已能上网"
    if bound_online and tun_present:
        return "校园网本身已通，但默认路由被梯子 TUN 截走（拔插网线后很常见）"
    if bound_online:
        return "校园网卡能出网，但系统默认路由不通"
    return "尚未认证或网络未就绪"


def make_unbound_session(cfg: AppConfig) -> requests.Session:
    """Default-route session: what the browser/VPN actually use."""
    return make_session(cfg, None)


def make_session(cfg: AppConfig, source_ip: str | None = None) -> requests.Session:
    session = requests.Session()
    session.trust_env = not cfg.bypass_proxy
    if cfg.bypass_proxy:
        session.proxies = {"http": "", "https": ""}
        session.trust_env = False
    session.headers.update({"User-Agent": UA, "Accept": "*/*"})
    session.verify = False
    retry = Retry(total=1, backoff_factor=0.2, status_forcelist=(502, 503, 504))
    adapter: HTTPAdapter
    if source_ip and cfg.bind_campus_nic:
        adapter = SourceAddressAdapter(source_ip, max_retries=retry)
    else:
        adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def _snippet(text: str, limit: int = 180) -> str:
    compact = re.sub(r"\s+", " ", text or "").strip()
    return compact[:limit]


def host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def is_detect_host(url: str) -> bool:
    return host_of(url) in DETECT_HOSTS


def is_gateway_host(url: str) -> bool:
    host = host_of(url)
    if not host:
        return False
    if host in GATEWAY_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def looks_like_portal(url: str, body: str) -> bool:
    if is_detect_host(url):
        return False
    blob = f"{url}\n{body}".lower()
    keywords = (
        "srun_portal",
        "get_challenge",
        "/eportal",
        "interface.do",
        "drcom",
        "0mkkey",
        "wlanuserip",
        "ac_id=",
        "认证",
        "校园网",
        "上网认证",
        "连接网络",
        "请登录",
        "欢迎使用校园",
        "web auth",
    )
    return any(k in blob for k in keywords)


def check_online(session: requests.Session, timeout: float = 5.0) -> OnlineStatus:
    last = OnlineStatus(online=False, reason="所有探测地址都失败")
    for url, expected in DETECT_URLS:
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=True)
        except requests.RequestException as exc:
            last = OnlineStatus(online=False, reason=f"{url} 请求失败: {exc}")
            continue
        body = resp.text or ""
        final = str(resp.url)
        snippet = _snippet(body)
        if looks_like_portal(final, body) or (
            host_of(final) not in {"", host_of(url)} and is_gateway_host(final)
        ):
            return OnlineStatus(
                online=False,
                reason="探测被重定向到认证页",
                final_url=final,
                status_code=resp.status_code,
                body_snippet=snippet,
            )
        if resp.status_code == 204:
            return OnlineStatus(online=True, reason=f"{url} 返回 204", final_url=final, status_code=204)
        if expected and expected.lower() in body.lower() and resp.status_code == 200:
            return OnlineStatus(
                online=True,
                reason=f"{url} 返回预期内容",
                final_url=final,
                status_code=200,
                body_snippet=snippet,
            )
        if resp.status_code == 200 and not looks_like_portal(final, body) and len(body) < 400:
            if is_detect_host(final) or (host_of(final) and "login" not in host_of(final)):
                return OnlineStatus(
                    online=True,
                    reason=f"{url} 返回 {resp.status_code}",
                    final_url=final,
                    status_code=resp.status_code,
                    body_snippet=snippet,
                )
        last = OnlineStatus(
            online=False,
            reason=f"{url} 状态 {resp.status_code}",
            final_url=final,
            status_code=resp.status_code,
            body_snippet=snippet,
        )
    return last


def windows_system_proxy() -> str:
    if sys.platform != "win32":
        return ""
    out = _run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            r"(Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' "
            r"| Select-Object ProxyEnable,ProxyServer | Format-List | Out-String)",
        ]
    )
    return out.strip()


def flush_dns() -> None:
    if sys.platform == "win32":
        _run(["ipconfig", "/flushdns"], timeout=10)
    else:
        _run(["resolvectl", "flush-caches"], timeout=5)
