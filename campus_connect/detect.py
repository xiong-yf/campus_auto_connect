from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, urljoin, urlparse

import requests

from campus_connect.htmlutil import parse_html
from campus_connect.models import AppConfig, PortalInfo
from campus_connect.netutil import (
    COMMON_PORTAL_HINTS,
    DETECT_URLS,
    host_of,
    is_detect_host,
    is_gateway_host,
    looks_like_portal,
)


def parse_jsonp(text: str) -> dict:
    text = (text or "").strip()
    if not text:
        return {}
    if text.startswith("{") or text.startswith("["):
        try:
            data = json.loads(text)
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            return {}
    match = re.search(r"^[^(]*\((.*)\)\s*;?\s*$", text, re.S)
    if match:
        try:
            data = json.loads(match.group(1))
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def guess_backend(url: str, html: str) -> str:
    blob = f"{url}\n{html}".lower()
    if any(k in blob for k in ("srun_portal", "get_challenge", "cgi-bin/srun", "srun_bx1")):
        return "srun"
    if any(k in blob for k in ("/eportal", "interface.do", "wlanuserip", "wlanacname")):
        return "ruijie"
    if any(k in blob for k in ("drcom", "0mkkey", "a70.htm", "ddddd")):
        return "drcom"
    return "generic"


def _first_query(url: str, *names: str) -> str:
    qs = parse_qs(urlparse(url).query)
    for name in names:
        values = qs.get(name)
        if values and values[0]:
            return values[0]
    return ""


def extract_ac_id(url: str, html: str) -> str:
    value = _first_query(url, "ac_id", "acId", "ac-id")
    if value:
        return value
    match = re.search(r"""ac_id\s*[:=]\s*['"]?(\d+)""", html or "", re.I)
    return match.group(1) if match else ""


def extract_user_ip(url: str, html: str) -> str:
    value = _first_query(url, "ip", "user_ip", "wlanuserip", "UserIP", "userip")
    if value:
        return value
    match = re.search(
        r"""(?:user_ip|wlanuserip|ip)\s*[:=]\s*['"](\d+\.\d+\.\d+\.\d+)['"]""",
        html or "",
        re.I,
    )
    return match.group(1) if match else ""


def _portal_from_response(resp: requests.Response, original_url: str, note: str) -> PortalInfo | None:
    final = str(resp.url)
    html = resp.text or ""
    if is_detect_host(final):
        return None
    hijacked = host_of(final) not in {"", host_of(original_url)} and is_gateway_host(final)
    if not looks_like_portal(final, html) and not hijacked:
        return None
    backend = guess_backend(final, html)
    query = urlparse(final).query
    if not query and "wlanuserip" in html:
        match = re.search(r"(wlanuserip=[^'\"\s<]+)", html, re.I)
        query = match.group(1) if match else ""
    return PortalInfo(
        found=True,
        url=final,
        backend=backend,
        html=html,
        query=query,
        ac_id=extract_ac_id(final, html),
        user_ip=extract_user_ip(final, html),
        notes=[note],
    )


def _try_get(session: requests.Session, url: str, timeout: float = 6.0) -> requests.Response | None:
    try:
        return session.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        return None


def detect_portal(session: requests.Session, cfg: AppConfig) -> PortalInfo:
    notes: list[str] = []
    if cfg.portal_url:
        resp = _try_get(session, cfg.portal_url)
        if resp is not None:
            info = _portal_from_response(resp, cfg.portal_url, f"使用配置的 portal_url: {cfg.portal_url}")
            if info:
                return info
            guessed = guess_backend(str(resp.url), resp.text or "")
            return PortalInfo(
                found=True,
                url=str(resp.url),
                backend=guessed,
                html=resp.text or "",
                query=urlparse(str(resp.url)).query,
                ac_id=extract_ac_id(str(resp.url), resp.text or ""),
                user_ip=extract_user_ip(str(resp.url), resp.text or ""),
                notes=[f"打开了配置的认证页: {cfg.portal_url}"],
            )
        notes.append(f"配置的 portal_url 无法访问: {cfg.portal_url}")

    clean_hits = 0
    for url, _expected in DETECT_URLS:
        resp = _try_get(session, url)
        if resp is None:
            notes.append(f"探测失败 {url}")
            continue
        info = _portal_from_response(resp, url, f"由 {url} 跳转")
        if info:
            info.notes.extend(notes)
            return info
        notes.append(f"{url} -> {resp.status_code} {resp.url}")
        if is_detect_host(str(resp.url)):
            clean_hits += 1

    if clean_hits >= 2:
        notes.append("公网探测正常，没有认证页跳转")
        return PortalInfo(found=False, notes=notes)

    for url in COMMON_PORTAL_HINTS:
        resp = _try_get(session, url, timeout=2.0)
        if resp is None:
            continue
        info = _portal_from_response(resp, url, f"扫描常见网关 {url}")
        if info:
            info.notes.extend(notes)
            return info
        html = resp.text or ""
        parser = parse_html(html)
        if parser.meta_refresh:
            jumped = _try_get(session, urljoin(str(resp.url), parser.meta_refresh))
            if jumped is not None:
                info = _portal_from_response(jumped, url, f"{url} meta-refresh")
                if info:
                    info.notes.extend(notes)
                    return info

    return PortalInfo(found=False, notes=notes or ["没有探测到认证页"])
