from __future__ import annotations

import json
import logging
import time
from urllib.parse import parse_qsl, urljoin, urlparse

import requests

from campus_connect.detect import extract_ac_id, extract_user_ip, parse_jsonp
from campus_connect.htmlutil import connect_links, fill_form, parse_html, pick_form
from campus_connect.models import AppConfig, LoginResult, PortalInfo
from campus_connect.srun_crypto import encode_info, hmac_md5, sha1_hex
from campus_connect.vpn import origin_of

log = logging.getLogger("campus_connect")

SRUN_OK = (
    "login_ok",
    "ok",
    "success",
    "ip_already_online_error",
    "already_online",
)


def _jsonp_callback() -> str:
    return f"jQuery{int(time.time() * 1000)}"


def login_srun(session: requests.Session, cfg: AppConfig, portal: PortalInfo) -> LoginResult:
    if not cfg.username:
        return LoginResult(ok=False, message="深澜认证需要学号/账号", backend="srun")
    base = origin_of(portal.url or cfg.portal_url)
    if not base:
        return LoginResult(ok=False, message="找不到深澜认证服务器地址", backend="srun")

    ip = portal.user_ip or extract_user_ip(portal.url, portal.html)
    ac_ids: list[str] = []
    for candidate in (
        cfg.srun_ac_id,
        portal.ac_id,
        extract_ac_id(portal.url, portal.html),
        "1",
        "2",
        "3",
        "4",
        "5",
    ):
        if candidate and candidate not in ac_ids:
            ac_ids.append(str(candidate))

    last_msg = "深澜登录失败"
    for ac_id in ac_ids:
        result = _srun_once(session, cfg, base, ip, ac_id)
        if result.ok:
            return result
        last_msg = result.message
        if "acid" not in last_msg.lower() and "ac_id" not in last_msg.lower():
            return result
        log.info("ac_id=%s 未成功，尝试下一个: %s", ac_id, last_msg)
    return LoginResult(ok=False, message=last_msg, backend="srun", portal_url=base)


def _srun_once(
    session: requests.Session,
    cfg: AppConfig,
    base: str,
    ip: str,
    ac_id: str,
) -> LoginResult:
    callback = _jsonp_callback()
    challenge_url = urljoin(base + "/", "cgi-bin/get_challenge")
    try:
        chal = session.get(
            challenge_url,
            params={"callback": callback, "username": cfg.username, "ip": ip or ""},
            timeout=8,
        )
    except requests.RequestException as exc:
        return LoginResult(ok=False, message=f"get_challenge 失败: {exc}", backend="srun")

    data = parse_jsonp(chal.text)
    token = str(data.get("challenge") or "")
    ip = str(data.get("client_ip") or data.get("online_ip") or ip)
    if not token:
        return LoginResult(
            ok=False,
            message=f"未拿到 challenge: {chal.text[:180]}",
            backend="srun",
            portal_url=base,
        )
    if not ip:
        return LoginResult(ok=False, message="未拿到校园网 IP", backend="srun", portal_url=base)

    info_obj = {
        "username": cfg.username,
        "password": cfg.password,
        "ip": ip,
        "acid": str(ac_id),
        "enc_ver": "srun_bx1",
    }
    info = encode_info(json.dumps(info_obj, separators=(",", ":"), ensure_ascii=False), token)
    n_const, vtype = "200", "1"
    hmd5 = hmac_md5(cfg.password, token)
    chkstr = token + token.join(
        [cfg.username, hmd5, str(ac_id), ip, n_const, vtype, info]
    )
    params = {
        "callback": _jsonp_callback(),
        "action": "login",
        "username": cfg.username,
        "password": "{MD5}" + hmd5,
        "os": "Windows 10",
        "name": "Windows",
        "double_stack": "1" if cfg.srun_double_stack else "0",
        "chksum": sha1_hex(chkstr),
        "info": info,
        "ac_id": ac_id,
        "ip": ip,
        "n": n_const,
        "type": vtype,
        "_": int(time.time() * 1000),
    }
    try:
        resp = session.get(urljoin(base + "/", "cgi-bin/srun_portal"), params=params, timeout=8)
    except requests.RequestException as exc:
        return LoginResult(ok=False, message=f"srun_portal 失败: {exc}", backend="srun")
    payload = parse_jsonp(resp.text)
    error = str(payload.get("error") or "")
    suc = str(payload.get("suc_msg") or payload.get("error_msg") or "")
    ecode = payload.get("ecode")
    combined = f"{error} {suc} {ecode}".lower()
    if (
        ecode == 0
        or error.lower() in SRUN_OK
        or suc.lower() in SRUN_OK
        or "already_online" in combined
        or "login_ok" in combined
    ):
        return LoginResult(
            ok=True,
            message=suc or error or "login_ok",
            backend="srun",
            portal_url=base,
            already_online="already" in combined,
        )
    return LoginResult(
        ok=False,
        message=suc or error or resp.text[:200] or "深澜返回失败",
        backend="srun",
        portal_url=base,
    )


def _ruijie_query(portal: PortalInfo) -> str:
    if portal.query:
        return portal.query
    parsed = urlparse(portal.url)
    if parsed.query:
        return parsed.query
    return ""


def _rsa_encrypt(message: str, exponent_hex: str, modulus_hex: str) -> str:
    exponent = int(exponent_hex, 16)
    modulus = int(modulus_hex, 16)
    data = int.from_bytes(message.encode("utf-8"), "big")
    cipher = pow(data, exponent, modulus)
    return format(cipher, "x")


def login_ruijie(session: requests.Session, cfg: AppConfig, portal: PortalInfo) -> LoginResult:
    if not cfg.username:
        return LoginResult(ok=False, message="锐捷认证需要账号", backend="ruijie")
    base = origin_of(portal.url or cfg.portal_url)
    query = _ruijie_query(portal)
    if not query:
        return LoginResult(ok=False, message="锐捷缺少 queryString，无法登录", backend="ruijie")

    page_url = urljoin(base + "/", "eportal/InterFace.do?method=pageInfo")
    login_url = urljoin(base + "/", "eportal/InterFace.do?method=login")
    password = cfg.password
    encrypt_flag = "false"
    try:
        page = session.post(page_url, data={"queryString": query}, timeout=8)
        info = page.json() if page.text else {}
    except (requests.RequestException, ValueError):
        info = {}
    exponent = str((info or {}).get("publicKeyExponent") or "")
    modulus = str((info or {}).get("publicKeyModulus") or "")
    if exponent and modulus:
        mac = str((info or {}).get("mac") or "")
        raw = f"{cfg.password}>{mac}" if mac else cfg.password
        try:
            password = _rsa_encrypt(raw, exponent, modulus)
            encrypt_flag = "true"
        except (ValueError, OverflowError):
            password = cfg.password
            encrypt_flag = "false"

    body = {
        "userId": cfg.username,
        "password": password,
        "service": cfg.ruijie_service,
        "queryString": query,
        "operatorPwd": "",
        "operatorUserId": "",
        "validcode": "",
        "passwordEncrypt": encrypt_flag,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Origin": base,
        "Referer": portal.url or base,
    }
    try:
        resp = session.post(login_url, data=body, headers=headers, timeout=8)
        payload = resp.json() if resp.text else {}
    except (requests.RequestException, ValueError) as exc:
        return LoginResult(ok=False, message=f"锐捷登录失败: {exc}", backend="ruijie")
    result = str((payload or {}).get("result") or "")
    message = str((payload or {}).get("message") or result or resp.text[:180])
    if result.lower() == "success" or "success" in message.lower():
        return LoginResult(ok=True, message=message or "success", backend="ruijie", portal_url=base)
    return LoginResult(ok=False, message=message or "锐捷返回失败", backend="ruijie", portal_url=base)


def login_drcom(session: requests.Session, cfg: AppConfig, portal: PortalInfo) -> LoginResult:
    if not cfg.username:
        return LoginResult(ok=False, message="DrCOM 认证需要账号", backend="drcom")
    base = origin_of(portal.url or cfg.portal_url)
    url = urljoin(base + "/", "drcom/login")
    params = {
        "callback": "dr1003",
        "DDDDD": cfg.username,
        "upass": cfg.password,
        "0MKKey": "123456",
        "R1": "0",
        "R2": "",
        "R3": "0",
        "R6": "0",
        "para": "00",
        "v6ip": "",
        "terminal_type": "1",
        "lang": "zh",
    }
    try:
        resp = session.get(url, params=params, timeout=8)
    except requests.RequestException as exc:
        return LoginResult(ok=False, message=f"DrCOM 请求失败: {exc}", backend="drcom")
    text = resp.text or ""
    data = parse_jsonp(text)
    result = data.get("result")
    if result in {1, "1"} or '"result":1' in text.replace(" ", ""):
        return LoginResult(
            ok=True,
            message=str(data.get("msg") or "DrCOM 登录成功"),
            backend="drcom",
            portal_url=base,
        )
    return LoginResult(
        ok=False,
        message=str(data.get("msg") or text[:180] or "DrCOM 失败"),
        backend="drcom",
        portal_url=base,
    )


def login_generic(session: requests.Session, cfg: AppConfig, portal: PortalInfo) -> LoginResult:
    url = portal.url or cfg.portal_url
    if not url:
        return LoginResult(ok=False, message="没有认证页可点", backend="generic")
    try:
        page = session.get(url, timeout=8)
    except requests.RequestException as exc:
        return LoginResult(ok=False, message=f"打开认证页失败: {exc}", backend="generic")
    html = page.text or portal.html
    parser = parse_html(html)
    form = pick_form(parser)
    if form:
        action = urljoin(str(page.url), form.get("action") or str(page.url))
        payload = fill_form(form, cfg.username, cfg.password)
        method = (form.get("method") or "GET").upper()
        try:
            if method == "GET":
                resp = session.get(action, params=payload, timeout=8)
            else:
                resp = session.post(action, data=payload, timeout=8)
        except requests.RequestException as exc:
            return LoginResult(ok=False, message=f"提交表单失败: {exc}", backend="generic")
        if resp.status_code < 400:
            return LoginResult(
                ok=True,
                message=f"已提交认证表单 ({resp.status_code})",
                backend="generic",
                portal_url=str(page.url),
            )
        return LoginResult(ok=False, message=f"表单返回 {resp.status_code}", backend="generic")

    for link in connect_links(parser, str(page.url)):
        try:
            resp = session.get(link, timeout=8)
        except requests.RequestException:
            continue
        if resp.status_code < 400:
            return LoginResult(
                ok=True,
                message=f"已访问连接链接 {link}",
                backend="generic",
                portal_url=str(page.url),
            )
    return LoginResult(ok=False, message="认证页上没有找到可提交的表单或连接按钮", backend="generic")


def login_custom(session: requests.Session, cfg: AppConfig, portal: PortalInfo) -> LoginResult:
    if not cfg.custom_url:
        return LoginResult(ok=False, message="custom.url 未配置", backend="custom")
    url = (
        cfg.custom_url.replace("{username}", cfg.username)
        .replace("{password}", cfg.password)
        .replace("{portal}", portal.url or "")
    )
    body = (cfg.custom_body or "").replace("{username}", cfg.username).replace(
        "{password}", cfg.password
    )
    method = (cfg.custom_method or "POST").upper()
    headers = dict(cfg.custom_headers or {})
    try:
        if method == "GET":
            resp = session.get(url, timeout=8, headers=headers)
        else:
            parsed = dict(parse_qsl(body, keep_blank_values=True)) if body else body
            if isinstance(parsed, dict) and parsed:
                resp = session.post(url, data=parsed, timeout=8, headers=headers)
            else:
                resp = session.post(url, data=body, timeout=8, headers=headers)
    except requests.RequestException as exc:
        return LoginResult(ok=False, message=f"自定义请求失败: {exc}", backend="custom")
    text = resp.text or ""
    needle = cfg.custom_success_contains
    ok = resp.status_code < 400 and (not needle or needle in text)
    return LoginResult(
        ok=ok,
        message=f"自定义请求 {resp.status_code}" + ("" if ok else f" {text[:160]}"),
        backend="custom",
        portal_url=url,
    )


BACKENDS = {
    "srun": login_srun,
    "ruijie": login_ruijie,
    "drcom": login_drcom,
    "generic": login_generic,
    "custom": login_custom,
}


def run_backend(name: str, session: requests.Session, cfg: AppConfig, portal: PortalInfo) -> LoginResult:
    func = BACKENDS.get(name)
    if func is None:
        return LoginResult(ok=False, message=f"未知认证类型: {name}", backend=name)
    return func(session, cfg, portal)
