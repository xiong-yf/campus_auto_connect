from __future__ import annotations

import hashlib
import hmac
import math


_PADCHAR = "="
_ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"


def hmac_md5(password: str, token: str) -> str:
    return hmac.new(token.encode(), password.encode(), hashlib.md5).hexdigest()


def sha1_hex(value: str) -> str:
    return hashlib.sha1(value.encode()).hexdigest()


def _getbyte(s: str, i: int) -> int:
    x = ord(s[i])
    if x > 255:
        raise ValueError("srun base64 input must be latin-1")
    return x


def srun_base64(s: str) -> str:
    """Custom base64 used by 深澜 srun_bx1."""
    if not s:
        return s
    x: list[str] = []
    imax = len(s) - len(s) % 3
    for i in range(0, imax, 3):
        b10 = (_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8) | _getbyte(s, i + 2)
        x.append(_ALPHA[(b10 >> 18)])
        x.append(_ALPHA[(b10 >> 12) & 63])
        x.append(_ALPHA[(b10 >> 6) & 63])
        x.append(_ALPHA[b10 & 63])
    i = imax
    if len(s) - imax == 1:
        b10 = _getbyte(s, i) << 16
        x.append(_ALPHA[(b10 >> 18)] + _ALPHA[(b10 >> 12) & 63] + _PADCHAR + _PADCHAR)
    elif len(s) - imax == 2:
        b10 = (_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8)
        x.append(
            _ALPHA[(b10 >> 18)]
            + _ALPHA[(b10 >> 12) & 63]
            + _ALPHA[(b10 >> 6) & 63]
            + _PADCHAR
        )
    return "".join(x)


def _ordat(msg: str, idx: int) -> int:
    return ord(msg[idx]) if len(msg) > idx else 0


def _sencode(msg: str, key: bool) -> list[int]:
    length = len(msg)
    pwd = []
    for i in range(0, length, 4):
        pwd.append(
            _ordat(msg, i)
            | _ordat(msg, i + 1) << 8
            | _ordat(msg, i + 2) << 16
            | _ordat(msg, i + 3) << 24
        )
    if key:
        pwd.append(length)
    return pwd


def _lencode(msg: list[int], key: bool) -> str:
    length = len(msg)
    ll = (length - 1) << 2
    if key:
        m = msg[length - 1]
        if m < ll - 3 or m > ll:
            return ""
        ll = m
    for i in range(length):
        msg[i] = (
            chr(msg[i] & 0xFF)
            + chr(msg[i] >> 8 & 0xFF)
            + chr(msg[i] >> 16 & 0xFF)
            + chr(msg[i] >> 24 & 0xFF)
        )
    joined = "".join(msg)
    return joined[:ll] if key else joined


def xencode(msg: str, key: str) -> str:
    """XXTEA-like encoder used by 深澜 (srun_bx1)."""
    if msg == "":
        return ""
    pwd = _sencode(msg, True)
    pwdk = _sencode(key, False)
    if len(pwdk) < 4:
        pwdk.extend([0] * (4 - len(pwdk)))
    n = len(pwd) - 1
    z = pwd[n]
    y = pwd[0]
    c = 0x9E3779B9
    q = int(math.floor(6 + 52 / (n + 1)))
    d = 0
    while q > 0:
        d = (d + c) & 0xFFFFFFFF
        e = (d >> 2) & 3
        p = 0
        while p < n:
            y = pwd[p + 1]
            m = (z >> 5) ^ (y << 2)
            m = m + (((y >> 3) ^ (z << 4)) ^ (d ^ y))
            m = m + (pwdk[(p & 3) ^ e] ^ z)
            pwd[p] = (pwd[p] + m) & 0xFFFFFFFF
            z = pwd[p]
            p += 1
        y = pwd[0]
        m = (z >> 5) ^ (y << 2)
        m = m + (((y >> 3) ^ (z << 4)) ^ (d ^ y))
        m = m + (pwdk[(p & 3) ^ e] ^ z)
        pwd[n] = (pwd[n] + m) & 0xFFFFFFFF
        z = pwd[n]
        q -= 1
    return _lencode(pwd, False)


def encode_info(payload: str, token: str) -> str:
    return "{SRBX1}" + srun_base64(xencode(payload, token))
