from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin


class FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []
        self.links: list[tuple[str, str]] = []
        self._current: dict | None = None
        self._capture_link: str | None = None
        self._link_text: list[str] = []
        self.meta_refresh: str = ""
        self.js_locations: list[str] = []
        self.title = ""
        self._in_title = False
        self._in_button = False
        self._button_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        ad = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._current = {
                "action": ad.get("action", ""),
                "method": (ad.get("method") or "GET").upper(),
                "inputs": [],
                "submit_text": "",
            }
            self.forms.append(self._current)
        elif tag == "input" and self._current is not None:
            self._current["inputs"].append(
                {
                    "type": (ad.get("type") or "text").lower(),
                    "name": ad.get("name", ""),
                    "value": ad.get("value", ""),
                    "id": ad.get("id", ""),
                    "placeholder": ad.get("placeholder", ""),
                }
            )
            if (ad.get("type") or "").lower() in {"submit", "button"}:
                self._current["submit_text"] += ad.get("value", "")
        elif tag == "button" and self._current is not None:
            self._in_button = True
            self._button_text = []
            if ad.get("name"):
                self._current["inputs"].append(
                    {
                        "type": "submit",
                        "name": ad.get("name", ""),
                        "value": ad.get("value", ""),
                        "id": ad.get("id", ""),
                        "placeholder": "",
                    }
                )
        elif tag == "a":
            href = ad.get("href", "")
            if href:
                self._capture_link = href
                self._link_text = []
        elif tag == "meta":
            http_equiv = ad.get("http-equiv", "").lower()
            if http_equiv == "refresh":
                content = ad.get("content", "")
                match = re.search(r"url\s*=\s*([^\s;]+)", content, re.I)
                if match:
                    self.meta_refresh = match.group(1).strip("\"'")
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current = None
        elif tag == "a" and self._capture_link is not None:
            self.links.append((self._capture_link, "".join(self._link_text).strip()))
            self._capture_link = None
        elif tag == "title":
            self._in_title = False
        elif tag == "button":
            if self._current is not None:
                self._current["submit_text"] += "".join(self._button_text)
            self._in_button = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data
        if self._capture_link is not None:
            self._link_text.append(data)
        if self._in_button:
            self._button_text.append(data)
        for match in re.finditer(
            r"""(?:window|document|top|self|parent)?(?:\.location(?:\.href)?)?\s*=\s*['"]([^'"]+)['"]""",
            data,
        ):
            self.js_locations.append(match.group(1))
        for match in re.finditer(r"""location\.href\s*=\s*['"]([^'"]+)['"]""", data):
            self.js_locations.append(match.group(1))


CONNECT_WORDS = ("连接", "上网", "认证", "登录", "一键", "同意", "connect", "login", "auth")


def parse_html(html: str) -> FormParser:
    parser = FormParser()
    try:
        parser.feed(html or "")
    except Exception:
        pass
    return parser


def _score_form(form: dict) -> int:
    blob = (form.get("submit_text") or "") + " " + form.get("action", "")
    score = 0
    for word in CONNECT_WORDS:
        if word.lower() in blob.lower():
            score += 5
    names = " ".join(i.get("name", "") for i in form.get("inputs", []))
    if re.search(r"user|uid|account|pass|pwd", names, re.I):
        score += 3
    if form.get("inputs"):
        score += 1
    return score


def fill_form(
    form: dict,
    username: str,
    password: str,
) -> dict[str, str]:
    data: dict[str, str] = {}
    user_assigned = False
    pass_assigned = False
    for item in form.get("inputs", []):
        name = item.get("name") or ""
        if not name:
            continue
        typ = item.get("type") or "text"
        value = item.get("value") or ""
        key = f"{name} {item.get('id','')} {item.get('placeholder','')}".lower()
        if typ in {"submit", "button", "image"}:
            data[name] = value or "登录"
            continue
        if typ in {"checkbox", "radio"}:
            data[name] = value or "on"
            continue
        if typ == "hidden":
            data[name] = value
            continue
        if (typ == "password" or re.search(r"pass|pwd", key)) and not pass_assigned:
            data[name] = password
            pass_assigned = True
            continue
        if re.search(r"user|uid|account|login|学号|账号", key) and not user_assigned:
            data[name] = username
            user_assigned = True
            continue
        data[name] = value
    return data


def pick_form(parser: FormParser) -> dict | None:
    if not parser.forms:
        return None
    return max(parser.forms, key=_score_form)


def connect_links(parser: FormParser, base_url: str) -> list[str]:
    urls: list[str] = []
    for href, text in parser.links:
        blob = f"{href} {text}".lower()
        if any(word.lower() in blob for word in CONNECT_WORDS):
            urls.append(urljoin(base_url, href))
    for loc in parser.js_locations + ([parser.meta_refresh] if parser.meta_refresh else []):
        if loc and not loc.lower().startswith("javascript:"):
            urls.append(urljoin(base_url, loc))
    # unique preserve order
    seen = set()
    out = []
    for url in urls:
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out
