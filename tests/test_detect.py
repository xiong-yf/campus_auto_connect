from __future__ import annotations

import unittest

from campus_connect.detect import extract_ac_id, extract_user_ip, guess_backend, parse_jsonp
from campus_connect.htmlutil import connect_links, fill_form, parse_html, pick_form
from campus_connect.netutil import describe_connectivity, is_campus_ip, is_detect_host, is_gateway_host, looks_like_portal


class DetectTests(unittest.TestCase):
    def test_guess_srun(self) -> None:
        self.assertEqual(guess_backend("http://10.0.0.55/srun_portal_pc?ac_id=1", ""), "srun")

    def test_detect_host_is_not_portal(self) -> None:
        url = "http://detectportal.firefox.com/canonical.html"
        self.assertTrue(is_detect_host(url))
        self.assertFalse(looks_like_portal(url, "success"))
        self.assertTrue(looks_like_portal("http://10.0.0.55/srun_portal_pc?ac_id=1", ""))

    def test_campus_ip_cidr(self) -> None:
        prefixes = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        self.assertTrue(is_campus_ip("10.8.1.2", prefixes))
        self.assertTrue(is_campus_ip("172.30.0.2", prefixes))
        self.assertFalse(is_campus_ip("198.18.0.1", prefixes))
        self.assertFalse(is_campus_ip("8.8.8.8", prefixes))
        self.assertTrue(is_campus_ip("10.1.1.1", ["10."]))

    def test_gateway_host(self) -> None:
        self.assertTrue(is_gateway_host("http://10.0.0.55/srun_portal_pc"))
        self.assertTrue(is_gateway_host("http://123.123.123.123/"))
        self.assertFalse(is_gateway_host("https://one.one.one.one/"))

    def test_describe_connectivity(self) -> None:
        self.assertIn("已能上网", describe_connectivity(True, True, True))
        self.assertIn("TUN", describe_connectivity(True, False, True))
        self.assertIn("尚未认证", describe_connectivity(False, False, False))

    def test_guess_ruijie(self) -> None:
        self.assertEqual(
            guess_backend("http://10.0.0.1:801/eportal/index.jsp?wlanuserip=10.1.1.1", ""),
            "ruijie",
        )

    def test_guess_drcom(self) -> None:
        self.assertEqual(guess_backend("http://172.30.0.1/a70.htm", "0MKKey"), "drcom")

    def test_jsonp(self) -> None:
        data = parse_jsonp('jQuery123({"error":"ok","challenge":"abc"})')
        self.assertEqual(data["challenge"], "abc")

    def test_extractors(self) -> None:
        url = "http://gw/srun_portal_pc?ac_id=12&ip=10.8.1.2"
        self.assertEqual(extract_ac_id(url, ""), "12")
        self.assertEqual(extract_user_ip(url, ""), "10.8.1.2")
        html = 'var ac_id = "3"; ip : "10.9.9.9"'
        self.assertEqual(extract_ac_id("http://gw/", html), "3")


class HtmlTests(unittest.TestCase):
    def test_click_form(self) -> None:
        html = """
        <html><title>校园网</title>
        <form action="/connect" method="post">
          <input type="hidden" name="token" value="abc">
          <input type="submit" value="连接网络">
        </form>
        </html>
        """
        parser = parse_html(html)
        form = pick_form(parser)
        self.assertIsNotNone(form)
        data = fill_form(form, "", "")
        self.assertEqual(data["token"], "abc")

    def test_login_fields(self) -> None:
        html = """
        <form method="post" action="/login">
          <input name="username" placeholder="学号">
          <input name="password" type="password">
          <button type="submit">登录</button>
        </form>
        """
        form = pick_form(parse_html(html))
        data = fill_form(form, "u1", "p1")
        self.assertEqual(data["username"], "u1")
        self.assertEqual(data["password"], "p1")

    def test_connect_link(self) -> None:
        html = '<a href="/go">点击连接</a>'
        urls = connect_links(parse_html(html), "http://portal.local/")
        self.assertEqual(urls[0], "http://portal.local/go")


if __name__ == "__main__":
    unittest.main()
