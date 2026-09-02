from __future__ import annotations

import unittest
from unittest.mock import patch

from campus_connect.models import AppConfig, NicInfo
from campus_connect.netutil import (
    COMMON_PORTAL_HINTS,
    campus_link_up_without_ip,
    decode_windows_text,
    parse_ipconfig,
    pick_campus_nic,
)


CHINESE_IPCONFIG = """
Windows IP 配置

以太网适配器 以太网:

   连接特定的 DNS 后缀 . . . . . . . :
   本地链接 IPv6 地址. . . . . . . . : fe80::1
   IPv4 地址 . . . . . . . . . . . . : 10.8.1.2
   子网掩码  . . . . . . . . . . . . : 255.255.255.0
   默认网关. . . . . . . . . . . . . : 10.8.1.1

以太网适配器 VMware Network Adapter VMnet8:

   连接特定的 DNS 后缀 . . . . . . . :
   IPv4 地址 . . . . . . . . . . . . : 192.168.242.1
   子网掩码  . . . . . . . . . . . . : 255.255.255.0

以太网适配器 VMware Network Adapter VMnet1:

   IPv4 地址 . . . . . . . . . . . . : 192.168.44.1
   子网掩码  . . . . . . . . . . . . : 255.255.255.0

无线局域网适配器 WLAN:

   媒体状态  . . . . . . . . . . . . : 媒体已断开连接
"""

PUBLIC_IP_IPCONFIG = """
以太网适配器 以太网:

   IPv4 地址 . . . . . . . . . . . . : 203.0.113.10
   子网掩码  . . . . . . . . . . . . : 255.255.255.0

以太网适配器 VMware Network Adapter VMnet8:

   IPv4 地址 . . . . . . . . . . . . : 192.168.242.1
"""


class NicParseTests(unittest.TestCase):
    def test_common_portal_hints_exported(self) -> None:
        self.assertTrue(COMMON_PORTAL_HINTS)
        self.assertTrue(any("1.1.1.1" in url for url in COMMON_PORTAL_HINTS))

    def test_parse_chinese_ipconfig(self) -> None:
        nics = parse_ipconfig(CHINESE_IPCONFIG)
        by_name = {nic.name: nic.ip for nic in nics}
        self.assertEqual(by_name["以太网"], "10.8.1.2")
        self.assertEqual(by_name["VMware Network Adapter VMnet8"], "192.168.242.1")
        self.assertEqual(by_name["VMware Network Adapter VMnet1"], "192.168.44.1")

    def test_decode_gbk_ipconfig_header(self) -> None:
        raw = "以太网适配器 以太网:\r\n   IPv4 地址 . . . . . . . . . . . . : 10.8.1.2\r\n".encode(
            "gb18030"
        )
        text = decode_windows_text(raw)
        self.assertIn("以太网", text)
        nics = parse_ipconfig(text)
        self.assertEqual(nics[0].name, "以太网")
        self.assertEqual(nics[0].ip, "10.8.1.2")


class PickCampusNicTests(unittest.TestCase):
    def test_skips_vmware_even_when_rfc1918(self) -> None:
        nics = [
            NicInfo(name="VMware Network Adapter VMnet8", ip="192.168.242.1"),
            NicInfo(name="VMware Network Adapter VMnet1", ip="192.168.44.1"),
            NicInfo(name="以太网", ip="10.8.1.2"),
        ]
        with patch("campus_connect.netutil.list_nics", return_value=nics):
            chosen = pick_campus_nic(AppConfig())
        self.assertIsNotNone(chosen)
        assert chosen is not None
        self.assertEqual(chosen.name, "以太网")
        self.assertEqual(chosen.ip, "10.8.1.2")

    def test_public_ip_fallback_skips_vmware(self) -> None:
        nics = parse_ipconfig(PUBLIC_IP_IPCONFIG)
        self.assertEqual(nics[0].ip, "203.0.113.10")
        with patch("campus_connect.netutil.list_nics", return_value=nics):
            chosen = pick_campus_nic(AppConfig())
        self.assertIsNotNone(chosen)
        assert chosen is not None
        self.assertEqual(chosen.name, "以太网")
        self.assertEqual(chosen.ip, "203.0.113.10")

    def test_campus_nic_name_wins(self) -> None:
        nics = [
            NicInfo(name="WLAN", ip="10.1.1.1"),
            NicInfo(name="以太网", ip="10.8.1.2"),
            NicInfo(name="VMware Network Adapter VMnet8", ip="192.168.242.1"),
        ]
        cfg = AppConfig(campus_nic_name="以太网")
        with patch("campus_connect.netutil.list_nics", return_value=nics):
            chosen = pick_campus_nic(cfg)
        self.assertIsNotNone(chosen)
        assert chosen is not None
        self.assertEqual(chosen.name, "以太网")

    def test_campus_nic_name_matches_public_ethernet(self) -> None:
        nics = [
            NicInfo(name="VMware Network Adapter VMnet8", ip="192.168.242.1"),
            NicInfo(name="以太网", ip="198.51.100.20"),
        ]
        cfg = AppConfig(campus_nic_name="以太网")
        with patch("campus_connect.netutil.list_nics", return_value=nics):
            chosen = pick_campus_nic(cfg)
        self.assertIsNotNone(chosen)
        assert chosen is not None
        self.assertEqual(chosen.name, "以太网")
        self.assertEqual(chosen.ip, "198.51.100.20")

    def test_fake_ip_is_not_campus(self) -> None:
        nics = [
            NicInfo(name="Meta", ip="198.18.0.1", is_tun=True),
            NicInfo(name="以太网", ip="10.8.1.2"),
        ]
        with patch("campus_connect.netutil.list_nics", return_value=nics):
            chosen = pick_campus_nic(AppConfig())
        self.assertIsNotNone(chosen)
        assert chosen is not None
        self.assertEqual(chosen.name, "以太网")

    def test_only_vmware_means_no_campus_nic(self) -> None:
        nics = [
            NicInfo(name="VMware Network Adapter VMnet8", ip="192.168.242.1"),
            NicInfo(name="VMware Network Adapter VMnet1", ip="192.168.44.1"),
        ]
        with patch("campus_connect.netutil.list_nics", return_value=nics):
            self.assertIsNone(pick_campus_nic(AppConfig()))

    def test_apipa_counts_as_waiting_for_dhcp(self) -> None:
        nics = [
            NicInfo(name="VMware Network Adapter VMnet8", ip="192.168.242.1"),
            NicInfo(name="以太网", ip="169.254.12.34"),
        ]
        cfg = AppConfig()
        with (
            patch("campus_connect.netutil.list_nics", return_value=nics),
            patch("campus_connect.netutil.windows_adapter_status", return_value=[]),
        ):
            self.assertEqual(campus_link_up_without_ip(cfg), "以太网")
            self.assertIsNone(pick_campus_nic(cfg))


if __name__ == "__main__":
    unittest.main()
