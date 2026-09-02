from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from campus_connect.config import load_config, save_config
from campus_connect.models import AppConfig


class ConfigTests(unittest.TestCase):
    def test_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.yaml"
            cfg = AppConfig(
                username="stu001",
                password="s3cret",
                backend="srun",
                srun_ac_id="3",
                campus_nic_name="以太网",
            )
            save_config(cfg, path)
            loaded = load_config(path)
            self.assertEqual(loaded.username, "stu001")
            self.assertEqual(loaded.password, "s3cret")
            self.assertEqual(loaded.backend, "srun")
            self.assertEqual(loaded.srun_ac_id, "3")
            self.assertEqual(loaded.campus_nic_name, "以太网")
            self.assertTrue(loaded.clash_disable_tun)
            self.assertEqual(loaded.link_up_delay, 5)
            self.assertTrue(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
