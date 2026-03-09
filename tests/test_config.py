from __future__ import annotations

import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from cella_dispatcher.config import AppConfig, ConfigError


class AppConfigTests(unittest.TestCase):
    def test_load_normalizes_values_and_creates_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base_dir = Path(tmpdir)
            (base_dir / "CellaDispatcher.ini").write_text(
                textwrap.dedent(
                    """
                    [SERVER]
                    ApiEndpointUrl=https://api.example.com/graphql
                    WarehouseLogin=warehouse
                    WarehousePassword=secret
                    WarehouseId=my-warehouse

                    [CONFIG]
                    ConnectionFailedWaitBeforeRetry=10
                    LogRetentionDays=5
                    LogDirectory=logs
                    TempDirectory=tmp
                    NumberOfCopies=2
                    Debug=yes
                    EnablePrint=no
                    ForceReadDelay=20
                    PrinterList=Printer A, Printer B
                    ExcludePrinterList=Printer C
                    """,
                ).strip(),
                encoding="utf-8",
            )

            config = AppConfig.load(base_dir)

            self.assertEqual(config.server.websocket_endpoint_url, "wss://api.example.com/graphql")
            self.assertEqual(config.runtime.number_of_copies, 2)
            self.assertTrue(config.runtime.debug)
            self.assertFalse(config.runtime.enable_print)
            self.assertEqual(config.runtime.printer_allow_list, frozenset({"Printer A", "Printer B"}))
            self.assertEqual(config.runtime.printer_exclude_list, frozenset({"Printer C"}))
            self.assertTrue(config.runtime.log_directory.is_dir())
            self.assertTrue(config.runtime.temp_directory.is_dir())
            self.assertTrue(config.runtime.error_directory.is_dir())

    def test_load_rejects_missing_required_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base_dir = Path(tmpdir)
            (base_dir / "CellaDispatcher.ini").write_text(
                textwrap.dedent(
                    """
                    [SERVER]
                    ApiEndpointUrl=
                    WarehouseLogin=warehouse
                    WarehousePassword=secret
                    WarehouseId=my-warehouse

                    [CONFIG]
                    TempDirectory=tmp
                    """,
                ).strip(),
                encoding="utf-8",
            )

            with self.assertRaises(ConfigError):
                AppConfig.load(base_dir)


if __name__ == "__main__":
    unittest.main()
