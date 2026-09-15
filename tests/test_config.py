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
            # No [PRINT_SETTINGS] section: PDF documents keep the SumatraPDF defaults on every printer
            self.assertEqual(config.runtime.pdf_print_settings, "")
            self.assertEqual(config.runtime.pdf_print_settings_by_printer, {})
            self.assertEqual(config.pdf_print_settings_for("Printer A"), "")

    def test_load_reads_pdf_print_settings_per_printer(self) -> None:
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
                    TempDirectory=tmp

                    [PRINT_SETTINGS]
                    ; every printer without a line of its own
                    *=shrink
                    ZEBRA39 = disable-auto-rotation, noscale ,
                    Label Printer=disable-auto-rotation
                    Office Printer=
                    """,
                ).strip(),
                encoding="utf-8",
            )

            config = AppConfig.load(base_dir)

            self.assertEqual(config.runtime.pdf_print_settings, "shrink")
            self.assertEqual(
                config.runtime.pdf_print_settings_by_printer,
                {"zebra39": "disable-auto-rotation,noscale", "label printer": "disable-auto-rotation", "office printer": ""},
            )
            # Printer names are matched case insensitively, blanks and empty items are cleaned up
            self.assertEqual(config.pdf_print_settings_for("zebra39"), "disable-auto-rotation,noscale")
            self.assertEqual(config.pdf_print_settings_for(" Label Printer "), "disable-auto-rotation")
            # An explicit empty line overrides the "*" default, an unknown printer gets the default
            self.assertEqual(config.pdf_print_settings_for("Office Printer"), "")
            self.assertEqual(config.pdf_print_settings_for("Other Printer"), "shrink")
            self.assertEqual(config.pdf_print_settings_for(None), "shrink")

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
