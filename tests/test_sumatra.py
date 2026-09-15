from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from cella_dispatcher.sumatra import build_print_command, normalize_print_settings


class SumatraPrintCommandTests(unittest.TestCase):
    def test_normalize_print_settings_cleans_blanks_and_empty_items(self) -> None:
        self.assertEqual(normalize_print_settings(None), "")
        self.assertEqual(normalize_print_settings(""), "")
        self.assertEqual(normalize_print_settings("  ,  "), "")
        self.assertEqual(normalize_print_settings("disable-auto-rotation"), "disable-auto-rotation")
        self.assertEqual(
            normalize_print_settings(" disable-auto-rotation , noscale ,, paper=A4 "),
            "disable-auto-rotation,noscale,paper=A4",
        )

    def test_build_print_command_without_settings_keeps_the_historical_command(self) -> None:
        command = build_print_command(Path("C:/dispatcher/SumatraPDF.exe"), "ZEBRA39", Path("C:/temp/1_abc.pdf"))

        self.assertEqual(
            command,
            ["C:/dispatcher/SumatraPDF.exe", "-print-to", "ZEBRA39", "-silent", "-exit-on-print", "C:/temp/1_abc.pdf"],
        )

    def test_build_print_command_forwards_print_settings(self) -> None:
        command = build_print_command("SumatraPDF.exe", "ZEBRA39", "label.pdf", " disable-auto-rotation, noscale ")

        self.assertEqual(
            command,
            [
                "SumatraPDF.exe",
                "-print-to",
                "ZEBRA39",
                "-print-settings",
                "disable-auto-rotation,noscale",
                "-silent",
                "-exit-on-print",
                "label.pdf",
            ],
        )

    def test_build_print_command_tolerates_a_missing_printer_name(self) -> None:
        command = build_print_command("SumatraPDF.exe", None, "label.pdf", "")

        self.assertEqual(command[1:3], ["-print-to", ""])
        self.assertNotIn("-print-settings", command)


if __name__ == "__main__":
    unittest.main()
