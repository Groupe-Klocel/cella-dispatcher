"""Helpers to drive the bundled SumatraPDF executable used to print PDF documents on Windows."""

from __future__ import annotations

from pathlib import Path


def normalize_print_settings(raw_value: str | None) -> str:
    """Return a clean, comma separated SumatraPDF ``-print-settings`` value.

    Blank items and surrounding spaces are dropped, so a value typed in the INI file such as
    ``disable-auto-rotation, noscale`` reaches SumatraPDF as ``disable-auto-rotation,noscale``.
    """
    if not raw_value:
        return ""
    items = (item.strip() for item in raw_value.split(","))
    return ",".join(item for item in items if item)


def build_print_command(
    sumatra_path: Path | str,
    printer_name: str | None,
    document_path: Path | str,
    print_settings: str = "",
) -> list[str]:
    """Build the SumatraPDF command line printing ``document_path`` on ``printer_name``.

    ``print_settings`` is forwarded through ``-print-settings`` when it is not empty. SumatraPDF
    ignores the settings it does not know, so the command stays valid whatever the bundled version.
    """
    command = [str(sumatra_path), "-print-to", printer_name or ""]
    settings = normalize_print_settings(print_settings)
    if settings:
        command += ["-print-settings", settings]
    command += ["-silent", "-exit-on-print", str(document_path)]
    return command
