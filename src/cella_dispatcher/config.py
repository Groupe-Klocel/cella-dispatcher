from __future__ import annotations

import configparser
from dataclasses import dataclass, field
from pathlib import Path

from .sumatra import normalize_print_settings


class ConfigError(RuntimeError):
    """Raised when the dispatcher configuration is missing or invalid."""


TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"0", "false", "no", "off"}

# Optional INI section holding the SumatraPDF "-print-settings" used for PDF documents, per printer.
PRINT_SETTINGS_SECTION = "PRINT_SETTINGS"
# Key of that section applying to every printer without a line of its own.
DEFAULT_PRINTER_KEY = "*"


@dataclass(slots=True, frozen=True)
class ServerConfig:
    api_endpoint_url: str
    warehouse_login: str
    warehouse_password: str
    warehouse_id: str

    @property
    def websocket_endpoint_url(self) -> str:
        if self.api_endpoint_url.startswith("https://"):
            return "wss://" + self.api_endpoint_url.removeprefix("https://")
        if self.api_endpoint_url.startswith("http://"):
            return "ws://" + self.api_endpoint_url.removeprefix("http://")
        return self.api_endpoint_url


@dataclass(slots=True, frozen=True)
class RuntimeConfig:
    connection_retry_seconds: int
    log_retention_days: int
    log_directory: Path
    temp_directory: Path
    number_of_copies: int
    debug: bool
    enable_print: bool
    force_read_delay: int
    printer_allow_list: frozenset[str] | None
    printer_exclude_list: frozenset[str]
    # SumatraPDF -print-settings for PDF documents: the default value and the per printer overrides
    # (keys are printer names in lower case, Windows printer names being case insensitive).
    pdf_print_settings: str = ""
    pdf_print_settings_by_printer: dict[str, str] = field(default_factory=dict)

    @property
    def error_directory(self) -> Path:
        return self.temp_directory / "errors"


@dataclass(slots=True, frozen=True)
class AppConfig:
    config_path: Path
    server: ServerConfig
    runtime: RuntimeConfig

    @classmethod
    def load(cls, base_dir: Path) -> "AppConfig":
        config_path = base_dir / "CellaDispatcher.ini"
        if not config_path.is_file():
            raise ConfigError(f"Config file not found: {config_path}")

        parser = configparser.ConfigParser()
        with config_path.open("r", encoding="utf-8") as handle:
            parser.read_file(handle)

        for section_name in ("SERVER", "CONFIG"):
            if not parser.has_section(section_name):
                raise ConfigError(f"Missing [{section_name}] section in {config_path.name}")

        default_print_settings, print_settings_by_printer = _parse_print_settings(parser)
        server = ServerConfig(
            api_endpoint_url=_require_value(parser, "SERVER", "ApiEndpointUrl"),
            warehouse_login=_require_value(parser, "SERVER", "WarehouseLogin"),
            warehouse_password=_require_value(parser, "SERVER", "WarehousePassword"),
            warehouse_id=_require_value(parser, "SERVER", "WarehouseId"),
        )
        runtime = RuntimeConfig(
            connection_retry_seconds=_parse_int(
                parser,
                "CONFIG",
                "ConnectionFailedWaitBeforeRetry",
                default=15,
                minimum=1,
            ),
            log_retention_days=_parse_int(parser, "CONFIG", "LogRetentionDays", default=7, minimum=1),
            log_directory=_resolve_path(base_dir, parser.get("CONFIG", "LogDirectory", fallback="logs")),
            temp_directory=_resolve_path(base_dir, _require_value(parser, "CONFIG", "TempDirectory")),
            number_of_copies=_parse_int(parser, "CONFIG", "NumberOfCopies", default=1, minimum=1),
            debug=_parse_bool(parser, "CONFIG", "Debug", default=False),
            enable_print=_parse_bool(parser, "CONFIG", "EnablePrint", default=True),
            force_read_delay=_parse_int(parser, "CONFIG", "ForceReadDelay", default=15, minimum=1),
            printer_allow_list=_parse_printer_list(parser.get("CONFIG", "PrinterList", fallback="*")),
            printer_exclude_list=_parse_printer_list(parser.get("CONFIG", "ExcludePrinterList", fallback=""))
            or frozenset(),
            pdf_print_settings=default_print_settings,
            pdf_print_settings_by_printer=print_settings_by_printer,
        )
        config = cls(config_path=config_path, server=server, runtime=runtime)
        config.ensure_directories()
        return config

    def ensure_directories(self) -> None:
        self.runtime.log_directory.mkdir(parents=True, exist_ok=True)
        self.runtime.temp_directory.mkdir(parents=True, exist_ok=True)
        self.runtime.error_directory.mkdir(parents=True, exist_ok=True)

    def is_printer_allowed(self, printer_name: str) -> bool:
        normalized_name = printer_name.strip()
        if self.runtime.printer_allow_list is not None and normalized_name not in self.runtime.printer_allow_list:
            return False
        if normalized_name in self.runtime.printer_exclude_list:
            return False
        return True

    def pdf_print_settings_for(self, printer_name: str | None) -> str:
        """Return the SumatraPDF -print-settings to use for PDF documents sent to ``printer_name``.

        A printer with its own line in [PRINT_SETTINGS] uses that line, even when it is empty; every
        other printer uses the "*" default, which is empty (SumatraPDF defaults) when not configured.
        """
        normalized_name = (printer_name or "").strip().lower()
        return self.runtime.pdf_print_settings_by_printer.get(normalized_name, self.runtime.pdf_print_settings)


def _require_value(parser: configparser.ConfigParser, section: str, option: str) -> str:
    value = parser.get(section, option, fallback="").strip()
    if not value:
        raise ConfigError(f"Missing required value: [{section}] {option}")
    return value


def _parse_bool(
    parser: configparser.ConfigParser,
    section: str,
    option: str,
    *,
    default: bool,
) -> bool:
    raw_value = parser.get(section, option, fallback=str(default)).strip().lower()
    if raw_value in TRUE_VALUES:
        return True
    if raw_value in FALSE_VALUES:
        return False
    raise ConfigError(f"Invalid boolean value for [{section}] {option}: {raw_value!r}")


def _parse_int(
    parser: configparser.ConfigParser,
    section: str,
    option: str,
    *,
    default: int,
    minimum: int,
) -> int:
    raw_value = parser.get(section, option, fallback=str(default)).strip()
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ConfigError(f"Invalid integer value for [{section}] {option}: {raw_value!r}") from exc
    if value < minimum:
        raise ConfigError(
            f"Value for [{section}] {option} must be greater than or equal to {minimum}, got {value}",
        )
    return value


def _parse_print_settings(parser: configparser.ConfigParser) -> tuple[str, dict[str, str]]:
    """Read the optional [PRINT_SETTINGS] section: the "*" default and the per printer overrides."""
    if not parser.has_section(PRINT_SETTINGS_SECTION):
        return "", {}
    default_settings = ""
    settings_by_printer: dict[str, str] = {}
    for printer_name, raw_value in parser.items(PRINT_SETTINGS_SECTION):
        settings = normalize_print_settings(raw_value)
        normalized_name = printer_name.strip()
        if normalized_name == DEFAULT_PRINTER_KEY:
            default_settings = settings
        elif normalized_name:
            settings_by_printer[normalized_name.lower()] = settings
    return default_settings, settings_by_printer


def _parse_printer_list(raw_value: str) -> frozenset[str] | None:
    normalized = raw_value.strip()
    if not normalized or normalized == "*":
        return None
    return frozenset(item.strip() for item in normalized.split(",") if item.strip())


def _resolve_path(base_dir: Path, raw_path: str) -> Path:
    path = Path(raw_path).expanduser()
    if path.is_absolute():
        return path
    return (base_dir / path).resolve()
