from __future__ import annotations

import configparser
from dataclasses import dataclass
from pathlib import Path


class ConfigError(RuntimeError):
    """Raised when the dispatcher configuration is missing or invalid."""


TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"0", "false", "no", "off"}


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
