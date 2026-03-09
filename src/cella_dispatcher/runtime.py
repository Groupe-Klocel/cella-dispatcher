from __future__ import annotations

import asyncio
import logging
import threading
from datetime import date, datetime, timedelta
from pathlib import Path

from .api import CellaApi
from .config import AppConfig, ConfigError
from .printing import PrinterSpooler


class DailyLogManager:
    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._current_date: date | None = None

    def initialize(self) -> None:
        self.rotate_if_needed(force=True)

    def rotate_if_needed(self, *, force: bool = False) -> None:
        today = date.today()
        if not force and today == self._current_date:
            return

        logfile = self._config.runtime.log_directory / f"{today.isoformat()}.log"
        root_logger = logging.getLogger()
        for handler in list(root_logger.handlers):
            root_logger.removeHandler(handler)
            handler.close()

        log_level = logging.DEBUG if getattr(self._config.runtime, "debug", False) else logging.INFO
        logging.basicConfig(
            filename=logfile,
            filemode="a",
            format="%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s",
            datefmt="%H:%M:%S",
            level=log_level,
        )
        self._current_date = today
        logging.info("Switched log file to %s", logfile)
        self.cleanup_archives()

    def cleanup_archives(self) -> None:
        threshold = datetime.now() - timedelta(days=self._config.runtime.log_retention_days)
        for directory in (
            self._config.runtime.log_directory,
            self._config.runtime.error_directory,
        ):
            for path in directory.iterdir():
                if not path.is_file():
                    continue
                modified_at = datetime.fromtimestamp(path.stat().st_mtime)
                if modified_at >= threshold:
                    continue
                try:
                    path.unlink(missing_ok=True)
                except Exception:
                    logging.exception("Unable to remove archive file %s", path)
                    continue
                logging.info("Removed archive file %s", path)


async def run_dispatcher(base_dir: Path, stop_event: threading.Event | None = None) -> None:
    try:
        config = AppConfig.load(base_dir)
    except ConfigError as exc:
        raise SystemExit(str(exc)) from exc

    log_manager = DailyLogManager(config)
    log_manager.initialize()
    CellaApi.configure_transport_logging(config.runtime.debug)

    api = CellaApi(config)
    spooler = PrinterSpooler(config, api, base_dir)
    logging.info("Starting Cella dispatcher")

    try:
        while not _should_stop(stop_event):
            try:
                token = await api.authenticate()
                await api.use_token(token)
                logging.info("Authenticated to CELLA")
                await _drain_backlog(log_manager, api, spooler)
                await _consume_subscription(log_manager, api, spooler, stop_event)
            except asyncio.CancelledError:
                raise
            except Exception:
                logging.exception(
                    "Connection to CELLA failed. Retrying in %s seconds",
                    config.runtime.connection_retry_seconds,
                )
                await api.close()
                if _should_stop(stop_event):
                    break
                await _sleep_with_stop(config.runtime.connection_retry_seconds, stop_event)
    finally:
        await spooler.close()
        await api.close()
        logging.info("Cella dispatcher stopped")


async def _drain_backlog(log_manager: DailyLogManager, api: CellaApi, spooler: PrinterSpooler) -> None:
    for document in await api.get_unprinted_documents():
        log_manager.rotate_if_needed()
        await spooler.enqueue(document)


async def _consume_subscription(
    log_manager: DailyLogManager,
    api: CellaApi,
    spooler: PrinterSpooler,
    stop_event: threading.Event | None,
) -> None:
    async for document in api.subscribe_documents():
        log_manager.rotate_if_needed()
        if _should_stop(stop_event):
            return
        if document is None:
            logging.debug("Subscription keep-alive received")
            continue
        await spooler.enqueue(document)


def _should_stop(stop_event: threading.Event | None) -> bool:
    return stop_event is not None and stop_event.is_set()


async def _sleep_with_stop(seconds: int, stop_event: threading.Event | None) -> None:
    remaining = max(seconds, 0)
    while remaining > 0 and not _should_stop(stop_event):
        await asyncio.sleep(min(remaining, 1))
        remaining -= 1
