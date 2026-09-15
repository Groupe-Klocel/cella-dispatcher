from __future__ import annotations

import asyncio
import logging
import os
import platform
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

from .api import CellaApi
from .config import AppConfig
from .models import DocumentFormat, DocumentJob, decode_document
from .sumatra import build_print_command

OS_PLATFORM = platform.system().lower()
BUNDLE_DIR = getattr(sys, "_MEIPASS", os.path.abspath(os.path.dirname(__file__)))


class PrintingError(RuntimeError):
    """Raised when a document cannot be sent to the requested printer."""


class DocumentPrinter:
    def __init__(self, config: AppConfig, base_dir: Path) -> None:
        self._config = config
        self._base_dir = base_dir
        self.sumatra_path = Path(BUNDLE_DIR) / "SumatraPDF.exe"

    def print_job(self, job: DocumentJob) -> bool:
        try:
            decoded_document = decode_document(job)
        except Exception:
            logging.exception("Unable to decode document %s", job.id)
            return False

        temp_file_path = self._build_temp_path(job, decoded_document.suffix)
        try:
            temp_file_path.write_bytes(decoded_document.content)
        except Exception:
            logging.exception("Unable to persist document %s to %s", job.id, temp_file_path)
            return False
        logging.info("Document %s written to %s", job.id, temp_file_path)

        success = False
        try:
            if self._config.runtime.enable_print:
                self._dispatch_print(job, temp_file_path, decoded_document)
                logging.info("Document %s sent to printer %s", job.id, job.printer_name)
            else:
                logging.info("Printing disabled by configuration for document %s", job.id)
            success = True
            return True
        except Exception:
            logging.exception("Failed to print document %s on printer %s", job.id, job.printer_name)
            self._move_to_error_directory(temp_file_path, job)
            return False
        finally:
            if success:
                _safe_remove(temp_file_path)

    def _dispatch_print(self, job: DocumentJob, temp_file_path: Path, decoded_document) -> None:
        if decoded_document.format is DocumentFormat.DOCX:
            raise PrintingError(
                "DOCX printing is not supported by the bundled backends. "
                "Send a PDF payload or configure an external conversion step.",
            )

        if OS_PLATFORM == "windows":
            self._print_windows(job, temp_file_path, decoded_document)
            return
        if OS_PLATFORM == "linux":
            self._print_linux(job, temp_file_path, decoded_document)
            return
        raise PrintingError(f"Unsupported operating system: {platform.system()}")

    def _print_windows(self, job: DocumentJob, temp_file_path: Path, decoded_document) -> None:
        if decoded_document.format is DocumentFormat.PDF:
            if not self.sumatra_path.is_file():
                raise PrintingError(f"SumatraPDF executable not found at {self.sumatra_path}")
            # Without settings SumatraPDF shrinks the page to the paper and turns any page wider than
            # tall by 90 degrees: right for an A4 landscape report, wrong for a label designed wider
            # than tall. [PRINT_SETTINGS] in the INI file tunes this per printer (disable-auto-rotation).
            print_settings = self._config.pdf_print_settings_for(job.printer_name)
            if print_settings:
                logging.info("Document %s printed with SumatraPDF settings %s", job.id, print_settings)
            command = build_print_command(self.sumatra_path, job.printer_name, temp_file_path, print_settings)
            for _ in range(self._config.runtime.number_of_copies):
                subprocess.run(command, check=True)
            return

        if decoded_document.format is not DocumentFormat.RAW:
            raise PrintingError(f"Unsupported Windows print format: {decoded_document.format}")

        import win32print

        printer_handle = win32print.OpenPrinter(job.printer_name or "")
        try:
            for copy_index in range(self._config.runtime.number_of_copies):
                win32print.StartDocPrinter(
                    printer_handle,
                    1,
                    (f"CELLA RAW Print Job {copy_index + 1}", None, "RAW"),
                )
                try:
                    win32print.StartPagePrinter(printer_handle)
                    try:
                        win32print.WritePrinter(printer_handle, decoded_document.content)
                    finally:
                        win32print.EndPagePrinter(printer_handle)
                finally:
                    win32print.EndDocPrinter(printer_handle)
        finally:
            win32print.ClosePrinter(printer_handle)

    def _print_linux(self, job: DocumentJob, temp_file_path: Path, decoded_document) -> None:
        copies = str(self._config.runtime.number_of_copies)
        if decoded_document.format is DocumentFormat.PDF:
            try:
                import cups
            except ImportError:
                subprocess.run(
                    ["lpr", "-P", job.printer_name or "", "-#", copies, str(temp_file_path)],
                    check=True,
                )
                return

            connection = cups.Connection()
            connection.printFile(
                job.printer_name or "",
                str(temp_file_path),
                f"CELLA Print Job {job.id}",
                {"copies": copies},
            )
            return

        if decoded_document.format is DocumentFormat.RAW:
            subprocess.run(
                ["lpr", "-P", job.printer_name or "", "-o", "raw", "-#", copies, str(temp_file_path)],
                check=True,
            )
            return

        raise PrintingError(f"Unsupported Linux print format: {decoded_document.format}")

    def _build_temp_path(self, job: DocumentJob, suffix: str) -> Path:
        unique_name = f"{job.id}_{uuid.uuid4().hex}{suffix}"
        return self._config.runtime.temp_directory / unique_name

    def _move_to_error_directory(self, temp_file_path: Path, job: DocumentJob) -> None:
        if not temp_file_path.exists():
            return
        error_path = self._config.runtime.error_directory / f"{job.id}_{job.safe_filename}"
        candidate = error_path
        counter = 1
        while candidate.exists():
            candidate = error_path.with_name(f"{error_path.stem}_{counter}{error_path.suffix}")
            counter += 1
        shutil.move(str(temp_file_path), str(candidate))
        logging.info("Moved failed document %s to %s", job.id, candidate)


class PrinterSpooler:
    def __init__(self, config: AppConfig, api: CellaApi, base_dir: Path) -> None:
        self._config = config
        self._api = api
        self._printer = DocumentPrinter(config, base_dir)
        self._queues: dict[str, asyncio.Queue[DocumentJob | None]] = {}
        self._workers: dict[str, asyncio.Task[None]] = {}

    async def enqueue(self, job: DocumentJob) -> None:
        if job.printed:
            return

        if not job.printer_name:
            logging.info("Document %s has no printer configured; marking as printed", job.id)
            await self._api.update_document_print_status(job.id)
            return

        if not self._config.is_printer_allowed(job.printer_name):
            logging.info("Printer %s is not authorized for document %s", job.printer_name, job.id)
            return

        queue = self._queues.get(job.printer_name)
        if queue is None:
            queue = asyncio.Queue()
            self._queues[job.printer_name] = queue
            self._workers[job.printer_name] = asyncio.create_task(self._worker(job.printer_name, queue))
            logging.info("Started printer worker for %s", job.printer_name)

        await queue.put(job)

    async def close(self) -> None:
        for queue in self._queues.values():
            await queue.put(None)
        if self._workers:
            await asyncio.gather(*self._workers.values(), return_exceptions=True)
        self._queues.clear()
        self._workers.clear()

    async def _worker(self, printer_name: str, queue: asyncio.Queue[DocumentJob | None]) -> None:
        try:
            while True:
                job = await queue.get()
                try:
                    if job is None:
                        return
                    printed_without_error = await asyncio.to_thread(self._printer.print_job, job)
                    status_updated = await self._api.update_document_print_status(job.id)
                    if not printed_without_error:
                        logging.error("Document %s failed to print but was still acknowledged", job.id)
                    if not status_updated:
                        logging.error("Document %s could not be acknowledged after printing", job.id)
                finally:
                    queue.task_done()
        finally:
            self._queues.pop(printer_name, None)
            self._workers.pop(printer_name, None)
            logging.info("Stopped printer worker for %s", printer_name)


def _safe_remove(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except Exception:
        logging.exception("Unable to delete temporary file %s", path)
