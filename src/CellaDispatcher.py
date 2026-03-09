"""Compatibility entrypoint for the Cella dispatcher service."""

from __future__ import annotations

import asyncio
import platform
import sys
import threading
from pathlib import Path

OS_PLATFORM = platform.system()

if OS_PLATFORM == "Windows":
    import servicemanager
    import win32service
    import win32serviceutil


def get_cella_directory() -> Path:
    """Return the directory that contains the dispatcher assets."""

    if OS_PLATFORM == "Windows" and getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def main_process(stop_event: threading.Event | None = None) -> None:
    """Run the dispatcher until it is stopped or crashes."""

    try:
        from cella_dispatcher.runtime import run_dispatcher
    except ModuleNotFoundError as exc:
        raise SystemExit(
            f"Missing dependency {exc.name!r}. Install the packages from requirements.txt before starting the dispatcher.",
        ) from exc

    try:
        asyncio.run(run_dispatcher(get_cella_directory(), stop_event=stop_event))
    except KeyboardInterrupt:
        return


def init_service() -> None:
    """Expose the dispatcher as a Windows service when needed."""

    class CellaDispatcherServiceFramework(win32serviceutil.ServiceFramework):
        _svc_name_ = "CellaDispatcherService"
        _svc_display_name_ = "Cella Dispatcher Service"
        _svc_description_ = "Cella Dispatcher is a service that manages the execution of Cella agents and tools."

        def __init__(self, args):
            super().__init__(args)
            self.stop_event = threading.Event()

        def SvcStop(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.stop_event.set()
            self.ReportServiceStatus(win32service.SERVICE_STOPPED)

        def SvcDoRun(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_START_PENDING)
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            main_process(stop_event=self.stop_event)

    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(CellaDispatcherServiceFramework)
        servicemanager.StartServiceCtrlDispatcher()
        return

    win32serviceutil.HandleCommandLine(CellaDispatcherServiceFramework)


if __name__ == "__main__":
    if OS_PLATFORM == "Windows":
        init_service()
    else:
        main_process()
