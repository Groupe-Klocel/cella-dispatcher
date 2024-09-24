# CELLA Dispatcher
# Multiplatform tool that can be used to communicate with CELLA WMS APIs.
# Copyright (C) 2023 KLOCEL <contact@klocel.com>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import asyncio
import base64
import configparser
import logging
import os
import platform
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta
from queue import Queue
from typing import Any, Dict, List

from gql import Client, gql
from gql.transport.aiohttp import AIOHTTPTransport
from gql.transport.aiohttp import log as requests_logger
from gql.transport.websockets import WebsocketsTransport
from gql.transport.websockets import log as websockets_logger

os_platform = platform.system()

if os_platform == "Windows":
    import servicemanager
    import win32print
    import win32service
    import win32serviceutil
if os_platform == "Linux":
    import cups


printer_queue = {}
printer_threads = {}
# Default logging level
requests_logger.setLevel(logging.WARNING)
websockets_logger.setLevel(logging.WARNING)


def get_cella_directory() -> str:
    """
    Get Cella directory
    """

    path = os.path.dirname(__file__)
    if os_platform == "Windows":
        if getattr(sys, "frozen", False):
            path = os.path.dirname(sys.executable)
    return path


def get_cella_dispatcher_config() -> configparser.ConfigParser:
    """
    Get Cella Dispatcher configuration from file
    """

    path = os.path.join(get_cella_directory(), "CellaDispatcher.ini")
    if not os.path.isfile(path):
        print("Config file not found")
        sys.exit(1)
    config = configparser.ConfigParser()
    config.read(path)
    return config


# Fonction to init log file or display logs on screen if error occured
def init_logs(config: configparser.ConfigParser) -> str:
    """
    Initialize log file
    """

    # check log directory
    if not os.path.isdir(os.path.join(get_cella_directory(), config["CONFIG"]["LogDirectory"])):
        os.makedirs(os.path.join(get_cella_directory(), config["CONFIG"]["LogDirectory"]))

    create_log_file(config)

    logging.info("Start KloDispatcher")
    if config["CONFIG"]["Debug"] == "yes":
        logging.info("Debug mode is enabled")
        requests_logger.setLevel(logging.INFO)
        websockets_logger.setLevel(logging.INFO)

    # store current date
    now = datetime.now()
    log_date = f"{now.year}{now.month:02d}{now.day:02d}"

    return log_date


def create_log_file(config: configparser.ConfigParser) -> None:
    """
    Create new or use existing log file
    """
    # set date on filename
    now = datetime.now()
    log_extension = ".log"

    # Remove all handlers associated with the root logger object.
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    filename = f"{now.year}-{now.month:02d}-{now.day:02d}{log_extension}"
    logfile = os.path.join(os.path.join(get_cella_directory(), config["CONFIG"]["LogDirectory"]), filename)
    logging.basicConfig(
        filename=logfile,
        filemode="a",
        format="%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
        level=logging.DEBUG,
    )
    logging.info("Start new log file")


# Function to check if all vars are set
def check_init_config(config: configparser.ConfigParser) -> bool:
    """
    Check the configuration file
    """

    # check init vars
    if (
        config["SERVER"]["ApiEndpointUrl"] == ""
        or config["SERVER"]["WarehouseLogin"] == ""
        or config["SERVER"]["WarehousePassword"] == ""
        or config["SERVER"]["WarehouseId"] == ""
        or config["CONFIG"]["LogRetentionDays"] == ""
        or config["CONFIG"]["TempDirectory"] == ""
    ):
        logging.error("Config vars are not all set : KloDispatcher is stopped")
        return False

    # check number of copies is integer
    if int(config["CONFIG"]["NumberOfCopies"]) < 0:
        config["CONFIG"]["NumberOfCopies"] = "1"
        logging.info("Number of copies is set to negative, set to default value")
    # check temp directory
    if not os.path.isdir(config["CONFIG"]["TempDirectory"]):
        try:
            os.makedirs(config["CONFIG"]["TempDirectory"])
        except Exception as e:
            logging.error("Temp directory cannot be created")
            logging.error(f"Error: {e}")
            return False

    # check temp directory (errors)
    if not os.path.isdir(config["CONFIG"]["TempDirectory"] + "/errors"):
        try:
            os.makedirs(config["CONFIG"]["TempDirectory"] + "/errors")
        except Exception as e:
            logging.error("Temp error directory cannot be created")
            logging.error(f"Error: {e}")

    return True


# Fonction to remove old logs
def delete_archives(config: configparser.ConfigParser) -> None:
    """
    Delete old log files
    """

    # Remove old log files
    logging.info("Remove old archives")

    try:
        # Calculate the date threshold for old files
        current_date = datetime.now()
        threshold_date = current_date - timedelta(days=int(config["CONFIG"]["LogRetentionDays"]))

        # List files in the specified directory
        files = os.listdir(os.path.join(get_cella_directory(), config["CONFIG"]["LogDirectory"]))

        for file_name in files:
            file_path = os.path.join(get_cella_directory(), config["CONFIG"]["LogDirectory"], file_name)

            # Check if the file is a regular file (not a directory)
            if os.path.isfile(file_path):
                # Extract the file's modification timestamp from its name
                try:
                    # Assuming the filename format is "YYYYMMDD.ext"
                    timestamp_str = file_name[0:4] + file_name[5:7] + file_name[8:10]
                    file_date = datetime.strptime(timestamp_str, "%Y%m%d")

                    # Compare the file's date with the threshold date
                    if file_date < threshold_date:
                        # Remove the old file
                        os.remove(file_path)
                        logging.info(f"Removed old archive file: {file_name}")
                except ValueError:
                    logging.error(f"Skipped file with invalid format: {file_name}")

    except Exception as e:
        logging.error(f"Error: {e}")


# Fonction to remove old error files
def delete_error_files(config: configparser.ConfigParser) -> None:
    """
    Delete old error files
    """

    # Remove old error files
    logging.info("Remove old error files")

    try:

        # Calculate the date threshold for old files
        current_datetime = datetime.now()
        # threshold_date = current_date - timedelta(days=int(config["CONFIG"]["LogRetentionDays"]))

        for file_name in os.listdir(os.path.join(config["CONFIG"]["TempDirectory"], "errors")):
            file_path = os.path.join(os.path.join(config["CONFIG"]["TempDirectory"], "errors", file_name))

            # Check if the path is a file and not a directory
            if os.path.isfile(file_path):
                # Get the last modification time of the file
                modification_datetime = datetime.fromtimestamp(os.path.getmtime(file_path))

                # Calculate the age of the file in days
                age_in_days = (current_datetime - modification_datetime).days
                # Delete the file if it's older than the threshold
                if age_in_days > int(config["CONFIG"]["LogRetentionDays"]):
                    os.remove(file_path)
                    logging.info(f"Removed old error file: {file_name}")

    except Exception as e:
        logging.error(f"Error: {e}")


# Function to update document print status
async def update_document_print_status(
    config: configparser.ConfigParser, session, token: str, document_id: str
) -> bool:
    """
    Update document print status
    """

    if session is None:
        client, local_session = await connect_api(config, token)
    else:
        local_session = session
    mutation = gql(
        """
        mutation updateDocumentHistory($id: Int!){
            updateDocumentHistory(id: $id,
            input: { printed: true } ) {
                id
            }
        }
        """
    )

    params = {"id": int(document_id)}
    try:
        result = await local_session.execute(mutation, variable_values=params)
        logging.info(f"Document {document_id} updated")
    except Exception as e:
        logging.error(f"Error when updating the document {document_id}: {e}")
        if session is None:
            await client.close_async()
        return False

    if session is None:
        await client.close_async()

    return True


# Function to manage printing
async def manage_printing(config: configparser.ConfigParser, token: str, documentToPrint: Dict[str, Any]) -> bool:
    # is document has been printed
    if not documentToPrint["printed"]:
        logging.info(f"Document to print: {documentToPrint['id']}")

        if documentToPrint["printerName"] is None or documentToPrint["printerName"] == "":
            logging.info(f"Printer name is not set for document {documentToPrint['id']}")
            await update_document_print_status(config, None, token, documentToPrint["id"])
            return True

        if config["CONFIG"]["PrinterList"] != "*" and documentToPrint["printerName"] not in config["CONFIG"][
            "PrinterList"
        ].split(","):
            logging.info(f"Printer {documentToPrint['printerName']} is not in the list of authorized printers")
            return True
        # Search existing printer thread. If not, create new thread
        if not documentToPrint["printerName"] in printer_threads:
            logging.info(f"Start new thread for printer {documentToPrint['printerName']}")
            # Create a queue for passing messages to the threads
            printer_queue[documentToPrint["printerName"]] = Queue()
            # Create thread
            thread = threading.Thread(
                target=printer_worker_thread,
                args=(
                    config,
                    token,
                    printer_queue[documentToPrint["printerName"]],
                ),
            )
            thread.start()
            printer_threads[documentToPrint["printerName"]] = thread

        # set current document to related queue
        printer_queue[documentToPrint["printerName"]].put(documentToPrint)
    return True


# Set subscription
async def subscription(config: configparser.ConfigParser, token: str, log_date: str) -> None:
    """
    Core process, subscribe to documentPrintings
    """
    transport_ws = WebsocketsTransport(
        url=str(config["SERVER"]["ApiEndpointUrl"]).replace("http", "ws"),
        headers={"authorization": "Bearer " + token},
        connect_args={"max_size": None}
    )
    client_ws = Client(transport=transport_ws, fetch_schema_from_transport=False, execute_timeout=10)

    subscription_query = gql(
        """
        subscription documentPrintings($auth: Authinput!){
            documentPrintings(auth: $auth) {
                keepAlive
                documentHistory {
                    id
                    created
                    createdBy
                    modified
                    modifiedBy
                    lastTransactionId
                    documentName
                    version
                    executionDate
                    binaryDocument
                    printed
                    printerName
                    reference
                    documentType
                    documentTemplateId
                    documentTemplateVersionId
                }
            }
        }
        """
    )

    subscriptionQueryVariables = {
        "auth": {"token": "Bearer " + token, "keepAlive": int(config["CONFIG"]["ForceReadDelay"])},
    }

    async for oneDocument in client_ws.subscribe_async(subscription_query, variable_values=subscriptionQueryVariables):

        # check for new log file
        now = datetime.now()
        current_date = f"{now.year}{now.month:02d}{now.day:02d}"

        if not current_date == log_date:
            logging.info("System date changed")
            # delete old log archives
            delete_archives(config)
            # delete old error files
            delete_error_files(config)

            # create new log file
            create_log_file(config)

            log_date = current_date

        if oneDocument["documentPrintings"]["documentHistory"] is not None:
            documentToPrint = oneDocument["documentPrintings"]["documentHistory"]
            await manage_printing(config, token, documentToPrint)
        else:
            logging.info("Keep alive")
            # logging.info("Force reading of unprinted documents")
            # unprinted_documents = await get_unprinted_documents(config, token)
            # for oneUnprintedDocument in unprinted_documents:
            #     await manage_printing(config, token, oneUnprintedDocument)

    return None


# Function that will be executed by the threads
async def printer_worker_execution(config, token, documentToPrint) -> bool:
    """
    Print document
    """

    if config["CONFIG"]["Debug"] == "yes":
        logging.info(
            f"{threading.current_thread().name} => Document to print: "
            f"{documentToPrint['documentName']}; "
            f"Printer: {documentToPrint['printerName']}"
        )
    # Start print process
    if documentToPrint["printerName"] is None or documentToPrint["printerName"] == "":
        logging.info(f"Printer name is not set for document {documentToPrint['id']}")
        process_without_error = True
    else:
        process_without_error = await print_current_document(config, documentToPrint)

    # Update document anyway
    await update_document_print_status(config, None, token, documentToPrint["id"])
    if not process_without_error:
        logging.error("Document history updated BUT error occured during printing.")

    return True


# Function that represents a thread
def printer_worker_thread(config, token, printer_queue):
    """
    Thread that will print documents
    """

    logging.info(f"Thread {threading.current_thread().name} started")
    # client, session = asyncio.run(connect_api(config, token))
    while True:
        documentToPrint = printer_queue.get()
        if documentToPrint is None:
            break
        asyncio.run(printer_worker_execution(config, token, documentToPrint))

    logging.info(f"Thread {threading.current_thread().name} ended")


async def print_current_document(config, document: Dict[str, Any]):
    """
    Spool document to the printer
    """

    process_without_error = True
    file_extension = ""

    if config["CONFIG"]["Debug"] == "yes":
        logging.info("document type: " + document["documentType"].lower())

    # set printer name
    printer_name = document["printerName"]

    if document["documentType"].lower() == "rml" or document["documentType"].lower() == "pdf":
        # Decode the Base64 string, making sure that
        # it contains only valid characters
        bytes = base64.b64decode(document["binaryDocument"], validate=True)

        # Perform a basic validation to make sure that the
        # result is a valid PDF file
        # Be aware! The magic number (file signature) is not
        # 100% reliable solution to validate PDF files
        # Moreover, if you get Base64 from an untrusted source,
        # you must sanitize the PDF contents
        if bytes[0:4] != b"%PDF":
            process_without_error = False
            logging.error("PDF document not valid")
            raise ValueError("Missing the PDF file signature")
    elif document["documentType"].lower() == "zpl":
        # Decode the Base64 string, making sure that
        # it contains only valid characters
        bytes = base64.b64decode(document["binaryDocument"], validate=True)

    else:
        process_without_error = False
        logging.error(f'Unknown document type: {document["documentType"]}')

    # create temp file
    if process_without_error:
        # Write the PDF contents to a local file
        # create temp binary file
        now = datetime.now()
        filename, file_extension = os.path.splitext(document["documentName"])
        file_name = f"{now.year}-{now.month:02d}-{now.day:02d}_{str(uuid.uuid4())}"
        file_path = f"{config['CONFIG']['TempDirectory']}/{file_name}{file_extension}"

        try:
            f = open(file_path, "wb")
            f.write(bytes)
            f.close()
            logging.info(f"Binary content written to {file_path}")

        except Exception as e:
            process_without_error = False
            logging.error(f"Error during file creation: {e}")

    # on windows printer
    if process_without_error:
        if os_platform == "Windows":
            if config["CONFIG"]["Debug"] == "yes":
                logging.info("Print on Windows")
            try:
                if config["CONFIG"]["EnablePrint"] == "yes":
                    if document["documentType"].lower() == "rml" or document["documentType"].lower() == "pdf":
                        file_format = "PDF"

                    elif document["documentType"].lower() == "zpl":
                        file_format = "ZPL"

                    else:
                        os.rename(
                            file_path,
                            (
                                config["CONFIG"]["TempDirectory"]
                                + "/errors/"
                                + file_name
                                + f"_{document['documentName']}"
                            ),
                        )
                        logging.error(f"Document {file_path} format not reconized ")
                        process_without_error = False

                    if process_without_error:
                        if document["documentType"].lower() == "rml" or document["documentType"].lower() == "pdf":
                            bundle_dir = getattr(sys, "_MEIPASS", os.path.abspath(os.path.dirname(__file__)))
                            path_to_sumatra = os.path.abspath(os.path.join(bundle_dir, "SumatraPDF.exe"))
                            print_result = subprocess.run(
                                [path_to_sumatra, "-print-to", printer_name, "-silent", "-exit-on-print", file_path]
                            )

                            if print_result.returncode == 1:
                                raise Exception(f"Exception raised : 'Return code' ({print_result.returncode})")

                        elif document["documentType"].lower() == "zpl":
                            printer_handle = win32print.OpenPrinter(printer_name)

                            # Start a print job

                            win32print.StartDocPrinter(printer_handle, 1, (f"{file_format} Print Job", None, "RAW"))
                            win32print.StartPagePrinter(printer_handle)

                            win32print.WritePrinter(printer_handle, bytes)

                            # End the print job
                            win32print.EndPagePrinter(printer_handle)
                            win32print.EndDocPrinter(printer_handle)
                            win32print.ClosePrinter(printer_handle)

                        if config["CONFIG"]["Debug"] == "yes":
                            logging.info(f"Document {file_path} sent to printer '{printer_name}'")

                else:
                    logging.info(f"Document {file_path} print is DISABLED from config file.")

            except Exception as e:
                process_without_error = False
                # move binary file to error directory
                os.rename(
                    file_path,
                    (config["CONFIG"]["TempDirectory"] + "/errors/" + file_name + f"_{document['documentName']}"),
                )
                logging.error(f"Error: {e}")

        elif os_platform == "linux":
            if config["CONFIG"]["Debug"] == "yes":
                logging.info("Print on Linux")
            try:
                if config["CONFIG"]["EnablePrint"] == "yes":
                    if document["documentType"].lower() == "rml" or document["documentType"].lower() == "pdf":
                        # Create a CUPS connection
                        conn = cups.Connection()

                        # Print the document
                        job_id = conn.printFile(printer_name, file_path, "Print Job", {})

                    elif document["documentType"].lower() == "zpl":
                        subprocess.run(["lpr", "-P", printer_name, "-o", "raw", file_path])

                    if config["CONFIG"]["Debug"] == "yes":
                        logging.info(
                            f"Document {file_path} sent to printer '{printer_name}' (Printer Job ID: {job_id})."
                        )
                else:
                    logging.info(f"Document {file_path} print is DISABLE from config file.")

            except Exception as e:
                process_without_error = False
                # move binary file to error directory
                os.rename(
                    file_path,
                    (config["CONFIG"]["TempDirectory"] + "/errors/" + file_name + f"_{document['documentName']}"),
                )
                logging.error(f"Error: {e}")
        else:
            logging.error("Os not compatible")
            process_without_error = False

    else:
        logging.error("Format not supported")
        process_without_error = False

    # delete temp document
    if process_without_error:
        try:
            os.remove(file_path)
        except Exception as e:
            process_without_error = False
            logging.error(f"Error: {e}")

    return process_without_error


# Function to connect to GraphQL Endpoint
async def authenticate_api(config):
    """
    Authenticate to CELLA
    """
    user = config["SERVER"]["WarehouseLogin"]
    password = config["SERVER"]["WarehousePassword"]
    warehouse_id = config["SERVER"]["WarehouseId"]
    api_endpoint = config["SERVER"]["ApiEndpointUrl"]

    transport = AIOHTTPTransport(url=api_endpoint, ssl_close_timeout=10, timeout=10)
    client = Client(transport=transport, fetch_schema_from_transport=False, execute_timeout=600)
    session = await client.connect_async(reconnecting=True)

    # Login
    query = gql(
        """
        mutation warehouseLogin($username: String!, $password: String!, $warehouseId: ID!) {
            warehouseLogin(username: $username, password: $password, warehouseId: $warehouseId) {
                accessToken
            }
        }
        """
    )
    params = {"username": user, "password": password, "warehouseId": warehouse_id}
    try:
        result = await session.execute(query, variable_values=params)
        if result["warehouseLogin"] is None:
            logging.error("Password error")
            raise Exception("Password error")
        token = result["warehouseLogin"]["accessToken"]
    except Exception as e:
        logging.error(f"Cella Access Token cannot be retrieved: {e}")
        # We disconnect the session
        await client.close_async()
        await transport.close()
        raise e

    # We disconnect the session
    await client.close_async()
    await transport.close()

    logging.info("Authenticated to CELLA")
    return token


# Function to connect to GraphQL Endpoint
async def connect_api(config, token: str):
    """
    Connect to CELLA
    """
    logging.info("Connecting to CELLA")
    api_endpoint = config["SERVER"]["ApiEndpointUrl"]
    transport = AIOHTTPTransport(
        url=api_endpoint, headers={"authorization": "Bearer " + token}, ssl_close_timeout=10, timeout=10
    )
    client = Client(transport=transport, fetch_schema_from_transport=False, execute_timeout=600)
    session = await client.connect_async(reconnecting=True)
    logging.info("Connected to CELLA")
    return client, session


# Get unprinted documents
async def get_unprinted_documents(config, token: str) -> List[Any]:
    """
    Get unprinted documents
    """

    client, session = await connect_api(config, token)
    logging.info("Get unprinted documents")
    # We retrieve the not printed documentsHistories
    query = gql(
        """
        query {
            documentHistories(
                orderBy: {field: id, ascending: true}
                filters: { printed: false}
                page: 1,
                itemsPerPage: 10000,
            ) {
                results {
                    id
                    created
                    createdBy
                    modified
                    modifiedBy
                    lastTransactionId
                    documentName
                    version
                    executionDate
                    binaryDocument
                    printed
                    printerName
                    reference
                    documentType
                    documentTemplateId
                    documentTemplateVersionId
                }
            }
        }
        """
    )
    try:
        result = await session.execute(query)
        if "errors" in result:
            logging.error("GraphQL Errors:")
            for error in result["errors"]:
                logging.error(f"- {error['message']}")
            await client.close_async()
            return []
        else:
            datas = result["documentHistories"]["results"]
            if datas is not None:
                logging.info(f"Number of unprinted documents: {len(result['documentHistories']['results'])}")
            await client.close_async()
            return datas

    except Exception as e:
        logging.error(f"Error: {e}")
        await client.close_async()
        raise e


def init_service():
    class CellaDispatcherService:
        """Service"""

        def stop(self):
            """Stop the service"""
            self.running = False

        def run(self):
            """Main service loop. This is where work is done!"""
            self.running = True
            while self.running:
                main_process()
                servicemanager.LogInfoMsg("Service running...")

    class CellaDispatcherServiceFramework(win32serviceutil.ServiceFramework):
        _svc_name_ = "CellaDispatcherService"
        _svc_display_name_ = "Cella Dispatcher Service"

        def SvcStop(self):
            """Stop the service"""
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.service_impl.stop()
            self.ReportServiceStatus(win32service.SERVICE_STOPPED)

        def SvcDoRun(self):
            """Start the service; does not return until stopped"""
            self.ReportServiceStatus(win32service.SERVICE_START_PENDING)
            self.service_impl = CellaDispatcherService()
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            # Run the service
            self.service_impl.run()

    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(CellaDispatcherServiceFramework)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(CellaDispatcherServiceFramework)


def main_process():
    config = get_cella_dispatcher_config()
    log_date = init_logs(config)
    if not check_init_config(config):
        sys.exit(1)
    authenticated = False

    # Main loop
    while True:
        try:
            if not authenticated:
                # We connect to the API
                token = asyncio.run(authenticate_api(config))
                authenticated = True
            unprinted_documents = asyncio.run(get_unprinted_documents(config, token))
            for oneUnprintedDocument in unprinted_documents:
                asyncio.run(printer_worker_execution(config, token, oneUnprintedDocument))

            run = asyncio.run(subscription(config, token, log_date))
        except Exception as e:
            logging.error("Connection to Cella failed. Wait before trying again.")
            logging.error(f"Error: {e}")
            time.sleep(int(config["CONFIG"]["ConnectionFailedWaitBeforeRetry"]))
            authenticated = False

    # We close the connection
    asyncio.run(client.close_async())


# main
if __name__ == "__main__":
    if os_platform == "Windows":
        init_service()
    else:
        main_process()
