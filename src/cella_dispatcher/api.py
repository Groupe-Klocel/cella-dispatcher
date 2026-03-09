from __future__ import annotations

import asyncio
import logging
import ssl
from collections.abc import AsyncIterator
from typing import Any

import certifi
from gql import Client, gql
from gql.transport.aiohttp import AIOHTTPTransport
from gql.transport.aiohttp import log as aiohttp_transport_logger
from gql.transport.websockets import WebsocketsTransport
from gql.transport.websockets_protocol import log as websocket_transport_logger

from .config import AppConfig
from .models import DocumentJob
from .query_builders import build_document_subscription_text, build_unprinted_documents_query_text

AUTHENTICATE_MUTATION = gql(
    """
    mutation warehouseLogin($username: String!, $password: String!, $warehouseId: ID!) {
        warehouseLogin(username: $username, password: $password, warehouseId: $warehouseId) {
            accessToken
        }
    }
    """,
)

UPDATE_DOCUMENT_STATUS_MUTATION = gql(
    """
    mutation updateDocumentHistory($id: Int!) {
        updateDocumentHistory(id: $id, input: { printed: true }) {
            id
        }
    }
    """,
)


class ApiError(RuntimeError):
    """Raised when the CELLA API interaction fails."""


class CellaApi:
    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._ssl_context = ssl.create_default_context(cafile=certifi.where())
        self._http_lock = asyncio.Lock()
        self._http_client: Client | None = None
        self._http_transport: AIOHTTPTransport | None = None
        self._http_session = None
        self._http_token: str | None = None

    @staticmethod
    def configure_transport_logging(debug: bool) -> None:
        level = logging.INFO if debug else logging.WARNING
        aiohttp_transport_logger.setLevel(level)
        websocket_transport_logger.setLevel(level)

    async def close(self) -> None:
        async with self._http_lock:
            await self._close_http_session()

    async def authenticate(self) -> str:
        transport = AIOHTTPTransport(
            url=self._config.server.api_endpoint_url,
            ssl=self._ssl_context,
            ssl_close_timeout=10,
            timeout=10,
        )
        client = Client(transport=transport, fetch_schema_from_transport=False, execute_timeout=600)
        session = await client.connect_async(reconnecting=True)
        try:
            result = await session.execute(
                AUTHENTICATE_MUTATION,
                variable_values={
                    "username": self._config.server.warehouse_login,
                    "password": self._config.server.warehouse_password,
                    "warehouseId": self._config.server.warehouse_id,
                },
            )
            login_result = result.get("warehouseLogin")
            if not login_result or not login_result.get("accessToken"):
                raise ApiError("Warehouse authentication returned no access token")
            return str(login_result["accessToken"])
        finally:
            await _close_graphql_client(client, transport)

    async def update_document_print_status(self, document_id: int) -> bool:
        try:
            await self._execute(
                UPDATE_DOCUMENT_STATUS_MUTATION,
                variable_values={"id": int(document_id)},
            )
        except Exception:
            logging.exception("Unable to update document %s as printed", document_id)
            return False
        logging.info("Document %s marked as printed", document_id)
        return True

    async def get_unprinted_documents(self) -> list[DocumentJob]:
        query = gql(build_unprinted_documents_query_text(self._config))
        result = await self._execute(query)
        records = result.get("documentHistories", {}).get("results", [])
        documents = [DocumentJob.from_payload(record) for record in records]
        logging.info("Fetched %s unprinted documents", len(documents))
        return documents

    async def subscribe_documents(self) -> AsyncIterator[DocumentJob | None]:
        subscription = gql(build_document_subscription_text(self._config, self._require_token()))
        transport = WebsocketsTransport(
            url=self._config.server.websocket_endpoint_url,
            headers={"authorization": f"Bearer {self._require_token()}"},
            connect_args={"max_size": None},
            ssl=self._ssl_context,
        )
        client = Client(transport=transport, fetch_schema_from_transport=False, execute_timeout=10)
        try:
            async for payload in client.subscribe_async(subscription):
                document_history = payload["documentPrintings"]["documentHistory"]
                if document_history is None:
                    yield None
                    continue
                yield DocumentJob.from_payload(document_history)
        finally:
            await client.close_async()

    async def use_token(self, token: str) -> None:
        async with self._http_lock:
            if self._http_token == token and self._http_session is not None:
                return
            await self._close_http_session()
            self._http_token = token

    async def _execute(self, document, *, variable_values: dict[str, Any] | None = None) -> dict[str, Any]:
        async with self._http_lock:
            session = await self._ensure_http_session()
            try:
                return await session.execute(document, variable_values=variable_values)
            except Exception:
                await self._close_http_session()
                raise

    async def _ensure_http_session(self):
        token = self._require_token()
        if self._http_session is not None and self._http_token == token:
            return self._http_session

        await self._close_http_session()
        self._http_transport = AIOHTTPTransport(
            url=self._config.server.api_endpoint_url,
            headers={"authorization": f"Bearer {token}"},
            ssl=self._ssl_context,
            ssl_close_timeout=10,
            timeout=10,
        )
        self._http_client = Client(
            transport=self._http_transport,
            fetch_schema_from_transport=False,
            execute_timeout=600,
        )
        self._http_session = await self._http_client.connect_async(reconnecting=True)
        self._http_token = token
        logging.info("Connected to CELLA API")
        return self._http_session

    async def _close_http_session(self) -> None:
        if self._http_client is not None and self._http_transport is not None:
            await _close_graphql_client(self._http_client, self._http_transport)
        self._http_client = None
        self._http_transport = None
        self._http_session = None

    def _require_token(self) -> str:
        if not self._http_token:
            raise ApiError("No CELLA access token is configured")
        return self._http_token


async def _close_graphql_client(client: Client, transport: AIOHTTPTransport) -> None:
    try:
        await client.close_async()
    finally:
        try:
            await transport.close()
        except Exception:
            return
