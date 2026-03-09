from __future__ import annotations

import json

from .config import AppConfig

DOCUMENT_HISTORY_FIELDS = """
id
documentName
binaryDocument
printed
printerName
documentType
""".strip()


def build_unprinted_documents_query_text(config: AppConfig) -> str:
    advanced_filters = [
        "{ filter: { field: { printerName: null }, searchType: DIFFERENT } }",
        '{ filter: { field: { printerName: "" }, searchType: DIFFERENT } }',
    ]

    allow_list = _graphql_list(config.runtime.printer_allow_list)
    if allow_list is not None:
        advanced_filters.append(
            f"{{ filter: {{ field: {{ printerName: {allow_list} }}, searchType: EQUAL }} }}",
        )

    exclude_list = _graphql_list(config.runtime.printer_exclude_list)
    if exclude_list is not None:
        advanced_filters.append(
            f"{{ filter: {{ field: {{ printerName: {exclude_list} }}, searchType: DIFFERENT }} }}",
        )

    return f"""
    query {{
        documentHistories(
            orderBy: {{ field: id, ascending: true }}
            filters: {{ printed: false }}
            page: 1
            itemsPerPage: 10000
            advancedFilters: [
                {' '.join(advanced_filters)}
            ]
        ) {{
            results {{
                {DOCUMENT_HISTORY_FIELDS}
            }}
        }}
    }}
    """.strip()


def build_document_subscription_text(config: AppConfig, token: str) -> str:
    arguments = [
        f'auth: {{ token: {json.dumps(f"Bearer {token}")}, keepAlive: {config.runtime.force_read_delay} }}',
    ]

    allow_list = _graphql_list(config.runtime.printer_allow_list)
    if allow_list is not None:
        arguments.append(f"printers: {allow_list}")

    exclude_list = _graphql_list(config.runtime.printer_exclude_list)
    if exclude_list is not None:
        arguments.append(f"excludedPrinters: {exclude_list}")

    return f"""
    subscription documentPrintings {{
        documentPrintings(
            {' '.join(arguments)}
        ) {{
            keepAlive
            documentHistory {{
                {DOCUMENT_HISTORY_FIELDS}
            }}
        }}
    }}
    """.strip()


def _graphql_list(values: frozenset[str] | None) -> str | None:
    if values is None:
        return None
    normalized_values = sorted(value for value in values if value)
    if not normalized_values:
        return None
    return json.dumps(normalized_values)
