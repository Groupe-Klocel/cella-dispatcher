from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from cella_dispatcher.config import AppConfig, RuntimeConfig, ServerConfig
from cella_dispatcher.query_builders import build_document_subscription_text, build_unprinted_documents_query_text


def make_config(
    *,
    allow_list: frozenset[str] | None,
    exclude_list: frozenset[str],
) -> AppConfig:
    return AppConfig(
        config_path=Path("/tmp/CellaDispatcher.ini"),
        server=ServerConfig(
            api_endpoint_url="https://api.example.com/graphql",
            warehouse_login="warehouse",
            warehouse_password="secret",
            warehouse_id="warehouse-id",
        ),
        runtime=RuntimeConfig(
            connection_retry_seconds=15,
            log_retention_days=7,
            log_directory=Path("/tmp/logs"),
            temp_directory=Path("/tmp/cella"),
            number_of_copies=1,
            debug=False,
            enable_print=True,
            force_read_delay=15,
            printer_allow_list=allow_list,
            printer_exclude_list=exclude_list,
        ),
    )


class QueryBuilderTests(unittest.TestCase):
    def test_unprinted_documents_query_always_excludes_none_and_empty_printers(self) -> None:
        config = make_config(allow_list=None, exclude_list=frozenset())

        query = build_unprinted_documents_query_text(config)

        self.assertIn("{ filter: { field: { printerName: null }, searchType: DIFFERENT } }", query)
        self.assertIn('{ filter: { field: { printerName: "" }, searchType: DIFFERENT } }', query)
        self.assertNotIn("searchType: EQUAL", query)
        self.assertNotIn("excludedPrinters", query)

    def test_unprinted_documents_query_uses_allow_and_exclude_printers(self) -> None:
        config = make_config(
            allow_list=frozenset({"PRINTER2", "PRINTER1"}),
            exclude_list=frozenset({"PRINTER3"}),
        )

        query = build_unprinted_documents_query_text(config)

        self.assertIn('{ filter: { field: { printerName: ["PRINTER1", "PRINTER2"] }, searchType: EQUAL } }', query)
        self.assertIn('{ filter: { field: { printerName: ["PRINTER3"] }, searchType: DIFFERENT } }', query)

    def test_subscription_uses_allow_and_exclude_printers(self) -> None:
        config = make_config(
            allow_list=frozenset({"PRINTER2", "PRINTER1"}),
            exclude_list=frozenset({"PRINTER3"}),
        )

        subscription = build_document_subscription_text(config, "TOKEN")

        self.assertIn('auth: { token: "Bearer TOKEN", keepAlive: 15 }', subscription)
        self.assertIn('printers: ["PRINTER1", "PRINTER2"]', subscription)
        self.assertIn('excludedPrinters: ["PRINTER3"]', subscription)

    def test_subscription_omits_printers_when_allow_list_is_wildcard(self) -> None:
        config = make_config(allow_list=None, exclude_list=frozenset({"PRINTER3"}))

        subscription = build_document_subscription_text(config, "TOKEN")

        self.assertNotIn("printers:", subscription)
        self.assertIn('excludedPrinters: ["PRINTER3"]', subscription)


if __name__ == "__main__":
    unittest.main()
