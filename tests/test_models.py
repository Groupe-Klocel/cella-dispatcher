from __future__ import annotations

import base64
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from cella_dispatcher.models import (
    DocumentFormat,
    DocumentJob,
    UnsupportedDocumentError,
    decode_document,
)


class DocumentModelTests(unittest.TestCase):
    def test_decode_uses_pdf_signature_even_when_type_is_wrong(self) -> None:
        job = DocumentJob(
            id=1,
            document_name="packing-slip.docx",
            document_type="docx",
            printer_name="Printer A",
            binary_document=base64.b64encode(b"%PDF-1.7 test").decode("ascii"),
            printed=False,
        )

        decoded = decode_document(job)

        self.assertEqual(decoded.format, DocumentFormat.PDF)
        self.assertEqual(decoded.suffix, ".pdf")

    def test_decode_supports_raw_zpl_payloads(self) -> None:
        job = DocumentJob(
            id=2,
            document_name="label.zpl",
            document_type="zpl",
            printer_name="Printer A",
            binary_document=base64.b64encode(b"^XA^FO50,50^FDHello^FS^XZ").decode("ascii"),
            printed=False,
        )

        decoded = decode_document(job)

        self.assertEqual(decoded.format, DocumentFormat.RAW)
        self.assertEqual(decoded.suffix, ".zpl")

    def test_decode_rejects_unknown_formats(self) -> None:
        job = DocumentJob(
            id=3,
            document_name="archive.bin",
            document_type="binary",
            printer_name="Printer A",
            binary_document=base64.b64encode(b"not printable").decode("ascii"),
            printed=False,
        )

        with self.assertRaises(UnsupportedDocumentError):
            decode_document(job)


if __name__ == "__main__":
    unittest.main()
