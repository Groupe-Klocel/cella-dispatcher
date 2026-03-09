from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping


class DocumentError(RuntimeError):
    """Raised when the incoming document payload is invalid."""


class UnsupportedDocumentError(DocumentError):
    """Raised when the dispatcher does not know how to print a document."""


class DocumentFormat(str, Enum):
    PDF = "pdf"
    RAW = "raw"
    DOCX = "docx"


@dataclass(slots=True, frozen=True)
class DocumentJob:
    id: int
    document_name: str
    document_type: str
    printer_name: str | None
    binary_document: str
    printed: bool

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "DocumentJob":
        try:
            document_id = int(payload["id"])
            document_name = str(payload["documentName"] or f"document-{document_id}")
            document_type = str(payload["documentType"] or "").strip()
            raw_printer_name = payload.get("printerName")
            printer_name = None if raw_printer_name in (None, "") else str(raw_printer_name).strip()
            binary_document = str(payload["binaryDocument"])
            printed = bool(payload["printed"])
        except KeyError as exc:
            raise DocumentError(f"Missing document payload field: {exc.args[0]}") from exc
        return cls(
            id=document_id,
            document_name=document_name,
            document_type=document_type,
            printer_name=printer_name,
            binary_document=binary_document,
            printed=printed,
        )

    @property
    def safe_filename(self) -> str:
        filename = Path(self.document_name).name
        sanitized = re.sub(r"[^A-Za-z0-9._-]+", "_", filename).strip("._")
        return sanitized or f"document-{self.id}"


@dataclass(slots=True, frozen=True)
class DecodedDocument:
    content: bytes
    format: DocumentFormat
    suffix: str


def decode_document(job: DocumentJob) -> DecodedDocument:
    try:
        content = base64.b64decode(job.binary_document, validate=True)
    except (ValueError, TypeError) as exc:
        raise DocumentError(f"Document {job.id} contains invalid base64 data") from exc

    if not content:
        raise DocumentError(f"Document {job.id} payload is empty")

    normalized_type = job.document_type.lower()
    normalized_suffix = Path(job.document_name).suffix.lower()

    if normalized_type in {"rml", "pdf"} or "pdf" in normalized_type or normalized_suffix == ".pdf":
        if not content.startswith(b"%PDF"):
            raise DocumentError(f"Document {job.id} is marked as PDF but does not contain a PDF payload")
        return DecodedDocument(content=content, format=DocumentFormat.PDF, suffix=".pdf")

    if content.startswith(b"%PDF"):
        return DecodedDocument(content=content, format=DocumentFormat.PDF, suffix=".pdf")

    if normalized_type in {"zpl", "txt"} or normalized_suffix in {".zpl", ".txt"}:
        suffix = normalized_suffix if normalized_suffix in {".zpl", ".txt"} else f".{normalized_type or 'txt'}"
        return DecodedDocument(content=content, format=DocumentFormat.RAW, suffix=suffix)

    if normalized_type == "docx" or normalized_suffix == ".docx" or content.startswith(b"PK\x03\x04"):
        return DecodedDocument(content=content, format=DocumentFormat.DOCX, suffix=".docx")

    raise UnsupportedDocumentError(
        f"Document {job.id} uses unsupported type {job.document_type!r} with filename {job.document_name!r}",
    )
