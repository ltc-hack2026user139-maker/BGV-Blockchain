"""
PyMuPDF (fitz) compatibility shim.

Replaces PyMuPDF with pypdfium2 (page rendering) + pdfplumber (text extraction)
since PyMuPDF is unavailable through the corporate PyPI proxy.

Implements the subset of the fitz API used in this project:
  - fitz.open(filepath) -> Document
  - fitz.Matrix(sx, sy)
  - document[idx] -> Page
  - iter(document) -> Page
  - page.get_text() -> str
  - page.get_pixmap(matrix=...) -> Pixmap
  - page.get_images(full=True) -> list  (always empty; embedded images handled by pikepdf fallback)
  - document.extract_image(xref) -> dict  (always empty)
  - document.close()
  - pixmap.width, pixmap.height, pixmap.samples
"""

from __future__ import annotations

import io
from typing import Iterator

try:
    import pypdfium2 as _pdfium
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "pypdfium2 is required as a PyMuPDF replacement. "
        "Install it with: pip install pypdfium2"
    ) from exc

try:
    import pdfplumber as _pdfplumber
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "pdfplumber is required for PDF text extraction. "
        "Install it with: pip install pdfplumber"
    ) from exc

from PIL import Image as _Image


class Matrix:
    """Minimal fitz.Matrix replacement — holds x/y scale factors."""

    def __init__(self, sx: float, sy: float) -> None:
        self.sx = sx
        self.sy = sy


class Pixmap:
    """Minimal fitz.Pixmap replacement — holds rendered page pixel data."""

    def __init__(self, width: int, height: int, samples: bytes) -> None:
        self.width = width
        self.height = height
        self.samples = samples


class Page:
    """Minimal fitz.Page replacement backed by pypdfium2 + pdfplumber."""

    def __init__(
        self,
        pdfium_page: "_pdfium.PdfPage",
        pdfplumber_page: "object | None",
    ) -> None:
        self._pdfium_page = pdfium_page
        self._pdfplumber_page = pdfplumber_page

    def get_text(self) -> str:
        """Extract plain text from the page via pdfplumber."""
        if self._pdfplumber_page is not None:
            try:
                text = self._pdfplumber_page.extract_text()
                return text or ""
            except Exception:
                return ""
        return ""

    def get_pixmap(self, matrix: "Matrix | None" = None) -> Pixmap:
        """Render the page to a Pixmap at the given scale."""
        scale = 1.0
        if matrix is not None:
            # Use the x scale; assume sx == sy (uniform scaling)
            scale = float(matrix.sx)

        bitmap = self._pdfium_page.render(scale=scale)
        pil_image = bitmap.to_pil()
        if pil_image.mode != "RGB":
            pil_image = pil_image.convert("RGB")

        return Pixmap(pil_image.width, pil_image.height, pil_image.tobytes())

    def get_images(self, full: bool = False) -> list:
        """
        Returns an empty list.

        Embedded image extraction is not implemented in this shim.
        The aadhaar pipeline falls back to pikepdf for embedded images.
        """
        return []


class Document:
    """Minimal fitz.Document replacement backed by pypdfium2 + pdfplumber."""

    def __init__(self, filepath: str) -> None:
        self._filepath = filepath
        self._is_encrypted = False
        try:
            self._pdfium_doc = _pdfium.PdfDocument(filepath)
        except Exception:
            # Likely password-protected — caller must call authenticate()
            self._is_encrypted = True
            self._pdfium_doc = None
        try:
            self._pdfplumber_doc = _pdfplumber.open(filepath)
        except Exception:
            self._pdfplumber_doc = None

    @property
    def is_encrypted(self) -> bool:
        return self._is_encrypted

    def authenticate(self, password: str) -> int:
        """Re-open the document with the given password. Returns 1 on success, 0 on failure."""
        try:
            self._pdfium_doc = _pdfium.PdfDocument(self._filepath, password=password)
            self._is_encrypted = False
            try:
                self._pdfplumber_doc = _pdfplumber.open(self._filepath, password=password)
            except Exception:
                pass
            return 1
        except Exception:
            return 0

    def __len__(self) -> int:
        if self._pdfium_doc is None:
            raise RuntimeError("Document is encrypted — call authenticate() first")
        return len(self._pdfium_doc)

    def __iter__(self) -> Iterator[Page]:
        if self._pdfium_doc is None:
            raise RuntimeError("Document is encrypted — call authenticate() first")
        for i in range(len(self._pdfium_doc)):
            yield self[i]

    def __getitem__(self, idx: int) -> Page:
        if self._pdfium_doc is None:
            raise RuntimeError("Document is encrypted — call authenticate() first")
        pdfium_page = self._pdfium_doc[idx]
        pdfplumber_page = None
        if self._pdfplumber_doc is not None:
            try:
                pdfplumber_page = self._pdfplumber_doc.pages[idx]
            except (IndexError, Exception):
                pass
        return Page(pdfium_page, pdfplumber_page)

    def extract_image(self, xref: int) -> dict:
        """
        Returns an empty dict.

        Embedded image extraction by xref is not implemented in this shim.
        """
        return {}

    def close(self) -> None:
        try:
            self._pdfium_doc.close()
        except Exception:
            pass
        if self._pdfplumber_doc is not None:
            try:
                self._pdfplumber_doc.close()
            except Exception:
                pass


def open(filepath: str) -> Document:  # noqa: A001  (shadows built-in 'open')
    """Open a PDF file and return a Document object — mirrors fitz.open()."""
    return Document(filepath)
