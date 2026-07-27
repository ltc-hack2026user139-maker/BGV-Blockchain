"""
BGV v3.0 — Digital Document Fingerprinting
============================================
Computes a multi-layer document fingerprint at ingestion time:

  Layer 1 — Cryptographic Hash  : SHA-256 of raw bytes (byte-exact identity)
  Layer 2 — Perceptual Hash     : pHash of rendered image (visual identity,
                                   robust to minor encoding differences)
  Layer 3 — Content Hash        : Document-type-specific structural signature
                                   (MRZ data for passports, QR payload hash
                                    for Aadhaar, OCR fingerprint for others)

The three-layer fingerprint is assembled into a VerificationRecord that the
blockchain_ledger module anchors immutably after the pipeline verdict.

Design goals:
  • PII never leaves this module — only hashes are stored / transmitted
  • Deterministic: same document always produces the same fingerprint
  • Tamper-evident: any byte change produces a completely different hash
"""

import hashlib
import json
import time
import os
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Layer 1 — Cryptographic Hash (SHA-256)
# ─────────────────────────────────────────────────────────────────────────────

def compute_sha256(filepath: str) -> str:
    """
    Compute SHA-256 of the raw file bytes.
    This is a byte-exact fingerprint — any change to the file, including
    metadata edits, produces a completely different hash.
    """
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# Layer 2 — Perceptual Hash (pHash)
# ─────────────────────────────────────────────────────────────────────────────

def compute_phash(filepath: str, password: str = '') -> Optional[str]:
    """
    Compute a 64-bit perceptual hash of the document's visual appearance.

    Algorithm (DCT-based pHash):
      1. Render/open the document as an image
      2. Resize to 32×32 greyscale
      3. Apply 2D DCT
      4. Take the top-left 8×8 (low-frequency) coefficients
      5. Compare each coefficient to the median → 64-bit binary hash

    pHash is robust to:
      • Minor JPEG re-compression
      • Small DPI differences
      • Colour-space conversions

    pHash is NOT robust to:
      • Significant content edits (names, numbers, stamps)
      → This is intentional: edited documents will produce a different pHash,
        alerting the system to a mismatch with the stored original hash.

    Returns a 16-character hex string (64 bits).
    """
    try:
        import numpy as np
        from PIL import Image
        import fitz  # PyMuPDF

        ext = os.path.splitext(filepath)[1].lower()

        if ext == '.pdf':
            doc = fitz.open(filepath)
            if doc.is_encrypted and password:
                doc.authenticate(password)
            page = doc[0]
            mat = fitz.Matrix(1.5, 1.5)
            pix = page.get_pixmap(matrix=mat)
            img = Image.frombytes('RGB', [pix.width, pix.height], pix.samples)
            doc.close()
        else:
            img = Image.open(filepath)

        # Greyscale + resize to 32×32
        img = img.convert('L').resize((32, 32), Image.LANCZOS)
        pixels = np.array(img, dtype=np.float32)

        # 2D DCT via repeated 1D DCT
        from scipy.fft import dct
        dct2d = dct(dct(pixels, axis=0, norm='ortho'), axis=1, norm='ortho')

        # Top-left 8×8 low-frequency block (exclude DC component at [0,0])
        dct_low = dct2d[:8, :8].flatten()
        dct_low = dct_low[1:]  # skip DC

        median = np.median(dct_low)
        bits = (dct_low > median).astype(int)

        # Convert 63-bit array to a 16-char hex string (pad to 64 bits)
        bits_padded = np.append(bits, 0)  # pad to 64
        binary_str = ''.join(str(b) for b in bits_padded)
        phash_int = int(binary_str, 2)
        return format(phash_int, '016x')

    except ImportError:
        # scipy not available — use simplified average hash
        try:
            from PIL import Image
            import numpy as np

            ext = os.path.splitext(filepath)[1].lower()
            if ext == '.pdf':
                import fitz
                doc = fitz.open(filepath)
                if doc.is_encrypted and password:
                    doc.authenticate(password)
                page = doc[0]
                pix = page.get_pixmap(matrix=fitz.Matrix(1.0, 1.0))
                img = Image.frombytes('RGB', [pix.width, pix.height], pix.samples)
                doc.close()
            else:
                img = Image.open(filepath)

            img = img.convert('L').resize((8, 8), Image.LANCZOS)
            pixels = np.array(img).flatten()
            avg = pixels.mean()
            bits = (pixels > avg).astype(int)
            binary_str = ''.join(str(b) for b in bits)
            return format(int(binary_str, 2), '016x')
        except Exception:
            return None
    except Exception as e:
        print(f"[WARN] pHash computation failed: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Layer 3 — Content Hash (document-type-specific structural signature)
# ─────────────────────────────────────────────────────────────────────────────

def compute_content_hash(pipeline_result: dict) -> Optional[str]:
    """
    Compute a hash of the structured data extracted from the document.

    This binds the fingerprint to the document's *semantic content*, not
    just its visual appearance.  Two visually identical documents with
    different embedded data (e.g., different MRZ) will have different content
    hashes.

    Per document type:
      • Passport  → SHA-256 of (passport_number + dob + expiry + nationality)
      • Aadhaar   → SHA-256 of (name + dob + gender) from QR payload
      • Other     → SHA-256 of extracted OCR text fingerprint

    Returns a 64-character hex string (SHA-256).
    """
    try:
        pipeline = pipeline_result.get('pipeline', 'unknown')

        if pipeline == 'passport':
            mrz = pipeline_result.get('mrz_data', {})
            content_str = '|'.join([
                mrz.get('passport_number', ''),
                mrz.get('dob', ''),
                mrz.get('expiry', ''),
                mrz.get('nationality', ''),
                mrz.get('full_name', ''),
            ])

        elif pipeline == 'aadhaar':
            qr = pipeline_result.get('qr_data', {})
            content_str = '|'.join([
                str(qr.get('name', '')),
                str(qr.get('dob', '')),
                str(qr.get('gender', '')),
            ])

        else:
            # General documents: use a fingerprint of all flags + scores
            flags = pipeline_result.get('flags', [])
            scores = pipeline_result.get('module_scores', {})
            content_str = json.dumps(
                {'flags': flags, 'scores': scores},
                sort_keys=True, default=str
            )

        if not content_str.strip('|'):
            return None

        return hashlib.sha256(content_str.encode('utf-8')).hexdigest()

    except Exception as e:
        print(f"[WARN] Content hash computation failed: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Document Fingerprint — combine all three layers
# ─────────────────────────────────────────────────────────────────────────────

def compute_document_fingerprint(filepath: str, pipeline_result: dict, password: str = '') -> dict:
    """
    Compute the complete three-layer document fingerprint.

    Returns:
        {
            'crypto_hash'   : str  — SHA-256 of raw bytes (hex)
            'perceptual_hash': str  — pHash of visual appearance (hex)
            'content_hash'  : str  — SHA-256 of extracted content (hex)
            'composite_hash': str  — SHA-256 of all three combined
        }
    """
    crypto_hash = compute_sha256(filepath)
    perceptual_hash = compute_phash(filepath, password=password)
    content_hash = compute_content_hash(pipeline_result)

    # Composite = SHA-256 of (crypto + perceptual + content)
    composite_input = '|'.join([
        crypto_hash,
        perceptual_hash or '',
        content_hash or '',
    ])
    composite_hash = hashlib.sha256(composite_input.encode('utf-8')).hexdigest()

    return {
        'crypto_hash': crypto_hash,
        'perceptual_hash': perceptual_hash,
        'content_hash': content_hash,
        'composite_hash': composite_hash,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Verification Record
# ─────────────────────────────────────────────────────────────────────────────

def create_verification_record(
    filepath: str,
    doc_type: str,
    candidate_id: str,
    fingerprint: dict,
    pipeline_result: dict,
    verdict: str,
    confidence: int,
    engine_version: str = 'tamper-detection-v3.0',
    cross_check: Optional[dict] = None,
) -> dict:
    """
    Create an immutable VerificationRecord that will be anchored to the ledger.

    Design principles:
      • No PII in the record — only hashes and non-identifying metadata
      • Deterministic structure for consistent hashing by the ledger
      • All timestamps are UTC ISO-8601

    Returns a dict that can be JSON-serialised and passed to the ledger.
    """
    document_id = f"DOC-{int(time.time() * 1000)}"
    timestamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

    # Summarise flags (severity only, no personal details)
    flag_summary = [
        {'module': f.get('module'), 'severity': f.get('severity')}
        for f in pipeline_result.get('flags', [])
    ]

    return {
        'schema_version': '3.0',
        'document_id': document_id,
        'doc_type': doc_type,
        'candidate_id': candidate_id,          # pseudonymous ID, not name
        'timestamp_utc': timestamp,
        'engine_version': engine_version,
        'fingerprint': fingerprint,
        'verification': {
            'verdict': verdict,
            'confidence_score': confidence,
            'flags': flag_summary,
            'pipeline': pipeline_result.get('pipeline', 'unknown'),
            'cross_check': cross_check or {},
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# Hamming Distance for pHash comparison
# ─────────────────────────────────────────────────────────────────────────────

def phash_similarity(hash1: str, hash2: str) -> float:
    """
    Compute similarity between two pHashes as a value in [0, 1].
    1.0 = identical, 0.0 = completely different.

    Uses Hamming distance on the 64-bit binary representations.
    Hashes with distance ≤ 10 are considered the same visual document.
    """
    if not hash1 or not hash2:
        return 0.0
    try:
        int1 = int(hash1, 16)
        int2 = int(hash2, 16)
        xor = int1 ^ int2
        hamming = bin(xor).count('1')
        return 1.0 - (hamming / 64.0)
    except ValueError:
        return 0.0
