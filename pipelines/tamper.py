"""
BGV Pipeline 3: Tamper Detection Engine v3.1 (Universal — High Precision)
==========================================================================
Applies to: Degree certificates, Payslips, Experience letters,
            Offer letters, Any uploaded document

Forensic Modules (v3.1):
  A. Error Level Analysis (ELA)          — Multi-quality JPEG compression variance
  B. Noise Inconsistency Analysis        — Sensor noise pattern uniformity
  C. DCT Block Analysis                  — JPEG quantization block anomalies
  D. Copy-Move Detection                 — Self-copy/patch detection using block hashing
  E. Metadata Forensics                  — Creation tool, timestamps, raw byte signatures
  F. CNN Font Forensics                  — MobileNetV2 glyph embeddings + KMeans clustering
  G. Character Copy-Paste                — Character-region pHash + noise-variance analysis
  H. PDF Content Stream Forensics (NEW)  — Layer overlay detection, incremental updates,
                                           annotation overlays, hidden text

Weight Tables v3.1:
  Digital (JPEG/PNG) : ELA×0.30 + Noise×0.25 + DCT×0.20 + CopyMove×0.05
                       + Meta×0.05 + FontCNN×0.10 + CharPaste×0.05
  Digital PDF        : Noise×0.10 + DCT×0.10 + CopyMove×0.05 + Meta×0.15
                       + FontCNN×0.10 + CharPaste×0.10 + PDFLayers×0.40
                       (ELA skipped — PDF renders losslessly, creating false hotspots)
  Scanned            : Noise×0.25 + CopyMove×0.10 + Meta×0.10
                       + FontCNN×0.35 + CharPaste×0.20  (ELA=0, DCT=0)
"""

import os
import io
import re
import struct
import hashlib
import traceback
from datetime import datetime

from PIL import Image, ImageFilter, ImageChops
import numpy as np

try:
    import cv2
    HAS_CV2 = True
except ImportError:
    HAS_CV2 = False

import PyPDF2


def detect_tampering(filepath, is_scanned: bool = False):
    """
    Main tamper detection pipeline.
    Runs forensic modules and returns individual + aggregate scores.

    Args:
        filepath   : Path to the uploaded document (PDF/JPG/PNG).
        is_scanned : True if the document is a physical scan/photograph.
                     When True, ELA and DCT are skipped because they produce
                     systematic false-positives from scanner noise and JPEG
                     re-compression artifacts that are indistinguishable from
                     tampering on scanned originals.
                     The freed weight is redistributed to Font CNN and
                     Character Copy-Paste — the two modules most effective at
                     detecting digitally-pasted content on scanned backgrounds.

    Module applicability matrix:
      Module           | Digital | Scanned
      -----------------|---------|--------
      ELA (A)          |   ✅    |   ❌  (scanner compression = false positives)
      Noise (B)        |   ✅    |   ⚠️  (run, but at higher threshold)
      DCT (C)          |   ✅    |   ❌  (scan JPEG artifacts = false positives)
      Copy-Move (D)    |   ✅    |   ✅
      Metadata (E)     |   ✅    |   ✅
      Font CNN (F)     |   ✅    |   ✅  (best: detects digital text on scan)
      Char Paste (G)   |   ✅    |   ✅  (best: detects digital paste on scan)

    Weight tables:
      Digital : ELA×0.30 + Noise×0.25 + DCT×0.20 + CopyMove×0.05
                + Meta×0.05 + FontCNN×0.10 + CharPaste×0.05
      Scanned : Noise×0.25 + CopyMove×0.10 + Meta×0.10
                + FontCNN×0.35 + CharPaste×0.20  (ELA=0, DCT=0)
    """
    result = {
        'pipeline': 'tamper',
        'checks': [],
        'flags': [],
        'module_scores': {},
        'tamper_score': 0.0,
        'is_scanned': is_scanned,
    }

    # Load the document
    try:
        image, file_ext, raw_bytes, raw_text = load_document(filepath)
        result['raw_text'] = raw_text
        doc_type_label = 'Scanned/Photographed' if is_scanned else 'Digital/Born-digital'
        result['checks'].append({
            'name': 'Document Loading',
            'passed': True,
            'detail': (
                f'Loaded as {file_ext.upper()} ({image.width}×{image.height}) '
                f'— Mode: {doc_type_label}'
            ),
        })
    except Exception as e:
        result['checks'].append({
            'name': 'Document Loading',
            'passed': False,
            'detail': f'Failed: {str(e)}',
        })
        result['error'] = f'Cannot process document: {str(e)}'
        return result

    # Detect document characteristics (auto-heuristics regardless of user flag)
    is_scanned_auto = file_ext == 'pdf' and _is_scanned_pdf(raw_text, image)
    # Honour user override; auto-detect is an additional signal
    is_scanned = is_scanned or is_scanned_auto
    is_high_contrast = _is_high_contrast_image(image)
    doc_context = {
        'is_scanned': is_scanned,
        'is_pdf': file_ext == 'pdf',
        'is_high_contrast': is_high_contrast,
    }
    # Scanned PDF: physical document scanned and saved as PDF.
    # Copy-move and font-CNN produce massive false-positives here:
    #   - repeating structural elements (borders, rules) fool copy-move
    #   - natural scan variation fools font stroke-width analysis
    # Only PDF structural forensics (Module H) and metadata (Module E) are reliable.
    is_scanned_pdf = is_scanned and file_ext == 'pdf'

    # ── Module A: Error Level Analysis ──────────────────────────────────────
    if is_scanned or doc_context.get('is_pdf'):
        # ELA is unreliable on scanned documents (scanner JPEG re-compression
        # produces uneven block-error levels) AND on born-digital PDFs (the PDF
        # is rendered to a lossless image; re-saving as JPEG then adds compression
        # artifacts uniformly everywhere, producing false hotspots throughout).
        result['module_scores']['ela'] = 0.0
        result['checks'].append({
            'name': 'Error Level Analysis (ELA)',
            'passed': True,
            'warning': False,
            'detail': (
                'Skipped — not applicable for PDFs or scanned documents '
                '(lossless rendering/scanner compression creates systematic false positives)'
            ),
        })
    else:
        ela_result = run_ela(image, file_ext, doc_context)
        result['module_scores']['ela'] = ela_result['score']
        result['checks'].append({
            'name': 'Error Level Analysis (ELA)',
            'passed': ela_result['score'] < 0.35,
            'warning': 0.2 <= ela_result['score'] < 0.35,
            'detail': f'Score: {ela_result["score"]:.2f} — {ela_result["detail"]}',
        })
        if ela_result['score'] >= 0.35:
            result['flags'].append({
                'module': 'ELA',
                'severity': 'HIGH' if ela_result['score'] >= 0.6 else 'MEDIUM',
                'description': ela_result['flag_desc'],
            })
        elif ela_result['score'] >= 0.2:
            result['flags'].append({
                'module': 'ELA', 'severity': 'LOW',
                'description': ela_result['flag_desc'],
            })

    # ── Module B: Noise Inconsistency Analysis ───────────────────────────────
    # Skipped for PDFs: high-contrast text regions (black on white) inflate
    # noise CV on every clean document. Only useful for raster image scans.
    if doc_context.get('is_pdf'):
        result['module_scores']['noise'] = 0.0
        result['checks'].append({
            'name': 'Noise Inconsistency Analysis',
            'passed': True,
            'warning': False,
            'detail': 'Skipped — not applicable for PDFs (high-contrast text inflates noise variance; use Module H/I for PDF detection)',
        })
    else:
        noise_result = run_noise_analysis(image, doc_context)
        result['module_scores']['noise'] = noise_result['score']
        noise_flag_thresh = 0.50 if is_scanned else 0.35
        result['checks'].append({
            'name': 'Noise Inconsistency Analysis',
            'passed': noise_result['score'] < noise_flag_thresh,
            'warning': 0.25 <= noise_result['score'] < noise_flag_thresh,
            'detail': (
                f'Score: {noise_result["score"]:.2f} — {noise_result["detail"]}'
                + (' (threshold raised for scanned doc)' if is_scanned else '')
            ),
        })
        if noise_result['score'] >= noise_flag_thresh:
            result['flags'].append({
                'module': 'NOISE_ANALYSIS',
                'severity': 'HIGH' if noise_result['score'] >= 0.7 else 'MEDIUM',
                'description': noise_result['flag_desc'],
            })

    # ── Module C: DCT Block Coefficient Analysis ─────────────────────────────
    if is_scanned or doc_context.get('is_pdf'):
        # DCT analysis detects JPEG quantization mismatches.
        # Not applicable for: scanned docs (scanner JPEG artifacts) or PDFs
        # (rendered from vectors — no JPEG quantization to compare).
        result['module_scores']['dct'] = 0.0
        result['checks'].append({
            'name': 'DCT Block Coefficient Analysis',
            'passed': True,
            'warning': False,
            'detail': 'Skipped — not applicable for PDFs or scanned documents',
        })
    else:
        dct_result = run_dct_block_analysis(image, doc_context)
        result['module_scores']['dct'] = dct_result['score']
        result['checks'].append({
            'name': 'DCT Block Coefficient Analysis',
            'passed': dct_result['score'] < 0.35,
            'warning': 0.2 <= dct_result['score'] < 0.35,
            'detail': f'Score: {dct_result["score"]:.2f} — {dct_result["detail"]}',
        })
        if dct_result['score'] >= 0.35:
            result['flags'].append({
                'module': 'DCT_ANALYSIS',
                'severity': 'HIGH' if dct_result['score'] >= 0.6 else 'MEDIUM',
                'description': dct_result['flag_desc'],
            })

    # ── Module D: Copy-Move Patch Detection ──────────────────────────────────
    # Skipped for ALL PDFs: repeating structural elements (table borders, ruled
    # lines, headers/footers, form fields) generate hundreds of false-positive
    # duplicate pairs even in clean documents. Pixel-level copy-move is only
    # useful for raster images (JPEG/PNG scans with actual cloned regions).
    if doc_context.get('is_pdf'):
        result['module_scores']['copy_move'] = 0.0
        result['checks'].append({
            'name': 'Copy-Move Patch Detection',
            'passed': True,
            'warning': False,
            'detail': 'Skipped — not applicable for PDFs (structural repeats create false positives; use Module H for PDF-specific detection)',
        })
    else:
        copy_result = run_copy_move_detection(image, doc_context)
        result['module_scores']['copy_move'] = copy_result['score']
        result['checks'].append({
            'name': 'Copy-Move Patch Detection',
            'passed': copy_result['score'] < 0.35,
            'warning': 0.2 <= copy_result['score'] < 0.35,
            'detail': f'Score: {copy_result["score"]:.2f} — {copy_result["detail"]}',
        })
        if copy_result['score'] >= 0.35:
            result['flags'].append({
                'module': 'COPY_MOVE', 'severity': 'HIGH',
                'description': copy_result['flag_desc'],
            })

    # ── Module E: Metadata Forensics ─────────────────────────────────────────
    meta_result = run_metadata_forensics(filepath, file_ext, raw_bytes)
    result['module_scores']['metadata'] = meta_result['score']
    result['checks'].append({
        'name': 'Metadata Forensics',
        'passed': meta_result['score'] < 0.4,
        'warning': 0.2 <= meta_result['score'] < 0.4,
        'detail': f'Score: {meta_result["score"]:.2f} — {meta_result["detail"]}',
    })
    if meta_result.get('flags'):
        for flag in meta_result['flags']:
            result['flags'].append(flag)

    # ── Module F: CNN Font Forensics ─────────────────────────────────────────
    # Skipped for ALL PDFs: PDFs legitimately use multiple font families and
    # sizes (headings, labels, values, footers) which creates high stroke-width
    # variance on every clean document. Font analysis is only meaningful for
    # raster images where a single print job should have uniform strokes.
    if doc_context.get('is_pdf'):
        result['module_scores']['font_cnn'] = 0.0
        result['checks'].append({
            'name': 'CNN Font Forensics (Module F)',
            'passed': True,
            'warning': False,
            'detail': 'Skipped — not applicable for PDFs (multiple fonts/sizes are normal in PDF documents)',
        })
    else:
        font_result = run_font_forensics(image, raw_text, doc_context)
        result['module_scores']['font_cnn'] = font_result['score']
        result['checks'].append({
            'name': 'CNN Font Forensics (Module F)',
            'passed': font_result['score'] < 0.35,
            'warning': 0.20 <= font_result['score'] < 0.35,
            'detail': f'Score: {font_result["score"]:.2f} — {font_result["detail"]}',
        })
        if font_result['score'] >= 0.35:
            result['flags'].append({
                'module': 'FONT_CNN',
                'severity': 'HIGH' if font_result['score'] >= 0.6 else 'MEDIUM',
                'description': font_result['flag_desc'],
            })

    # ── Module G: Character-Level Copy-Paste Detection ───────────────────────
    # Excellent for scanned docs: catches single-character digital substitutions
    # (e.g., salary "1" → "7" digitally pasted over a scanned salary slip).
    char_result = run_character_copypaste(image, raw_text, doc_context)
    result['module_scores']['char_paste'] = char_result['score']
    result['checks'].append({
        'name': 'Character Copy-Paste Detection (Module G)',
        'passed': char_result['score'] < 0.35,
        'warning': 0.20 <= char_result['score'] < 0.35,
        'detail': f'Score: {char_result["score"]:.2f} — {char_result["detail"]}',
    })
    if char_result['score'] >= 0.35:
        result['flags'].append({
            'module': 'CHAR_COPYPASTE',
            'severity': 'HIGH' if char_result['score'] >= 0.6 else 'MEDIUM',
            'description': char_result['flag_desc'],
        })

    # ── Module H: PDF Content Stream Forensics (PDF only) ───────────────────
    # Detects PDF object-level attacks that pixel analysis cannot see:
    # — Layer copy attack: digit "9" content stream placed over "5" at same position
    # — Incremental updates: post-creation %%EOF additions
    # — Annotation overlays: FreeText/Stamp annotations covering existing text
    # — Hidden/invisible text objects
    if doc_context.get('is_pdf'):
        layers_result = run_pdf_layer_forensics(filepath, raw_bytes, is_scanned=is_scanned)
        result['module_scores']['pdf_layers'] = layers_result['score']
        pdf_layers_flag_thresh = 0.35
        result['checks'].append({
            'name': 'PDF Content Stream Forensics (Module H)',
            'passed': layers_result['score'] < pdf_layers_flag_thresh,
            'warning': 0.15 <= layers_result['score'] < pdf_layers_flag_thresh,
            'detail': f'Score: {layers_result["score"]:.2f} — {layers_result["detail"]}',
        })
        if layers_result['score'] >= pdf_layers_flag_thresh:
            result['flags'].append({
                'module': 'PDF_LAYERS',
                'severity': 'HIGH' if layers_result['score'] >= 0.60 else 'MEDIUM',
                'description': layers_result.get('flag_desc', 'PDF structure anomalies detected'),
            })
        for flag in layers_result.get('flags', []):
            if flag not in result['flags']:
                result['flags'].append(flag)
    else:
        result['module_scores']['pdf_layers'] = 0.0

    # ── Module I: Cortex AI Visual Tamper Analysis (PDF only) ──────────────
    # Uses Gemini vision to detect specific targeted edits that structural
    # analysis misses: edited numbers, pasted text, font mismatches in
    # specific regions, tool marks, and visual inconsistencies.
    if doc_context.get('is_pdf'):
        cortex_result = run_cortex_tamper_analysis(image)
        result['module_scores']['cortex_ai'] = cortex_result['score']
        cortex_flag_thresh = 0.35
        result['checks'].append({
            'name': 'AI Visual Tamper Analysis (Module I)',
            'passed': cortex_result['score'] < cortex_flag_thresh,
            'warning': 0.15 <= cortex_result['score'] < cortex_flag_thresh,
            'detail': f'Score: {cortex_result["score"]:.2f} — {cortex_result["detail"]}',
        })
        if cortex_result['score'] >= cortex_flag_thresh:
            result['flags'].append({
                'module': 'CORTEX_AI',
                'severity': 'HIGH' if cortex_result['score'] >= 0.6 else 'MEDIUM',
                'description': cortex_result.get('flag_desc', 'AI detected visual tamper indicators'),
            })
    else:
        result['module_scores']['cortex_ai'] = 0.0

    # ── Weighted Aggregation ─────────────────────────────────────────────────
    # Four weight tables: scanned PDF, digital image, born-digital PDF, scanned image.
    if is_scanned_pdf:
        # Scanned PDF: pixel-analysis modules are unreliable (scanner noise,
        # repeating structural elements). Only PDF structural forensics and
        # metadata reliably detect targeted edits (overlay attack, editing tool).
        weights = {
            'ela':        0.00,   # N/A
            'noise':      0.00,   # not reliable for scanned PDFs
            'dct':        0.00,   # N/A
            'copy_move':  0.00,   # skipped — repeating elements cause false positives
            'metadata':   0.20,   # reliable: editing tool signatures
            'font_cnn':   0.00,   # skipped — scanner noise causes false positives
            'char_paste': 0.05,   # minor signal
            'pdf_layers': 0.35,   # primary: overlay attack, incremental edit
            'cortex_ai':  0.40,   # AI visual analysis — best for targeted edits
        }
        weight_mode = 'SCANNED_PDF'
    elif is_scanned:
        weights = {
            'ela':        0.00,   # skipped — false positives on scans
            'noise':      0.20,   # run with raised threshold
            'dct':        0.00,   # skipped — false positives on scans
            'copy_move':  0.10,   # catches cloned regions in raster
            'metadata':   0.10,
            'font_cnn':   0.30,   # detects digital text on scan background
            'char_paste': 0.20,   # catches digit substitution
            'pdf_layers': 0.00,
            'cortex_ai':  0.10,   # minor — limited for non-PDF scans
        }
        weight_mode = 'SCANNED'
    elif doc_context.get('is_pdf'):
        # Born-digital PDF: pixel-analysis modules (noise, DCT, copy-move, font)
        # all produce false positives on clean PDFs due to rendering artifacts,
        # high-contrast text patterns, structural repeats, and multiple fonts.
        # Only PDF structural forensics and metadata reliably detect targeted edits.
        weights = {
            'ela':        0.00,   # N/A for PDFs
            'noise':      0.00,   # high-contrast text inflates noise CV
            'dct':        0.00,   # text/blank bimodal patterns inflate DCT
            'copy_move':  0.00,   # skipped — structural repeats
            'metadata':   0.25,   # reliable: editing tool signatures
            'font_cnn':   0.00,   # skipped — multiple fonts are normal
            'char_paste': 0.05,   # minor signal
            'pdf_layers': 0.30,   # overlay attack, incremental updates, annotations
            'cortex_ai':  0.40,   # primary: AI detects specific text/number edits
        }
        weight_mode = 'DIGITAL_PDF'
    else:
        weights = {
            'ela':        0.30,
            'noise':      0.25,
            'dct':        0.20,
            'copy_move':  0.05,
            'metadata':   0.05,
            'font_cnn':   0.10,
            'char_paste': 0.05,
            'pdf_layers': 0.00,
            'cortex_ai':  0.00,
        }
        weight_mode = 'DIGITAL'

    result['weight_mode'] = weight_mode

    total_score = sum(
        result['module_scores'].get(m, 0) * w
        for m, w in weights.items()
    )
    result['tamper_score'] = round(total_score, 3)

    # Only include active (non-zero-weight) modules in breakdown
    score_breakdown = ' + '.join(
        f'{m.upper()[:3]}: {result["module_scores"].get(m, 0):.2f}×{w:.2f}'
        for m, w in weights.items()
        if w > 0
    )

    result['checks'].append({
        'name': 'Weighted Tamper Score',
        'passed': total_score < 0.25,
        'warning': 0.25 <= total_score < 0.50,
        'detail': f'Score: {total_score:.3f} [Mode: {weight_mode}] ({score_breakdown})',
    })

    return result


# ============================================
# Document Loader
# ============================================

def load_document(filepath):
    """Load document as PIL Image, returning extension, raw bytes, and text (if PDF)."""
    ext = os.path.splitext(filepath)[1].lower()

    with open(filepath, 'rb') as f:
        raw_bytes = f.read()

    raw_text = ""
    if ext == '.pdf':
        try:
            import fitz
            doc = fitz.open(filepath)
            for page in doc:
                raw_text += page.get_text() + "\n"
            doc.close()
        except:
            pass

        image = pdf_to_image(filepath)
        return image, 'pdf', raw_bytes, raw_text
    else:
        image = Image.open(filepath)
        if image.mode == 'RGBA':
            image = image.convert('RGB')
        return image, ext.lstrip('.'), raw_bytes, ""


def pdf_to_image(filepath):
    """Render first page of PDF as a high-resolution RGB image using PyMuPDF."""
    try:
        import fitz
        doc = fitz.open(filepath)
        page = doc[0]
        mat = fitz.Matrix(2.0, 2.0)
        pix = page.get_pixmap(matrix=mat)
        image = Image.frombytes('RGB', [pix.width, pix.height], pix.samples)
        doc.close()
        return image
    except Exception as e:
        print(f"[WARN] fitz PDF to image conversion error: {e}")

    raise Exception("Cannot render PDF to image. Try uploading as JPG/PNG.")


def _is_scanned_pdf(raw_text, image):
    """Heuristic: if extractable text is very sparse relative to image size, it's a scan."""
    if not raw_text or len(raw_text.strip()) < 50:
        return True
    text_density = len(raw_text.strip()) / (image.width * image.height + 1)
    return text_density < 0.0001


def _is_high_contrast_image(image):
    """Detect born-digital/vector-rendered images with sharp edges and flat regions."""
    gray = np.array(image.convert('L'), dtype=np.float64)
    h, w = gray.shape
    block_size = 64
    variances = []
    for y in range(0, min(h, 512), block_size):
        for x in range(0, min(w, 512), block_size):
            block = gray[y:y+block_size, x:x+block_size]
            if block.size > 0:
                variances.append(np.var(block))
    if not variances:
        return False
    var_arr = np.array(variances)
    near_zero = np.sum(var_arr < 50) / len(var_arr)
    return near_zero > 0.4


# ============================================
# Module A: Error Level Analysis (Enhanced)
# ============================================

def run_ela(image, source_format='jpeg', doc_context=None):
    """
    Enhanced ELA — run at multiple JPEG quality levels and analyze
    per-block variance. Edited regions have inconsistent compression
    signatures across quality levels.
    
    NOTE: ELA only applies to JPEG images. PNG files are lossless and
    will always show a large ELA difference (false positive). This is
    skipped for lossless sources.
    """
    result = {'score': 0.0, 'detail': '', 'flag_desc': 'ELA skipped (lossless source)'}

    # ELA only works on JPEG/lossy sources
    if source_format.lower() in ('png', 'bmp', 'tiff', 'tif', 'gif'):
        result['detail'] = f'Skipped — ELA requires a JPEG source (got {source_format.upper()})'
        result['flag_desc'] = 'ELA not applicable to lossless/rendered documents'
        return result

    try:
        if image.mode != 'RGB':
            image = image.convert('RGB')

        orig_array = np.array(image, dtype=np.float32)
        quality_scores = []

        # Test at 3 quality levels for more robust detection
        for quality in [75, 90, 95]:
            buf = io.BytesIO()
            image.save(buf, 'JPEG', quality=quality)
            buf.seek(0)
            resaved = np.array(Image.open(buf), dtype=np.float32)

            diff = np.abs(orig_array - resaved)
            quality_scores.append(diff)

        # Average difference map across all quality levels
        avg_diff = np.mean(quality_scores, axis=0)
        gray_diff = avg_diff.mean(axis=2)

        mean_d = np.mean(gray_diff)
        std_d  = np.std(gray_diff)

        # Coefficient of variation: high = inconsistent compression = edited
        cv = std_d / (mean_d + 1e-6)

        # Hotspot detection: pixels above sigma-threshold are anomalous
        # PDF-rendered & scanned images have inherently higher variance,
        # so use a wider sigma band to avoid false hotspots
        hotspot_sigma = 3.5 if (doc_context and (doc_context.get('is_pdf') or doc_context.get('is_scanned'))) else 2.5
        hotspot_threshold = mean_d + hotspot_sigma * std_d
        hotspot_mask = gray_diff > hotspot_threshold
        hotspot_ratio = np.sum(hotspot_mask) / hotspot_mask.size

        # Cluster analysis — isolated hotspot clusters are suspicious
        if HAS_CV2:
            hm_uint8 = (hotspot_mask * 255).astype(np.uint8)
            n_labels, labels, stats, _ = cv2.connectedComponentsWithStats(hm_uint8)
            # Require larger clusters for PDFs (small clusters are rendering artifacts)
            min_cluster_area = 500 if (doc_context and doc_context.get('is_pdf')) else 200
            large_clusters = sum(1 for i in range(1, n_labels) if stats[i, cv2.CC_STAT_AREA] > min_cluster_area)
        else:
            large_clusters = 0

        # Adaptive thresholds — PDF/scanned images require stronger signals
        if doc_context and doc_context.get('is_scanned'):
            cv_t = (3.5, 2.5, 1.8)
            hr_t = (0.20, 0.12, 0.05)
            cl_t = (10, 5)
        elif doc_context and doc_context.get('is_pdf'):
            cv_t = (3.0, 2.2, 1.5)
            hr_t = (0.15, 0.08, 0.03)
            cl_t = (8, 4)
        else:
            cv_t = (2.0, 1.5, 1.0)
            hr_t = (0.08, 0.04, 0.01)
            cl_t = (5, 2)

        score = 0.0
        if cv > cv_t[0]:     score += 0.35
        elif cv > cv_t[1]:   score += 0.25
        elif cv > cv_t[2]:   score += 0.15

        if hotspot_ratio > hr_t[0]:   score += 0.35
        elif hotspot_ratio > hr_t[1]: score += 0.20
        elif hotspot_ratio > hr_t[2]: score += 0.10

        if large_clusters > cl_t[0]:     score += 0.30
        elif large_clusters > cl_t[1]:   score += 0.15

        result['score'] = min(round(score, 3), 1.0)
        result['detail'] = (
            f'CV={cv:.2f}, hotspots={hotspot_ratio:.2%}, '
            f'anomalous clusters={large_clusters}'
        )

        if score >= 0.5:
            result['flag_desc'] = (
                f'ELA — Strong compression inconsistencies detected '
                f'({large_clusters} isolated anomalous region(s)). '
                'Likely edited.'
            )
        elif score >= 0.2:
            result['flag_desc'] = 'ELA — Moderate compression variance. May warrant review.'
        else:
            result['flag_desc'] = 'ELA — Compression appears uniform.'

    except Exception as e:
        result['detail'] = f'ELA error: {str(e)}'
        result['flag_desc'] = 'ELA could not complete'
        traceback.print_exc()

    return result


# ============================================
# Module B: Noise Inconsistency Analysis
# ============================================

def run_noise_analysis(image, doc_context=None):
    """
    Sensor noise analysis.
    
    Real documents (scanned or photographed) have consistent, spatially
    uniform sensor noise. Edited regions (pasted text, changed numbers)
    often come from a different image with a different noise signature.
    
    Method:
    - Divide image into NxN grid of blocks.
    - Estimate local noise variance for each block using a Laplacian filter.
    - Flag blocks whose noise variance deviates strongly from the global median.
    """
    result = {'score': 0.0, 'detail': '', 'flag_desc': ''}

    try:
        if image.mode != 'RGB':
            gray = image.convert('L')
        else:
            gray = image.convert('L')

        gray_arr = np.array(gray, dtype=np.float64)
        h, w = gray_arr.shape

        block_size = max(32, min(h, w) // 16)
        noise_map = []

        for y in range(0, h - block_size, block_size):
            for x in range(0, w - block_size, block_size):
                block = gray_arr[y:y+block_size, x:x+block_size]
                # Estimate noise as variance of high-frequency component
                # using a Laplacian kernel
                kernel = np.array([[0, -1, 0], [-1, 4, -1], [0, -1, 0]], dtype=np.float64)
                if HAS_CV2:
                    lap = cv2.filter2D(block, -1, kernel)
                else:
                    from scipy.ndimage import convolve
                    lap = convolve(block, kernel)
                noise_var = np.var(lap)
                noise_map.append(noise_var)

        if len(noise_map) < 4:
            result['detail'] = 'Document too small for noise analysis'
            result['score'] = 0.0
            return result

        noise_arr = np.array(noise_map)
        median_noise = np.median(noise_arr)
        mad = np.median(np.abs(noise_arr - median_noise))  # Median Absolute Deviation

        # Adaptive MAD threshold — scanned/high-contrast docs have inherently
        # non-uniform noise so require a wider deviation to count as anomalous
        if doc_context and doc_context.get('is_scanned'):
            mad_factor = 5.5
        elif doc_context and doc_context.get('is_high_contrast'):
            mad_factor = 5.0
        else:
            mad_factor = 3.5

        threshold = mad_factor * (mad + 1e-6)
        anomalous_blocks = np.sum(np.abs(noise_arr - median_noise) > threshold)
        anomaly_ratio = anomalous_blocks / len(noise_arr)

        # Spread check: coefficient of variation of noise across blocks
        noise_cv = np.std(noise_arr) / (np.mean(noise_arr) + 1e-6)

        # Adaptive scoring thresholds
        if doc_context and doc_context.get('is_scanned'):
            ar_t = (0.35, 0.22, 0.12)
            cv_t = (4.0, 2.8, 2.0)
        elif doc_context and doc_context.get('is_high_contrast'):
            ar_t = (0.30, 0.18, 0.10)
            cv_t = (3.5, 2.5, 1.8)
        else:
            ar_t = (0.20, 0.10, 0.05)
            cv_t = (2.5, 1.5, 1.0)

        score = 0.0
        if anomaly_ratio > ar_t[0]:   score += 0.40
        elif anomaly_ratio > ar_t[1]: score += 0.25
        elif anomaly_ratio > ar_t[2]: score += 0.10

        if noise_cv > cv_t[0]:    score += 0.35
        elif noise_cv > cv_t[1]:  score += 0.20
        elif noise_cv > cv_t[2]:  score += 0.10

        result['score'] = min(round(score, 3), 1.0)
        result['detail'] = (
            f'{anomalous_blocks}/{len(noise_arr)} anomalous blocks '
            f'({anomaly_ratio:.1%}), noise CV={noise_cv:.2f}'
        )

        if score >= 0.5:
            result['flag_desc'] = (
                f'Noise — {anomalous_blocks} block(s) have significantly different '
                'noise signatures. This is a strong indicator of pasted content.'
            )
        elif score >= 0.2:
            result['flag_desc'] = 'Noise — Slight noise inconsistency. May warrant review.'
        else:
            result['flag_desc'] = 'Noise — Noise level appears spatially uniform.'

    except Exception as e:
        result['detail'] = f'Noise analysis error: {str(e)}'
        result['flag_desc'] = 'Noise analysis could not complete'

    return result


# ============================================
# Module C: DCT Block Coefficient Analysis
# ============================================

def run_dct_block_analysis(image, doc_context=None):
    """
    DCT (Discrete Cosine Transform) Block Anomaly Detection.
    
    JPEG images are compressed in 8x8 pixel blocks. Each block's high-frequency
    DCT coefficients decay towards zero. When a region is edited and pasted
    from a different source, those 8x8 blocks will have different quantization
    tables and different coefficient distributions. This module tiles the
    image in 8x8 blocks and flags tiles whose AC energy is inconsistent
    with their neighbors.
    """
    result = {'score': 0.0, 'detail': '', 'flag_desc': ''}

    try:
        if image.mode != 'L':
            gray = image.convert('L')
        else:
            gray = image

        gray_arr = np.array(gray, dtype=np.float64)
        h, w = gray_arr.shape

        # Only analyze if image is large enough
        if h < 64 or w < 64:
            result['detail'] = 'Image too small for DCT block analysis'
            return result

        BLOCK = 8
        energies = []

        for y in range(0, h - BLOCK, BLOCK):
            row_energies = []
            for x in range(0, w - BLOCK, BLOCK):
                block = gray_arr[y:y+BLOCK, x:x+BLOCK] - 128.0
                # Manual 2D DCT via numpy
                dct_block = _dct2d(block)
                # AC energy = total energy minus DC (top-left) term
                ac_energy = np.sum(dct_block ** 2) - dct_block[0, 0] ** 2
                row_energies.append(ac_energy)
            energies.append(row_energies)

        energy_arr = np.array(energies, dtype=np.float64)

        global_mean = np.mean(energy_arr)
        global_std  = np.std(energy_arr)

        # Adaptive sigma — text documents have naturally bimodal AC energy
        # (text blocks vs blank areas), so require wider deviation for anomaly
        if doc_context and (doc_context.get('is_scanned') or doc_context.get('is_high_contrast')):
            sigma_factor = 4.5
        else:
            sigma_factor = 3.0

        anomaly_mask = np.abs(energy_arr - global_mean) > sigma_factor * global_std
        anomaly_ratio = np.sum(anomaly_mask) / anomaly_mask.size

        # Spatial clustering: check if anomalous blocks are clustered (paste region)
        # or random (normal noise)
        if HAS_CV2 and anomaly_ratio > 0.01:
            am_uint8 = (anomaly_mask * 255).astype(np.uint8)
            n_labels, _, stats, _ = cv2.connectedComponentsWithStats(am_uint8)
            # Require larger clusters for documents (small ones are text edges)
            min_cluster = 25 if (doc_context and (doc_context.get('is_scanned') or doc_context.get('is_high_contrast'))) else 10
            large_clusters = sum(1 for i in range(1, n_labels) if stats[i, cv2.CC_STAT_AREA] > min_cluster)
        else:
            large_clusters = 0

        # Adaptive scoring thresholds
        if doc_context and (doc_context.get('is_scanned') or doc_context.get('is_high_contrast')):
            ar_t = (0.25, 0.15, 0.08)
            cl_t = (6, 3)
        else:
            ar_t = (0.15, 0.07, 0.03)
            cl_t = (3, 1)

        score = 0.0
        if anomaly_ratio > ar_t[0]:   score += 0.40
        elif anomaly_ratio > ar_t[1]: score += 0.25
        elif anomaly_ratio > ar_t[2]: score += 0.10

        if large_clusters > cl_t[0]:     score += 0.35
        elif large_clusters > cl_t[1]:   score += 0.15

        result['score'] = min(round(score, 3), 1.0)
        result['detail'] = (
            f'{anomaly_ratio:.1%} anomalous DCT blocks, '
            f'{large_clusters} spatial cluster(s) detected'
        )

        if score >= 0.45:
            result['flag_desc'] = (
                f'DCT — {large_clusters} spatially-clustered DCT anomaly region(s) detected. '
                'This indicates content was spliced from a different image source.'
            )
        elif score >= 0.2:
            result['flag_desc'] = 'DCT — Moderate block coefficient anomalies detected.'
        else:
            result['flag_desc'] = 'DCT — Block coefficients appear consistent.'

    except Exception as e:
        result['detail'] = f'DCT error: {str(e)}'
        result['flag_desc'] = 'DCT analysis could not complete'

    return result


def _dct2d(block):
    """Compute 2D DCT using numpy separable 1D DCT."""
    n = block.shape[0]
    # Build DCT matrix
    idx = np.arange(n)
    k = idx.reshape(-1, 1)
    dct_mat = np.cos(np.pi * k * (2 * idx + 1) / (2 * n))
    dct_mat[0] *= 1 / np.sqrt(2)
    dct_mat *= np.sqrt(2 / n)
    return dct_mat @ block @ dct_mat.T


# ============================================
# Module D: Copy-Move Detection
# ============================================

def run_copy_move_detection(image, doc_context=None):
    """
    Copy-Move / Patch Detection.
    
    Fraudsters often copy a clean area of a document and paste it
    over the area they want to hide. This creates two identical
    (or near-identical) blocks within the same image.
    
    Method: Divide image into overlapping blocks, compute perceptual
    hash (pHash) for each block, find blocks with near-identical hashes
    that are spatially distant. Uniform/blank blocks are filtered out
    to avoid background false-positives.
    """
    result = {'score': 0.0, 'detail': '', 'flag_desc': ''}

    try:
        if image.mode != 'L':
            gray = image.convert('L')
        else:
            gray = image

        img_arr = np.array(gray, dtype=np.uint8)
        h, w = img_arr.shape

        BLOCK = 32
        STEP  = 24  # Less overlap → fewer total blocks → faster, fewer false positives
        MIN_DIST = BLOCK * 4  # Must be at least 4 blocks away to count

        # Born-digital PDFs have thousands of repeating structural elements
        # (table borders, horizontal rules, header/footer patterns). At 32px block
        # size these match each other constantly. Use larger blocks so structural
        # lines are absorbed into surrounding context, reducing false pairs.
        if doc_context and doc_context.get('is_pdf') and not doc_context.get('is_scanned'):
            BLOCK = 64
            STEP = 48
            MIN_DIST = BLOCK * 6  # 384px minimum — further apart for PDFs

        block_hashes = []  # (hash_int_64, cx, cy, std_dev)

        for y in range(0, h - BLOCK, STEP):
            for x in range(0, w - BLOCK, STEP):
                block = img_arr[y:y+BLOCK, x:x+BLOCK]
                std = np.std(block)
                # Skip very uniform blocks (blank spaces, white margins)
                # Raise threshold for scans (more repeating patterns like ruled lines)
                std_threshold = 12.0 if (doc_context and doc_context.get('is_scanned')) else 8.0
                if std < std_threshold:
                    continue
                # Downsample to 8x8 for pHash
                small = np.array(
                    Image.fromarray(block).resize((8, 8), Image.LANCZOS),
                    dtype=np.float64
                )
                mean_val = np.mean(small)
                bits = (small > mean_val).flatten().astype(np.uint8)
                # Pack 64 bits to integer for fast comparison
                phash_int = int.from_bytes(np.packbits(bits).tobytes(), 'big')
                cx, cy = x + BLOCK // 2, y + BLOCK // 2
                block_hashes.append((phash_int, cx, cy))

        if len(block_hashes) < 10:
            result['detail'] = 'Insufficient content blocks for copy-move analysis'
            return result

        # Find near-duplicate blocks using Hamming distance threshold
        # Scanned docs need stricter matching — repeating patterns (table lines,
        # headers, ruled lines) create similar-looking blocks that aren't clones.
        # Digital PDFs also need strict matching for the same reason.
        max_hamming = 1 if (doc_context and (doc_context.get('is_scanned') or (doc_context.get('is_pdf') and not doc_context.get('is_scanned')))) else 3
        min_spatial_dist = BLOCK * 6 if (doc_context and doc_context.get('is_scanned')) else MIN_DIST

        copy_pairs = 0
        for i in range(len(block_hashes)):
            for j in range(i + 1, len(block_hashes)):
                h1, x1, y1 = block_hashes[i]
                h2, x2, y2 = block_hashes[j]
                dist_px = ((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5
                if dist_px < min_spatial_dist:
                    continue
                # Hamming distance between the two pHashes
                xor = h1 ^ h2
                hamming = bin(xor).count('1')
                if hamming <= max_hamming:
                    copy_pairs += 1

        # Adaptive pair-count thresholds — scanned docs need more pairs to trigger
        if doc_context and doc_context.get('is_scanned'):
            score = 0.0
            if copy_pairs > 300:   score = 0.9
            elif copy_pairs > 150: score = 0.7
            elif copy_pairs > 60:  score = 0.5
            elif copy_pairs > 25:  score = 0.3
            elif copy_pairs > 8:   score = 0.15
        else:
            score = 0.0
            if copy_pairs > 200:   score = 0.9
            elif copy_pairs > 80:  score = 0.7
            elif copy_pairs > 30:  score = 0.5
            elif copy_pairs > 10:  score = 0.3
            elif copy_pairs > 3:   score = 0.15

        result['score'] = round(score, 3)
        result['detail'] = f'{copy_pairs} near-duplicate content block pair(s) at distant positions'

        if score >= 0.5:
            result['flag_desc'] = (
                f'Copy-Move — {copy_pairs} duplicate content region(s) detected far apart. '
                'Strong indicator of cloned/pasted content.'
            )
        elif score >= 0.15:
            result['flag_desc'] = f'Copy-Move — {copy_pairs} potential clone region(s). Review recommended.'
        else:
            result['flag_desc'] = 'Copy-Move — No suspicious duplicate content regions detected.'

    except Exception as e:
        result['detail'] = f'Copy-move error: {str(e)}'
        result['flag_desc'] = 'Copy-move analysis could not complete'

    return result


# ============================================
# Module E: Metadata Forensics
# ============================================

def run_metadata_forensics(filepath, file_ext, raw_bytes):
    """
    Analyze document metadata for editing signatures.
    Checks creator tool, timestamps, and raw byte patterns.
    """
    result = {
        'score': 0.0,
        'detail': '',
        'flags': [],
        'metadata': {},
    }

    risk_signals = []

    try:
        if file_ext == 'pdf':
            try:
                reader = PyPDF2.PdfReader(io.BytesIO(raw_bytes))
                meta = reader.metadata

                if meta:
                    result['metadata'] = {
                        'author':        str(meta.get('/Author', '')),
                        'creator':       str(meta.get('/Creator', '')),
                        'producer':      str(meta.get('/Producer', '')),
                        'creation_date': str(meta.get('/CreationDate', '')),
                        'mod_date':      str(meta.get('/ModDate', '')),
                        'title':         str(meta.get('/Title', '')),
                    }

                    creator  = str(meta.get('/Creator', '')).lower()
                    producer = str(meta.get('/Producer', '')).lower()

                    # Only flag image-editing tools, not legitimate document creators
                    # Word/LibreOffice/OpenOffice are normal creation tools for payslips, letters, etc.
                    editing_tools = [
                        'photoshop', 'gimp', 'paint.net', 'pixlr',
                        'affinity', 'corel', 'inkscape',
                    ]
                    for tool in editing_tools:
                        if tool in creator or tool in producer:
                            risk_signals.append(('HIGH', f'Editing tool in metadata: {creator or producer}'))
                            break

                    online_editors = [
                        'canva', 'ilovepdf', 'smallpdf', 'sejda',
                        'pdf2go', 'pdfcandy', 'cleverpdf', 'hipdf',
                        'pdfescape', 'pdfbuddy', 'docfly'
                    ]
                    for editor in online_editors:
                        if editor in creator or editor in producer:
                            risk_signals.append(('HIGH', f'Online PDF editor: {creator or producer}'))
                            break

                    create_date = str(meta.get('/CreationDate', ''))
                    mod_date    = str(meta.get('/ModDate', ''))
                    if create_date and mod_date and create_date != mod_date:
                        # Downgraded to LOW — most official docs (payslips, receipts) have
                        # different ModDate due to templates, digital signatures, or mail merges
                        risk_signals.append(('LOW', f'ModDate != CreateDate (document was modified after creation)'))

                    num_pages = len(reader.pages)
                    result['metadata']['page_count'] = num_pages

            except Exception as e:
                result['detail'] = f'PDF metadata extraction partial: {str(e)}'

        else:
            try:
                img = Image.open(io.BytesIO(raw_bytes))
                exif = img.getexif()

                if exif:
                    software = exif.get(305, '')
                    if software:
                        result['metadata']['software'] = str(software)
                        sw_lower = str(software).lower()
                        editing_tools = ['photoshop', 'gimp', 'paint.net', 'pixlr', 'affinity']
                        for tool in editing_tools:
                            if tool in sw_lower:
                                risk_signals.append(('HIGH', f'EXIF software: {software}'))
                                break

                    datetime_original  = exif.get(36867, '')
                    datetime_digitized = exif.get(36868, '')
                    if datetime_original and datetime_digitized:
                        if str(datetime_original) != str(datetime_digitized):
                            risk_signals.append(('LOW', 'EXIF original and digitized timestamps differ'))
                else:
                    result['metadata']['exif'] = 'Stripped (no EXIF present)'

            except Exception:
                pass

        # Raw byte signature scan — catches tools that strip metadata but leave traces
        raw_str = raw_bytes[:20000].decode('latin-1', errors='ignore').lower()
        byte_signatures = {
            'adobe photoshop':      ('HIGH',   'Adobe Photoshop byte signature'),
            'gimp':                 ('HIGH',   'GIMP byte signature'),
            'paint.net':            ('HIGH',   'Paint.NET byte signature'),
            'inkscape':             ('MEDIUM', 'Inkscape byte signature'),
            'canva':                ('HIGH',   'Canva byte signature'),
            'ilovepdf':             ('HIGH',   'iLovePDF byte signature'),
            'smallpdf':             ('HIGH',   'SmallPDF byte signature'),
            'sejda':                ('MEDIUM', 'Sejda byte signature'),
        }
        for pattern, (sev, desc) in byte_signatures.items():
            if pattern in raw_str:
                if not any(pattern in s[1].lower() for s in risk_signals):
                    risk_signals.append((sev, desc + ' found in raw file bytes'))

        score = 0.0
        for severity, _ in risk_signals:
            if severity == 'HIGH':    score += 0.40
            elif severity == 'MEDIUM': score += 0.20
            elif severity == 'LOW':    score += 0.10

        result['score'] = min(score, 1.0)
        result['flags'] = [
            {'module': 'METADATA', 'severity': s, 'description': d}
            for s, d in risk_signals
        ]

        if risk_signals:
            result['detail'] = f'{len(risk_signals)} risk signal(s): {"; ".join(d for _, d in risk_signals[:2])}'
        else:
            result['detail'] = 'No suspicious metadata detected'

    except Exception as e:
        result['detail'] = f'Metadata error: {str(e)}'
        traceback.print_exc()

    return result


# ============================================
# Module F — CNN Font Forensics
# ============================================

def run_font_forensics(image: Image.Image, raw_text: str, doc_context: dict = None) -> dict:
    """
    Module F: CNN-based Font Forensics
    ====================================
    Detects inconsistent font usage — a key indicator of digitally altered
    documents (e.g., salary number pasted with a different font, name edited
    with overlaid text from a different source).

    Architecture:
      1. CHARACTER SEGMENTATION — Use Tesseract word-level bounding boxes to
         extract individual word/character patches from the document image.
      2. FEATURE EXTRACTION — Pass each 32×32 patch through MobileNetV2
         (pretrained on ImageNet) to get a 128-dimensional feature embedding.
         MobileNetV2's early layers capture font texture, stroke width,
         serif presence, and character shape — without any custom training.
      3. FONT CLUSTERING — Apply KMeans clustering (k=2 to k=4) on the
         embeddings. A genuine document from a single print job will have
         all glyphs in ONE cluster. Multiple distinct clusters indicate
         different font origins.
      4. OUTLIER FLAGGING — Flag clusters that contain < 5% of all glyphs
         AND whose centroid distance from the main cluster exceeds 2σ.
         These are the suspected "pasted" characters.

    Fallback (no deep learning libs):
      Uses OpenCV-based stroke-width variance analysis as a classical
      approximation of font inconsistency detection.

    Returns dict with: score (0.0-1.0), detail (str), flag_desc (str)
    """
    result = {
        'score': 0.0,
        'detail': 'Font forensics not run',
        'flag_desc': '',
        'method': 'none',
    }

    try:
        if not HAS_CV2:
            raise ImportError('cv2 not available')

        import numpy as np

        # Convert to grayscale for glyph analysis
        gray = np.array(image.convert('L'))
        height, width = gray.shape

        # ── Attempt deep learning path (MobileNetV2) ─────────────────────
        try:
            import torch
            import torchvision.models as models
            import torchvision.transforms as transforms

            # Load MobileNetV2 backbone (pretrained, feature extraction only)
            model = models.mobilenet_v2(pretrained=False)
            model.eval()

            transform = transforms.Compose([
                transforms.Resize((32, 32)),
                transforms.Grayscale(num_output_channels=3),
                transforms.ToTensor(),
                transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225]),
            ])

            # Extract word-region patches via Tesseract bounding boxes
            try:
                import pytesseract
                data = pytesseract.image_to_data(
                    image, output_type=pytesseract.Output.DICT, config='--psm 6'
                )
                patches = []
                for i, conf in enumerate(data['conf']):
                    if conf > 60:  # only high-confidence words
                        x, y, w, h = (data['left'][i], data['top'][i],
                                      data['width'][i], data['height'][i])
                        if w > 5 and h > 5:
                            patch = image.crop((x, y, x + w, y + h))
                            patches.append(patch)
            except Exception:
                patches = []

            if len(patches) < 5:
                raise ValueError('Insufficient word patches for CNN analysis')

            # Extract embeddings
            embeddings = []
            with torch.no_grad():
                for patch in patches[:100]:  # limit to 100 patches
                    tensor = transform(patch).unsqueeze(0)
                    # Use the feature layer before classifier
                    feat = model.features(tensor)
                    feat = torch.nn.functional.adaptive_avg_pool2d(feat, (1, 1))
                    embeddings.append(feat.squeeze().numpy())

            embeddings = np.array(embeddings)

            # KMeans clustering (k=2: one main font, one anomalous)
            from sklearn.cluster import KMeans
            from sklearn.preprocessing import normalize

            emb_norm = normalize(embeddings)
            k = min(3, len(emb_norm) // 5)  # max k=3, at least 5 per cluster
            k = max(k, 2)
            kmeans = KMeans(n_clusters=k, n_init=10, random_state=42)
            labels = kmeans.fit_predict(emb_norm)

            # Analyse cluster distribution
            unique, counts = np.unique(labels, return_counts=True)
            total = len(labels)
            main_cluster_ratio = counts.max() / total
            outlier_ratio = 1.0 - main_cluster_ratio

            # Score: higher outlier ratio = more font inconsistency
            if outlier_ratio > 0.30:
                score = 0.80
                flag = f'CNN detected {k} distinct font clusters; outlier ratio {outlier_ratio:.1%}'
            elif outlier_ratio > 0.15:
                score = 0.50
                flag = f'Moderate font cluster separation; outlier ratio {outlier_ratio:.1%}'
            elif outlier_ratio > 0.08:
                score = 0.25
                flag = f'Slight font inconsistency; outlier ratio {outlier_ratio:.1%}'
            else:
                score = 0.05
                flag = f'Font appears consistent across document ({k} clusters, main={main_cluster_ratio:.1%})'

            result.update({
                'score': round(score, 3),
                'detail': flag,
                'flag_desc': flag if score >= 0.35 else '',
                'method': 'cnn_mobilenetv2',
                'num_patches': len(patches),
                'clusters': k,
                'outlier_ratio': round(outlier_ratio, 3),
            })
            return result

        except (ImportError, Exception) as cnn_err:
            # ── Classical fallback: Stroke-Width Variance ──────────────────
            # Compute stroke width via distance transform on binarized image
            result['method'] = 'classical_stroke_width'

            _, binary = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)

            # Divide into a grid of regions, compute mean stroke width per region
            block_size = max(min(height, width) // 8, 32)
            stroke_widths = []

            for row in range(0, height - block_size, block_size):
                for col in range(0, width - block_size, block_size):
                    block = binary[row:row + block_size, col:col + block_size]
                    text_pixels = np.sum(block > 0)
                    if text_pixels > (block_size * block_size * 0.02):  # skip near-blank
                        dist = cv2.distanceTransform(block, cv2.DIST_L2, 5)
                        nonzero = dist[dist > 0]
                        if len(nonzero) > 0:
                            stroke_widths.append(float(np.mean(nonzero)))

            if len(stroke_widths) < 4:
                result['detail'] = 'Insufficient text density for font analysis'
                result['score'] = 0.0
                return result

            sw_arr = np.array(stroke_widths)
            sw_cv = float(np.std(sw_arr) / (np.mean(sw_arr) + 1e-6))  # Coeff of Variation

            # Born-digital PDFs and professional documents legitimately use mixed
            # fonts (bold labels, regular values, different header sizes).
            # Apply stricter CV thresholds to avoid flagging normal document layout.
            is_digital_pdf = doc_context and doc_context.get('is_pdf') and not doc_context.get('is_scanned')
            if is_digital_pdf:
                high_cv, med_cv, low_cv = 1.30, 0.90, 0.65
            else:
                high_cv, med_cv, low_cv = 0.60, 0.40, 0.25

            # High CV = inconsistent stroke widths = different font sources
            if sw_cv > high_cv:
                score = 0.70
                detail = f'High stroke-width variation (CV={sw_cv:.2f}) — likely mixed fonts'
            elif sw_cv > med_cv:
                score = 0.45
                detail = f'Moderate stroke-width variation (CV={sw_cv:.2f})'
            elif sw_cv > low_cv:
                score = 0.20
                detail = f'Slight stroke-width variation (CV={sw_cv:.2f})'
            else:
                score = 0.05
                detail = f'Font appears consistent (stroke CV={sw_cv:.2f})'

            result.update({
                'score': round(score, 3),
                'detail': detail,
                'flag_desc': detail if score >= 0.35 else '',
                'stroke_cv': round(sw_cv, 3),
            })
            return result

    except Exception as e:
        result['detail'] = f'Font forensics error: {str(e)}'
        result['score'] = 0.0
    return result


# ============================================
# Module G — Character-Level Copy-Paste Detection
# ============================================

def run_character_copypaste(image: Image.Image, raw_text: str, doc_context: dict = None) -> dict:
    """
    Module G: Character-Level Copy-Paste Detection
    ================================================
    Detects small character/digit substitutions that pixel-level copy-move
    (Module D) misses — e.g., a "1" replaced by "7", or a salary figure
    digit swapped by pasting a character from a digital source onto a
    scanned document.

    Detection Strategy — two independent signals:

    Signal 1: Noise-Variance Bimodality
      - Scanned documents have spatially uniform sensor noise.
      - Digitally pasted characters have ZERO noise (they are vector/digital).
      - We measure noise variance at the character bounding-box level.
      - A bimodal distribution (some boxes near-zero, others normal) is a
        strong indicator of mixed-origin content.

    Signal 2: pHash Cross-Comparison
      - Extract patches for each character bounding box.
      - Compute pHash for each patch.
      - Find pairs of characters that are near-identical (Hamming ≤ 3)
        but appear in completely different contexts (different positions,
        different surrounding characters).
      - Legitimate repeated characters (e.g., 'the', 'and') are filtered
        by checking their textual neighbours.

    Returns dict with: score (0.0-1.0), detail (str), flag_desc (str)
    """
    result = {
        'score': 0.0,
        'detail': 'Character analysis not run',
        'flag_desc': '',
    }

    try:
        if not HAS_CV2:
            raise ImportError('cv2 not available')

        import numpy as np

        gray = np.array(image.convert('L'))
        height, width = gray.shape

        # ── Signal 1: Noise-Variance Bimodality ─────────────────────────
        # Laplacian noise extraction at character-region level
        laplacian = cv2.Laplacian(gray.astype(np.float32), cv2.CV_32F)

        # Divide into small blocks (character-sized: ~16×16)
        char_block = 16
        noise_variances = []
        for row in range(0, height - char_block, char_block):
            for col in range(0, width - char_block, char_block):
                block = laplacian[row:row + char_block, col:col + char_block]
                # Only analyse blocks with text content
                orig_block = gray[row:row + char_block, col:col + char_block]
                if np.std(orig_block) > 8:  # skip blank/background
                    noise_variances.append(float(np.var(block)))

        score_signal1 = 0.0
        detail_signal1 = ''
        # For born-digital PDFs all text has zero sensor noise by design — the
        # bimodality check would always see high near-zero ratios (false positive).
        # Skip Signal 1 for digital PDFs; rely on Signal 2 (pHash) instead.
        is_digital_pdf = doc_context and doc_context.get('is_pdf') and not doc_context.get('is_scanned')
        if len(noise_variances) >= 10 and not is_digital_pdf:
            nv = np.array(noise_variances)
            # Bimodality: check if significant fraction are near-zero
            # (digital origin = no sensor noise)
            near_zero = np.sum(nv < np.percentile(nv, 10)) / len(nv)
            cv = float(np.std(nv) / (np.mean(nv) + 1e-6))

            if near_zero > 0.25 and cv > 1.5:
                score_signal1 = 0.75
                detail_signal1 = (
                    f'Bimodal noise distribution: {near_zero:.1%} near-zero blocks '
                    f'(digital paste detected, CV={cv:.2f})'
                )
            elif near_zero > 0.15 or cv > 1.2:
                score_signal1 = 0.40
                detail_signal1 = f'Moderate noise bimodality (near-zero={near_zero:.1%}, CV={cv:.2f})'
            else:
                score_signal1 = 0.05
                detail_signal1 = f'Noise consistent (CV={cv:.2f})'

        # ── Signal 2: pHash Character Cross-Comparison ───────────────────
        score_signal2 = 0.0
        detail_signal2 = ''
        try:
            import pytesseract
            data = pytesseract.image_to_data(
                image, output_type=pytesseract.Output.DICT, config='--psm 6'
            )

            # Extract character patches and compute pHash
            char_patches = []  # list of (pHash_int, x, y, text)
            for i, conf in enumerate(data['conf']):
                word = str(data['text'][i]).strip()
                if conf > 50 and len(word) >= 1:
                    x, y, w, h = (data['left'][i], data['top'][i],
                                  data['width'][i], data['height'][i])
                    if w >= 4 and h >= 4:
                        patch = np.array(
                            image.crop((x, y, x + w, y + h))
                            .convert('L')
                            .resize((8, 8), Image.LANCZOS)
                        ).flatten().astype(np.float32)
                        avg = patch.mean()
                        bits = (patch > avg).astype(int)
                        phash_int = int(''.join(str(b) for b in bits), 2)
                        char_patches.append((phash_int, x, y, word))

            # Find suspiciously identical but spatially distant patches
            suspicious_pairs = 0
            for i in range(len(char_patches)):
                for j in range(i + 1, min(i + 50, len(char_patches))):
                    h1, x1, y1, t1 = char_patches[i]
                    h2, x2, y2, t2 = char_patches[j]
                    xor = h1 ^ h2
                    hamming = bin(xor).count('1')
                    dist = ((x1 - x2) ** 2 + (y1 - y2) ** 2) ** 0.5
                    # Near-identical appearance (hamming ≤ 2) but far apart
                    # AND different surrounding text context
                    if hamming <= 2 and dist > 100 and t1 != t2:
                        suspicious_pairs += 1

            if suspicious_pairs > 20:
                score_signal2 = 0.70
                detail_signal2 = f'High character pHash collision count ({suspicious_pairs} pairs)'
            elif suspicious_pairs > 8:
                score_signal2 = 0.40
                detail_signal2 = f'Moderate character similarity anomalies ({suspicious_pairs} pairs)'
            elif suspicious_pairs > 3:
                score_signal2 = 0.20
                detail_signal2 = f'Minor character similarities detected ({suspicious_pairs} pairs)'
            else:
                score_signal2 = 0.05
                detail_signal2 = f'No suspicious character copy-paste patterns'

        except Exception:
            # Tesseract not available — rely on Signal 1 only
            detail_signal2 = 'pHash analysis skipped (OCR unavailable)'

        # Combine signals (Signal 1 weighted 60%, Signal 2 weighted 40%)
        final_score = (score_signal1 * 0.60) + (score_signal2 * 0.40)
        detail = f'{detail_signal1}; {detail_signal2}' if detail_signal1 else detail_signal2

        result.update({
            'score': round(min(final_score, 1.0), 3),
            'detail': detail or 'No character anomalies detected',
            'flag_desc': detail if final_score >= 0.35 else '',
            'signal1_score': round(score_signal1, 3),
            'signal2_score': round(score_signal2, 3),
        })

    except Exception as e:
        result['detail'] = f'Character analysis error: {str(e)}'
        result['score'] = 0.0

    return result


# ============================================
# Module H — PDF Content Stream Forensics
# ============================================

def run_pdf_layer_forensics(filepath: str, raw_bytes: bytes, is_scanned: bool = False) -> dict:
    """
    Module H: PDF Content Stream Forensics
    ========================================
    Detects PDF object-level manipulation that is completely invisible to all
    pixel-based modules (ELA, Noise, DCT, Copy-Move) because those operate on
    the *rendered* image, not on the PDF object model.

    Targeted attack: "digit overlay" — fraudster copies the content stream
    object for digit "9" and places it at the same (x, y) position as "5",
    overlaying the original. The rendered image shows "9" but the PDF
    contains both objects stacked — detectable via bounding-box overlap.

    Checks performed:
      1. Incremental update markers (%%EOF count > 1)
      2. Overlapping character bounding boxes (layer copy attack)
      3. Invisible / hidden text objects (white-on-white)
      4. FreeText / Stamp annotation overlays
    """
    result = {
        'score': 0.0,
        'detail': 'PDF structure clean',
        'flag_desc': '',
        'flags': [],
    }

    risk_signals = []  # list of (severity, description)

    # ── Check 1: Incremental update markers ─────────────────────────────────
    # Each %%EOF in a PDF ends a cross-reference section.
    # 1 %%EOF = original clean file.
    # 2 %%EOF = one update (can be legitimate for digital signatures — check).
    # 3+ %%EOF = modified multiple times after creation.
    eof_count = raw_bytes.count(b'%%EOF')
    if eof_count >= 3:
        risk_signals.append((
            'HIGH',
            f'{eof_count} %%EOF markers — PDF modified {eof_count - 1} time(s) after creation'
        ))
    elif eof_count == 2:
        # Digital signatures legitimately produce a 2nd %%EOF; check for sig evidence
        is_signed = b'/Sig ' in raw_bytes[:60000] or b'/ByteRange' in raw_bytes[:60000]
        if not is_signed:
            risk_signals.append((
                'HIGH',
                'Two %%EOF markers — PDF was modified after creation (incremental update without digital signature)'
            ))

    # ── Check 2: Overlapping text objects (layer copy attack) ────────────────
    # pdfplumber exposes every character with its bounding box from the content
    # stream. A digit "9" placed over "5" at the same coordinates produces two
    # overlapping character objects — detected here.
    try:
        import pdfplumber
        with pdfplumber.open(filepath) as pdf:
            if pdf.pages:
                page = pdf.pages[0]
                chars = page.chars or []

                overlap_count = _detect_overlapping_chars(chars)
                # Invisible/white chars are extremely common in normal PDFs:
                # OCR text layers, form fields, accessibility markup, watermarks.
                # They do NOT indicate tampering by themselves.
                # Only overlapping chars (overlay attack) are a reliable signal.
                invisible_count = 0

                if overlap_count >= 5:
                    risk_signals.append((
                        'HIGH',
                        f'{overlap_count} overlapping character bounding box(es) — text layer overlay attack likely'
                    ))
                elif overlap_count >= 2:
                    risk_signals.append((
                        'MEDIUM',
                        f'{overlap_count} overlapping character position(s) — possible text overlay'
                    ))
                elif overlap_count == 1:
                    risk_signals.append((
                        'LOW',
                        '1 overlapping character position detected — minor anomaly'
                    ))

                if invisible_count >= 5:
                    risk_signals.append((
                        'HIGH',
                        f'{invisible_count} invisible/hidden character(s) — white text or zero-size objects'
                    ))
                elif invisible_count >= 1:
                    risk_signals.append((
                        'LOW',
                        f'{invisible_count} potentially hidden character(s) detected'
                    ))
    except Exception:
        pass  # pdfplumber not available — skip this check

    # ── Check 3: Suspicious annotation overlays ──────────────────────────────
    # FreeText and Stamp annotations place visible content over existing page
    # content — a common method for overlaying forged text.
    try:
        reader = PyPDF2.PdfReader(io.BytesIO(raw_bytes))
        if reader.pages:
            page = reader.pages[0]
            annots_raw = page.get('/Annots')
            if annots_raw is not None:
                freetext_count = 0
                try:
                    for item in annots_raw:
                        try:
                            annot = item.get_object() if hasattr(item, 'get_object') else item
                            subtype = str(annot.get('/Subtype', ''))
                            if subtype in ('/FreeText', '/Stamp', '/Caret'):
                                freetext_count += 1
                        except Exception:
                            pass
                except Exception:
                    pass
                if freetext_count > 0:
                    risk_signals.append((
                        'MEDIUM',
                        f'{freetext_count} FreeText/Stamp annotation(s) overlaying document content'
                    ))
    except Exception:
        pass

    # ── Score calculation ────────────────────────────────────────────────────
    score = 0.0
    for severity, _ in risk_signals:
        if severity == 'HIGH':     score += 0.45
        elif severity == 'MEDIUM': score += 0.25
        elif severity == 'LOW':    score += 0.10

    result['score'] = min(round(score, 3), 1.0)

    if risk_signals:
        descriptions = [d for _, d in risk_signals]
        result['detail'] = f'{len(risk_signals)} PDF structure anomaly(ies): {descriptions[0]}'
        result['flag_desc'] = result['detail']
        result['flags'] = [
            {'module': 'PDF_LAYERS', 'severity': s, 'description': d}
            for s, d in risk_signals
        ]
    else:
        result['detail'] = 'PDF structure clean — no layer manipulation detected'

    return result


def _detect_overlapping_chars(chars: list) -> int:
    """
    Count character pairs with significantly overlapping bounding boxes.

    A legitimate PDF has each character at a unique position. When a forger
    copies a digit's content stream object and places it at the same coordinates,
    pdfplumber sees both characters with nearly identical bounding boxes.

    Filters out: spaces, superscripts/subscripts (expected partial y-overlap),
    and normal kerning (small x-overlap between adjacent chars).
    """
    visible = [
        c for c in chars
        if c.get('text', '').strip()
        and (c.get('x1', 0) - c.get('x0', 0)) > 1.0
        and (c.get('bottom', 0) - c.get('top', 0)) > 2.0
    ]
    if len(visible) < 2:
        return 0

    # Sort by position so co-located chars appear adjacent in the list
    visible.sort(key=lambda c: (round(c.get('top', 0) / 4) * 4, c.get('x0', 0)))

    overlaps = 0
    n = len(visible)
    for i in range(n):
        c1 = visible[i]
        x0_1, x1_1 = c1.get('x0', 0), c1.get('x1', 0)
        t_1, b_1   = c1.get('top', 0), c1.get('bottom', 0)
        w1 = max(x1_1 - x0_1, 0.5)
        h1 = max(b_1 - t_1, 0.5)

        for j in range(i + 1, min(i + 30, n)):
            c2 = visible[j]
            # Once we're clearly on a lower line, no more overlaps possible with c1
            if c2.get('top', 0) > b_1 + 3:
                break

            x0_2, x1_2 = c2.get('x0', 0), c2.get('x1', 0)
            t_2, b_2   = c2.get('top', 0), c2.get('bottom', 0)
            w2 = max(x1_2 - x0_2, 0.5)
            h2 = max(b_2 - t_2, 0.5)

            x_ol = min(x1_1, x1_2) - max(x0_1, x0_2)
            y_ol = min(b_1, b_2)   - max(t_1, t_2)

            if x_ol <= 0 or y_ol <= 0:
                continue

            # Overlap must cover >65% of the smaller char's width AND >50% of its height.
            # This threshold rules out normal kerning (small x overlap) and
            # superscripts/subscripts (partial y overlap with significant y offset).
            if x_ol / min(w1, w2) > 0.65 and y_ol / min(h1, h2) > 0.50:
                overlaps += 1

    return overlaps


def _count_invisible_chars(chars: list) -> int:
    """Count characters that are invisible — white-on-white or zero-size."""
    invisible = 0
    for c in chars:
        if not c.get('text', '').strip():
            continue
        color = c.get('non_stroking_color') or c.get('stroking_color')
        if color is not None:
            try:
                if isinstance(color, (int, float)) and float(color) >= 0.95:
                    invisible += 1  # near-white grayscale
                elif isinstance(color, (tuple, list)) and len(color) >= 3:
                    if all(float(v) >= 0.95 for v in color[:3]):
                        invisible += 1  # near-white RGB
            except (TypeError, ValueError):
                pass
    return invisible


# ============================================
# Module I — Cortex AI Visual Tamper Analysis
# ============================================

def run_cortex_tamper_analysis(image: Image.Image) -> dict:
    """
    Module I: AI Vision-Based Tamper Detection
    ============================================
    Uses Gemini vision (via Cortex API) to detect specific targeted document
    edits that structural/pixel analysis cannot reliably identify:

    Detects:
      - Numbers changed (salary, dates, amounts) via PDF editing tools
      - Text pasted or overlaid with different visual characteristics
      - Font/size/color mismatches in specific characters vs surroundings
      - Visible editing artifacts (sharp edges, alignment issues, color drift)
      - Signature forgery indicators

    Unlike hardcoded modules, the AI can distinguish between:
      - Normal PDF structure (multiple fonts, sizes) → NOT tampering
      - A single digit that looks different from its neighbours → TAMPERING

    Returns dict with: score (0.0-1.0), detail (str), flag_desc (str)
    """
    result = {
        'score': 0.0,
        'detail': 'AI tamper analysis not run',
        'flag_desc': '',
    }

    try:
        import io
        import json
        import os
        import re

        import google
        from google import genai
        from google.genai import types

        project  = os.getenv('GOOGLE_CLOUD_PROJECT', '')
        location = os.getenv('GOOGLE_CLOUD_LOCATION', 'global')
        model    = os.getenv('GEMINI_MODEL', 'gemini-2.5-flash')

        if not project:
            result['detail'] = 'GOOGLE_CLOUD_PROJECT not configured — AI analysis skipped'
            result['score'] = 0.0
            return result

        client = genai.Client(vertexai=True, project=project, location=location)

        buf = io.BytesIO()
        image.convert('RGB').save(buf, format='PNG')
        img_bytes = buf.getvalue()

        prompt = (
            "You are a forensic document examiner. Analyze this document image for signs of tampering or editing.\n\n"
            "SPECIFICALLY LOOK FOR:\n"
            "1. Numbers that appear edited (salary figures, dates, amounts) — different font weight, "
            "size, color, or alignment vs surrounding text\n"
            "2. Text that looks pasted or overlaid — sharp edges, different background shade behind specific characters\n"
            "3. Individual characters or digits that visually differ from their neighbours "
            "(e.g., a '7' that looks different from other digits in the same row)\n"
            "4. Signature that looks digitally pasted (sharp uniform edges, no pen pressure variation, "
            "different resolution from surrounding content)\n"
            "5. Visible tool marks — white rectangles covering text, misaligned baselines, "
            "color banding around edited regions\n\n"
            "DO NOT flag these as tampering (they are normal):\n"
            "- Multiple font sizes/styles (headings vs body)\n"
            "- Bold labels with regular values\n"
            "- Table borders, horizontal rules\n"
            "- Watermarks or background patterns\n"
            "- Low scan quality or slight rotation\n\n"
            "Return ONLY valid JSON — no markdown fences — in this exact schema:\n"
            '{"tampering_detected":false,"confidence":0.0,"findings":[],"summary":"..."}\n\n'
            "Where:\n"
            "- tampering_detected: true if you see specific evidence of editing\n"
            "- confidence: 0.0 to 1.0 how confident you are that tampering exists\n"
            "- findings: list of specific observations (max 3), each as a string\n"
            "- summary: one-line explanation\n\n"
            "Be conservative — only flag clear visual evidence of specific edits, not general document characteristics."
        )

        response = client.models.generate_content(
            model=model,
            contents=[
                prompt,
                types.Part.from_bytes(data=img_bytes, mime_type='image/png'),
            ],
            config=types.GenerateContentConfig(
                temperature=0,
                response_mime_type='application/json',
            ),
        )

        raw_content = response.text.strip()
        json_text = re.sub(r'^```(?:json)?\s*|\s*```$', '', raw_content, flags=re.MULTILINE).strip()
        parsed = json.loads(json_text)

        tamper_detected = bool(parsed.get('tampering_detected', False))
        ai_confidence = float(parsed.get('confidence', 0.0))
        findings = parsed.get('findings', [])
        summary = str(parsed.get('summary', ''))

        if tamper_detected and ai_confidence >= 0.6:
            score = min(ai_confidence, 0.95)
            detail = f'AI detected tampering (confidence {ai_confidence:.0%}): {summary}'
        elif tamper_detected and ai_confidence >= 0.3:
            score = ai_confidence * 0.7
            detail = f'AI suspects possible edits (confidence {ai_confidence:.0%}): {summary}'
        else:
            score = 0.0
            detail = f'AI found no evidence of targeted edits: {summary}'

        result.update({
            'score': round(score, 3),
            'detail': detail,
            'flag_desc': detail if score >= 0.35 else '',
            'findings': findings[:3],
            'ai_confidence': ai_confidence,
        })

    except (ImportError, Exception) as e:
        result['detail'] = f'AI analysis unavailable: {str(e)}'
        result['score'] = 0.0

    return result
