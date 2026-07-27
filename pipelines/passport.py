"""
BGV Pipeline 2: Passport Verification
=======================================
Flow: PDF/Image → OCR MRZ Zone → Parse MRZ (ICAO 9303) → 
      Validate Check Digits → OCR VIZ (preprocessed) → Compare MRZ vs VIZ

MRZ (Machine Readable Zone) structure for Type 3 passport:
  Line 1: P<CCCFAMILYNAME<<GIVENNAMES<<<<<<<<<<<<<<<<<<<<
  Line 2: PPPPPPPPPCNNNDDDDDDCGEEEEEECOOOOOOOOOOOOOOC
  
Where:
  P = Passport number, C = Check digit, N = Nationality,
  D = DOB (YYMMDD), G = Gender, E = Expiry (YYMMDD), O = Optional

v3.0 Changes:
  - VIZ extraction now uses CLAHE + 2x upsampling + Otsu binarization
  - Tesseract PSM changed to auto-page (PSM 3) for VIZ, PSM 6 kept for MRZ
  - DOB patterns expanded to include DD-MMM-YYYY (e.g. 01 JAN 1990)
  - Improved name heuristics with passport-specific layout hints
"""

import os
import re
import traceback
from datetime import datetime
from PIL import Image, ImageFilter, ImageEnhance
import numpy as np


# ICAO 9303 check digit weights
MRZ_WEIGHTS = [7, 3, 1]

# Character values for MRZ check digit computation
MRZ_CHAR_VALUES = {}
for i in range(10):
    MRZ_CHAR_VALUES[str(i)] = i
for i, c in enumerate('ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
    MRZ_CHAR_VALUES[c] = i + 10
MRZ_CHAR_VALUES['<'] = 0


def _mrz_year_to_full(yy: int) -> int:
    """
    Convert a 2-digit MRZ year to 4-digit per ICAO 9303 50-year sliding window.
    Any yy that would place the year more than 50 years in the future is
    interpreted as 19yy; otherwise 20yy.
    """
    cutoff = (datetime.now().year + 50) % 100
    return (1900 + yy) if yy > cutoff else (2000 + yy)

def verify_passport(filepath):
    """
    Main passport verification pipeline.
    Returns a dict with pipeline results for the decision engine.
    """
    result = {
        'pipeline': 'passport',
        'checks': [],
        'flags': [],
        'mrz_data': {},
        'viz_data': {},
        'checksums_valid': None,
        'fields_match': None,
    }

    # Step 1: Load image and text (if PDF)
    try:
        doc_data = load_document(filepath)
        image = doc_data['image']
        pdf_text = doc_data.get('text', '')
        
        result['checks'].append({
            'name': 'Document Loading',
            'passed': True,
            'detail': f'Document loaded ({image.width}x{image.height})' if image else 'Document text loaded',
        })
    except Exception as e:
        result['checks'].append({
            'name': 'Document Loading',
            'passed': False,
            'detail': f'Failed: {str(e)}',
        })
        result['error'] = f'Failed to load document: {str(e)}'
        return result

    # Step 2: Extract MRZ
    mrz_text = None
    
    # Try native text extraction first
    if pdf_text:
        mrz_text = extract_mrz_from_text(pdf_text)
        
    if not mrz_text and image:
        # Fallback to image cropping and OCR
        mrz_text = extract_mrz_from_image(image)

    if mrz_text:
        result['checks'].append({
            'name': 'MRZ Extraction',
            'passed': True,
            'detail': 'Machine Readable Zone detected',
        })
    else:
            result['checks'].append({
                'name': 'MRZ Extraction',
                'passed': False,
                'detail': 'No MRZ detected in document',
            })
            result['flags'].append({
                'module': 'MRZ',
                'severity': 'HIGH',
                'description': 'Could not detect Machine Readable Zone — cannot verify passport',
            })
            return result

    # Step 3: Parse MRZ
    parsed_mrz = parse_mrz(mrz_text)
    result['mrz_data'] = parsed_mrz

    if parsed_mrz.get('valid_structure'):
        result['checks'].append({
            'name': 'MRZ Structure',
            'passed': True,
            'detail': f'Type: {parsed_mrz.get("doc_type", "?")} | Issuer: {parsed_mrz.get("issuing_country", "?")}',
        })
    else:
        result['checks'].append({
            'name': 'MRZ Structure',
            'passed': False,
            'detail': 'MRZ format does not match ICAO 9303 standard',
        })

    # Step 4: Validate Check Digits
    checksum_results = validate_mrz_checksums(parsed_mrz)
    result['checksums_valid'] = checksum_results['all_valid']

    for check in checksum_results['checks']:
        result['checks'].append(check)

    if not checksum_results['all_valid']:
        result['flags'].append({
            'module': 'MRZ_CHECKSUM',
            'severity': 'HIGH',
            'description': 'MRZ check digit validation failed — possible document alteration',
        })

    # Step 5: Extract Visual Zone (VIZ)
    viz_data = {'name': None, 'dob': None, 'gender': None}
    
    if pdf_text:
        viz_data = extract_viz_from_text(pdf_text)
        
    if not viz_data.get('name') and not viz_data.get('dob') and image:
        viz_data_img = extract_viz_from_image(image)
        # Merge dicts, preferring non-None values from viz_data_img if viz_data is empty
        for k, v in viz_data_img.items():
            if not viz_data.get(k):
                viz_data[k] = v

    result['viz_data'] = viz_data

    if viz_data.get('name') or viz_data.get('dob'):
        result['checks'].append({
            'name': 'VIZ Text Extraction',
            'passed': True,
            'detail': 'Visual zone text extracted',
        })
    else:
        result['checks'].append({
            'name': 'VIZ Text Extraction',
            'passed': True,
            'warning': True,
            'detail': 'Limited VIZ text extracted — comparison may be partial',
        })

    # Step 6: Compare MRZ vs VIZ — prefer Cortex vision AI, fall back to Tesseract
    if parsed_mrz.get('valid_structure'):
        cortex_result = None
        cortex_error  = None

        try:
            from cortex_ocr import cortex_compare_passport, CORTEX_API_KEY
        except ImportError:
            try:
                from pipelines.cortex_ocr import cortex_compare_passport, CORTEX_API_KEY
            except ImportError as imp_err:
                cortex_error = f'cortex_ocr import failed: {imp_err}'
                cortex_compare_passport = None
                CORTEX_API_KEY = ''

        if cortex_compare_passport and CORTEX_API_KEY and image:
            try:
                cortex_result = cortex_compare_passport(image, parsed_mrz)
                if not cortex_result.get('success'):
                    cortex_error = cortex_result.get('error', 'Unknown Cortex error')
            except Exception as _cx_err:
                cortex_error = str(_cx_err)

        if cortex_error:
            print(f'[WARN] Cortex passport OCR: {cortex_error}')
            result['checks'].append({
                'name': 'Cortex AI Visual Analysis',
                'passed': False,
                'warning': True,
                'detail': f'Cortex unavailable — falling back to Tesseract. Error: {cortex_error}',
            })
        elif not (cortex_compare_passport and CORTEX_API_KEY):
            result['checks'].append({
                'name': 'Cortex AI Visual Analysis',
                'passed': False,
                'warning': True,
                'detail': 'CORTEX_API_KEY not set — falling back to Tesseract OCR',
            })

        if cortex_result and cortex_result.get('success'):
            ocr_ext = cortex_result['ocr_extracted']
            cmp     = cortex_result['comparison']

            # Merge Cortex-extracted VIZ back into viz_data so cross-check also benefits
            result['viz_data'].update({
                'name':   ocr_ext.get('full_name')   or result['viz_data'].get('name'),
                'dob':    ocr_ext.get('dob')         or result['viz_data'].get('dob'),
                'gender': ocr_ext.get('gender')      or result['viz_data'].get('gender'),
                'nationality': ocr_ext.get('nationality'),
                'cortex_raw': cortex_result.get('raw_response', ''),
            })

            all_match = not cmp.get('any_mismatch', False)
            result['fields_match'] = all_match

            result['checks'].append({
                'name': 'Cortex AI Visual Analysis',
                'passed': True,
                'detail': 'Gemini vision model analysed the passport VIZ successfully',
            })
            result['checks'].append({
                'name': 'Name Match (Cortex AI)',
                'passed': cmp.get('name_match', False),
                'detail': (
                    f'MRZ: {parsed_mrz.get("full_name", "N/A")} | '
                    f'VIZ: {ocr_ext.get("full_name", "N/A")}'
                ),
            })
            result['checks'].append({
                'name': 'DOB Match (Cortex AI)',
                'passed': cmp.get('dob_match', False),
                'detail': (
                    f'MRZ: {parsed_mrz.get("dob_formatted", "N/A")} | '
                    f'VIZ: {ocr_ext.get("dob", "N/A")}'
                ),
            })
            result['checks'].append({
                'name': 'Gender Match (Cortex AI)',
                'passed': cmp.get('gender_match', False),
                'detail': (
                    f'MRZ: {parsed_mrz.get("gender_full", "N/A")} | '
                    f'VIZ: {ocr_ext.get("gender", "N/A")}'
                ),
            })
            if cmp.get('notes'):
                result['checks'].append({
                    'name': 'Cortex AI Notes',
                    'passed': not cmp.get('tampering_suspected', False),
                    'warning': cmp.get('tampering_suspected', False),
                    'detail': cmp['notes'],
                })

            if not all_match:
                result['flags'].append({
                    'module': 'MRZ_VIZ',
                    'severity': 'CRITICAL' if cmp.get('tampering_suspected') else 'MEDIUM',
                    'description': (
                        f'Cortex AI detected tampering: VIZ differs from MRZ. {cmp.get("notes", "")}'
                        if cmp.get('tampering_suspected')
                        else 'Mismatch between MRZ data and visible passport text'
                    ),
                })

        else:
            # Cortex unavailable — Tesseract-based comparison
            field_comparison = compare_mrz_viz(parsed_mrz, viz_data)
            result['fields_match'] = field_comparison['all_match']
            for check in field_comparison['checks']:
                result['checks'].append(check)
            if not field_comparison['all_match']:
                result['flags'].append({
                    'module': 'MRZ_VIZ',
                    'severity': 'MEDIUM',
                    'description': 'Mismatch between MRZ data and visible text on passport',
                })

    return result


def load_document(filepath):
    """Load document as PIL Image and extract text if PDF."""
    ext = os.path.splitext(filepath)[1].lower()
    doc_data = {'image': None, 'text': ''}

    if ext == '.pdf':
        try:
            import fitz
            doc = fitz.open(filepath)
            
            # Extract text
            for page in doc:
                doc_data['text'] += page.get_text() + "\n"
            
            # Extract image (try to render the page at 2x)
            page = doc[0]
            mat = fitz.Matrix(2.0, 2.0)
            pix = page.get_pixmap(matrix=mat)
            doc_data['image'] = Image.frombytes('RGB', [pix.width, pix.height], pix.samples)
            doc.close()
            return doc_data
        except Exception as e:
            print(f"[WARN] fitz PDF load error: {e}")
            pass

    # Fallback for images
    try:
        doc_data['image'] = Image.open(filepath)
    except Exception as e:
        raise Exception(f"Could not load image: {e}")

    return doc_data


def extract_mrz_from_text(text):
    """Extract MRZ lines directly from raw text."""
    lines = text.strip().split('\n')
    mrz_lines = []

    for line in lines:
        line = line.strip().replace(' ', '')
        if len(line) >= 30:
            mrz_chars = sum(1 for c in line if c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<')
            if mrz_chars / len(line) > 0.85:
                mrz_lines.append(line)

    if len(mrz_lines) >= 2:
        return '\n'.join(mrz_lines[-2:])
    return None


def extract_mrz_from_image(image):
    """
    Extract MRZ from passport image using image processing.
    MRZ is typically at the bottom of the passport page.
    """
    try:
        # Crop bottom 30% of image (where MRZ typically is)
        width, height = image.size
        bottom_crop = image.crop((0, int(height * 0.65), width, height))

        # Try OCR on the cropped region
        return ocr_mrz(bottom_crop)

    except Exception as e:
        print(f"[WARN] MRZ extraction error: {e}")
        return None


def ocr_mrz(image):
    """OCR the MRZ zone and extract the two MRZ lines."""
    text = ''

    try:
        # Try pytesseract
        try:
            import pytesseract
            text = pytesseract.image_to_string(
                image,
                config='--psm 6 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<'
            )
        except ImportError:
            pass

        # Try tesseract binary
        if not text:
            try:
                import subprocess
                import tempfile

                tmp_path = os.path.join(tempfile.gettempdir(), 'mrz_temp.png')
                image.save(tmp_path)

                proc = subprocess.run(
                    ['tesseract', tmp_path, 'stdout',
                     '--psm', '6',
                     '-c', 'tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<'],
                    capture_output=True, text=True, timeout=30
                )

                if proc.returncode == 0:
                    text = proc.stdout

                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

    except Exception:
        pass

    if not text:
        return None

    # Find MRZ lines (44 chars for passport, 36 for ID card)
    lines = text.strip().split('\n')
    mrz_lines = []

    for line in lines:
        line = line.strip().replace(' ', '')
        # MRZ line should be mostly uppercase letters, digits, and '<'
        if len(line) >= 30:
            mrz_chars = sum(1 for c in line if c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<')
            if mrz_chars / len(line) > 0.85:
                mrz_lines.append(line)

    if len(mrz_lines) >= 2:
        # Return the last two valid MRZ lines
        return '\n'.join(mrz_lines[-2:])

    return None


def parse_mrz(mrz_text):
    """Parse MRZ text into structured fields per ICAO 9303."""
    result = {'valid_structure': False, 'raw': mrz_text}

    if not mrz_text:
        return result

    lines = mrz_text.strip().split('\n')
    lines = [l.strip() for l in lines if l.strip()]

    if len(lines) < 2:
        return result

    line1 = lines[-2] if len(lines) >= 2 else lines[0]
    line2 = lines[-1]

    # Pad lines to 44 characters
    line1 = line1.ljust(44, '<')[:44]
    line2 = line2.ljust(44, '<')[:44]

    result['line1'] = line1
    result['line2'] = line2

    # Parse Line 1
    doc_type = line1[0:2].replace('<', '')
    issuing_country = line1[2:5].replace('<', '')

    # Name parsing
    name_part = line1[5:]
    name_parts = name_part.split('<<')
    surname = name_parts[0].replace('<', ' ').strip() if name_parts else ''
    given_names = name_parts[1].replace('<', ' ').strip() if len(name_parts) > 1 else ''

    result['doc_type'] = doc_type
    result['issuing_country'] = issuing_country
    result['surname'] = surname
    result['given_names'] = given_names
    result['full_name'] = f'{given_names} {surname}'.strip()

    # Parse Line 2
    result['passport_number'] = line2[0:9].replace('<', '')
    result['passport_check'] = line2[9] if len(line2) > 9 else ''
    result['nationality'] = line2[10:13].replace('<', '') if len(line2) > 12 else ''
    result['dob'] = line2[13:19] if len(line2) > 18 else ''  # YYMMDD
    result['dob_check'] = line2[19] if len(line2) > 19 else ''
    result['gender'] = line2[20] if len(line2) > 20 else ''
    result['expiry'] = line2[21:27] if len(line2) > 26 else ''  # YYMMDD
    result['expiry_check'] = line2[27] if len(line2) > 27 else ''
    result['optional'] = line2[28:42] if len(line2) > 41 else ''
    result['optional_check'] = line2[42] if len(line2) > 42 else ''
    result['composite_check'] = line2[43] if len(line2) > 43 else ''

    # Format DOB for display
    if result['dob'] and len(result['dob']) == 6:
        yy, mm, dd = int(result['dob'][:2]), result['dob'][2:4], result['dob'][4:6]
        result['dob_formatted'] = f'{dd}/{mm}/{_mrz_year_to_full(yy)}'

    # Format expiry
    if result['expiry'] and len(result['expiry']) == 6:
        yy, mm, dd = int(result['expiry'][:2]), result['expiry'][2:4], result['expiry'][4:6]
        result['expiry_formatted'] = f'{dd}/{mm}/{_mrz_year_to_full(yy)}'

    # Gender mapping
    gender_map = {'M': 'MALE', 'F': 'FEMALE', '<': 'UNSPECIFIED'}
    result['gender_full'] = gender_map.get(result['gender'], result['gender'])

    result['valid_structure'] = True
    return result


def compute_mrz_check_digit(data_str):
    """Compute ICAO 9303 check digit for a data string."""
    total = 0
    for i, char in enumerate(data_str):
        value = MRZ_CHAR_VALUES.get(char.upper(), 0)
        weight = MRZ_WEIGHTS[i % 3]
        total += value * weight
    return total % 10


def validate_mrz_checksums(parsed_mrz):
    """Validate all MRZ check digits per ICAO 9303."""
    results = {'all_valid': True, 'checks': []}

    if not parsed_mrz.get('valid_structure'):
        results['all_valid'] = False
        results['checks'].append({
            'name': 'MRZ Checksum Validation',
            'passed': False,
            'detail': 'Cannot validate — invalid MRZ structure',
        })
        return results

    line2 = parsed_mrz.get('line2', '')
    if len(line2) < 44:
        results['all_valid'] = False
        return results

    # Check 1: Passport number check digit
    passport_data = line2[0:9]
    passport_check = line2[9]
    expected = compute_mrz_check_digit(passport_data)
    actual = int(passport_check) if passport_check.isdigit() else -1
    passed = expected == actual
    results['checks'].append({
        'name': 'Passport Number Check Digit',
        'passed': passed,
        'detail': f'Expected: {expected}, Got: {actual}' if not passed else 'Valid',
    })
    if not passed:
        results['all_valid'] = False

    # Check 2: DOB check digit
    dob_data = line2[13:19]
    dob_check = line2[19]
    expected = compute_mrz_check_digit(dob_data)
    actual = int(dob_check) if dob_check.isdigit() else -1
    passed = expected == actual
    results['checks'].append({
        'name': 'DOB Check Digit',
        'passed': passed,
        'detail': f'Expected: {expected}, Got: {actual}' if not passed else 'Valid',
    })
    if not passed:
        results['all_valid'] = False

    # Check 3: Expiry date check digit
    expiry_data = line2[21:27]
    expiry_check = line2[27]
    expected = compute_mrz_check_digit(expiry_data)
    actual = int(expiry_check) if expiry_check.isdigit() else -1
    passed = expected == actual
    results['checks'].append({
        'name': 'Expiry Date Check Digit',
        'passed': passed,
        'detail': f'Expected: {expected}, Got: {actual}' if not passed else 'Valid',
    })
    if not passed:
        results['all_valid'] = False

    # Check 4: Personal Number (Optional Data) Check Digit
    # ICAO 9303 specifies that if there is optional data, character 42 is its check digit
    optional_data = line2[28:42]
    optional_check = line2[42] if len(line2) > 42 else ''
    
    # Only validate if the optional check digit is not '<' and optional data exists
    if optional_check and optional_check != '<':
        expected = compute_mrz_check_digit(optional_data)
        actual = int(optional_check) if optional_check.isdigit() else -1
        passed = expected == actual
        results['checks'].append({
            'name': 'Personal Number Check Digit',
            'passed': passed,
            'detail': f'Expected: {expected}, Got: {actual}' if not passed else 'Valid',
        })
        if not passed:
            results['all_valid'] = False

    # Check 5: Composite check digit
    # Composite = passport_number + check + DOB + check + expiry + check + optional + optional_check
    composite_data = line2[0:10] + line2[13:20] + line2[21:43]
    composite_check = line2[43]
    expected = compute_mrz_check_digit(composite_data)
    actual = int(composite_check) if composite_check.isdigit() else -1
    passed = expected == actual
    results['checks'].append({
        'name': 'Composite Check Digit',
        'passed': passed,
        'detail': f'Expected: {expected}, Got: {actual}' if not passed else 'All fields integrity verified',
    })
    if not passed:
        results['all_valid'] = False

    return results


def extract_viz_from_text(text):
    """
    Extract VIZ fields directly from native PDF text layer.
    v3.0: Expanded DOB patterns include DD-MMM-YYYY format.
    """
    result = {'name': None, 'dob': None, 'gender': None, 'raw_text': text}

    _SKIP_KEYWORDS = {
        'REPUBLIC', 'INDIA', 'PASSPORT', 'NATIONALITY', 'GIVEN',
        'SURNAME', 'NAMES', 'BIRTH', 'DATE', 'GENDER', 'PLACE',
        'EXPIRY', 'ISSUE', 'PERSONAL', 'NUMBER', 'SEX', 'FILE'
    }
    _MONTH_MAP = {
        'JAN': '01', 'FEB': '02', 'MAR': '03', 'APR': '04',
        'MAY': '05', 'JUN': '06', 'JUL': '07', 'AUG': '08',
        'SEP': '09', 'OCT': '10', 'NOV': '11', 'DEC': '12'
    }

    lines = text.strip().split('\n')
    for line in lines:
        line = line.strip()
        if not line:
            continue

        # DOB — numeric formats (DD/MM/YYYY, DD-MM-YYYY, DD.MM.YYYY)
        dob_match = re.search(r'(\d{2}[/\-\.]\d{2}[/\-\.]\d{4})', line)
        if dob_match and not result['dob']:
            result['dob'] = dob_match.group(1).replace('-', '/').replace('.', '/')

        # DOB — textual format (DD MMM YYYY / DD-MMM-YYYY)
        if not result['dob']:
            dob_match2 = re.search(
                r'(\d{1,2})[\s\-]+(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[\s\-]+(\d{4})',
                line, re.IGNORECASE
            )
            if dob_match2:
                dd = dob_match2.group(1).zfill(2)
                mm = _MONTH_MAP[dob_match2.group(2).upper()]
                yyyy = dob_match2.group(3)
                result['dob'] = f'{dd}/{mm}/{yyyy}'

        # Gender
        gender_match = re.search(r'\b(MALE|FEMALE)\b', line, re.IGNORECASE)
        if gender_match and not result['gender']:
            result['gender'] = gender_match.group(1).upper()

        # Name — mostly uppercase, no digits, not a label keyword
        if not result['name'] and 4 <= len(line) <= 50:
            upper_ratio = sum(1 for c in line if c.isupper()) / max(len(line), 1)
            words = set(line.upper().split())
            if upper_ratio > 0.65 and not any(c.isdigit() for c in line):
                if not words.intersection(_SKIP_KEYWORDS):
                    result['name'] = line

    return result


def _preprocess_for_ocr(image):
    """
    Preprocess an image region for high-accuracy Tesseract OCR.
    Pipeline v3.0:
      Grayscale → CLAHE contrast enhancement → 2× upsample
      → Denoising → Otsu binarize → Median blur

    The key addition over v2 is fastNlMeansDenoising *before* Otsu so that
    the threshold is computed on a clean signal rather than on sensor noise.
    """
    try:
        import cv2
        # Convert PIL → numpy
        img_np = np.array(image.convert('RGB'))
        gray = cv2.cvtColor(img_np, cv2.COLOR_RGB2GRAY)

        # CLAHE — Contrast Limited Adaptive Histogram Equalization
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        gray = clahe.apply(gray)

        # Upsample 2× for better glyph resolution (target ~300 DPI equivalent)
        h, w = gray.shape
        gray = cv2.resize(gray, (w * 2, h * 2), interpolation=cv2.INTER_CUBIC)

        # ── NEW: Non-local means denoising before binarization ───────────
        # Removes sensor/scan noise so Otsu picks the correct threshold.
        # h=10 is a balanced strength — strong enough to clean noise,
        # mild enough to preserve thin strokes.
        try:
            gray = cv2.fastNlMeansDenoising(gray, h=10, templateWindowSize=7,
                                            searchWindowSize=21)
        except Exception:
            pass  # Older OpenCV may not have this; continue without it

        # Otsu's binarization — adaptive threshold for mixed backgrounds
        _, binary = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)

        # Mild denoising pass on binary to remove salt-and-pepper
        binary = cv2.medianBlur(binary, 3)

        # Convert back to PIL
        return Image.fromarray(binary)

    except ImportError:
        # Fallback: PIL-only enhancement without OpenCV
        img_gray = image.convert('L')
        img_gray = ImageEnhance.Contrast(img_gray).enhance(2.0)
        img_gray = img_gray.filter(ImageFilter.SHARPEN)
        w, h = img_gray.size
        img_gray = img_gray.resize((w * 2, h * 2), Image.LANCZOS)
        return img_gray
    except Exception as e:
        print(f"[WARN] VIZ preprocessing fallback: {e}")
        return image


def extract_viz_from_image(image):
    """
    Extract text from the Visual Inspection Zone (upper portion of passport).

    v3.0 (REVISED):
      • Smarter crop: rows 25%–72% of image (skips decorative top header and
        keeps MRZ out of the VIZ zone)
      • Multi-PSM cascade: PSM 6 → PSM 4 → PSM 3 — tries the most structured
        mode first and falls back to more automatic modes
      • Relaxed name heuristic: upper_ratio threshold lowered to 0.50;
        collects ALL candidate name lines and picks the best one
      • Includes raw_text in result for downstream fallback matching
    """
    result = {'name': None, 'dob': None, 'gender': None, 'raw_text': ''}

    _SKIP_KEYWORDS = {
        'REPUBLIC', 'INDIA', 'PASSPORT', 'NATIONALITY', 'GIVEN',
        'SURNAME', 'NAMES', 'BIRTH', 'DATE', 'GENDER', 'PLACE',
        'EXPIRY', 'ISSUE', 'PERSONAL', 'NUMBER', 'SEX', 'FILE',
        'SIGNATURE', 'HOLDER', 'OLD', 'NEW', 'VALID', 'UNTIL',
    }
    _MONTH_MAP = {
        'JAN': '01', 'FEB': '02', 'MAR': '03', 'APR': '04',
        'MAY': '05', 'JUN': '06', 'JUL': '07', 'AUG': '08',
        'SEP': '09', 'OCT': '10', 'NOV': '11', 'DEC': '12'
    }

    try:
        width, height = image.size

        # ── Crop Strategy ────────────────────────────────────────────────
        # Indian passports: top ~25% is decorative header (Ashoka lion, title).
        # The VIZ data zone (name, DOB, gender, nationality) lives in rows
        # 25%–72%.  Rows 72%–100% are the MRZ — keep them out.
        top_y    = int(height * 0.22)
        bottom_y = int(height * 0.72)
        viz_crop = image.crop((0, top_y, width, bottom_y))

        # Also try a slightly wider crop in case layout varies
        viz_crop_wide = image.crop((0, 0, width, int(height * 0.72)))

        # ── Preprocess both crops ────────────────────────────────────────
        preprocessed      = _preprocess_for_ocr(viz_crop)
        preprocessed_wide = _preprocess_for_ocr(viz_crop_wide)

        all_texts = []  # Collect OCR texts from every PSM attempt

        try:
            import pytesseract

            # PSM cascade: 6 (uniform block) → 4 (single column) → 3 (auto)
            # Apply each to both the tight crop and the wide crop
            for psm in ['6', '4', '3']:
                for img_variant in [preprocessed, preprocessed_wide, viz_crop]:
                    try:
                        t = pytesseract.image_to_string(
                            img_variant, lang='eng',
                            config=f'--psm {psm} --oem 1'
                        )
                        if t and t.strip():
                            all_texts.append(t)
                    except Exception:
                        pass

        except ImportError:
            # Subprocess fallback
            try:
                import subprocess
                import tempfile
                for psm in ['6', '4', '3']:
                    for img_variant, tag in [(preprocessed, 'tight'),
                                             (preprocessed_wide, 'wide')]:
                        tmp_path = os.path.join(
                            tempfile.gettempdir(), f'viz_temp_{psm}_{tag}.png'
                        )
                        try:
                            img_variant.save(tmp_path)
                            proc = subprocess.run(
                                ['tesseract', tmp_path, 'stdout',
                                 '-l', 'eng', '--psm', psm, '--oem', '1'],
                                capture_output=True, text=True, timeout=30
                            )
                            if proc.returncode == 0 and proc.stdout.strip():
                                all_texts.append(proc.stdout)
                        except Exception:
                            pass
                        finally:
                            if os.path.exists(tmp_path):
                                os.remove(tmp_path)
            except Exception:
                pass

        # ── Merge all OCR texts into one combined blob ───────────────────
        combined_text = '\n'.join(all_texts)
        if not combined_text.strip():
            return result

        result['raw_text'] = combined_text
        lines = combined_text.split('\n')

        # ── Parse each line for fields ───────────────────────────────────
        name_candidates = []  # (score, line_text)
        dob_candidates = []   # list of dicts: {'date': str, 'score': int}
        
        # Gender mapping helper
        gender_keywords = r'\b(MALE|FEMALE|M|F)\b'

        for line in lines:
            line_upper = line.strip().upper()
            if not line_upper or len(line_upper) < 3:
                continue

            # Check if this line looks like a DOB line (has gender or nationality)
            is_dob_line = bool(re.search(gender_keywords, line_upper) or 'INDIAN' in line_upper or 'IND' in line_upper)

            # Extract dates: DD/MM/YYYY, DD-MM-YYYY, DD.MM.YYYY (tolerate spaces from OCR)
            date_matches = re.finditer(r'(\d{2})\s*[/\-\.]\s*(\d{2})\s*[/\-\.]\s*(\d{4})', line_upper)
            for m in date_matches:
                date_str = f"{m.group(1)}/{m.group(2)}/{m.group(3)}"
                score = 10 if is_dob_line else 1
                dob_candidates.append({'date': date_str, 'score': score})

            # Extract dates: DD MMM YYYY (e.g. "12 JAN 1990")
            date_matches2 = re.finditer(
                r'(\d{1,2})[\s\-]+(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[\s\-]+(\d{4})',
                line_upper
            )
            for m in date_matches2:
                dd   = m.group(1).zfill(2)
                mm   = _MONTH_MAP[m.group(2)]
                yyyy = m.group(3)
                date_str = f"{dd}/{mm}/{yyyy}"
                score = 10 if is_dob_line else 1
                dob_candidates.append({'date': date_str, 'score': score})

            # Gender
            if not result['gender']:
                gender_match = re.search(r'\b(MALE|FEMALE)\b', line_upper)
                if gender_match:
                    result['gender'] = gender_match.group(1)
                else:
                    # Indian passport VIZ prints single letter "M" or "F" next to Sex label
                    single_gender = re.search(r'(?:SEX|GENDER)\s*[:\-]?\s*([MF])\b', line_upper)
                    if single_gender:
                        result['gender'] = 'MALE' if single_gender.group(1) == 'M' else 'FEMALE'
                    elif re.search(r'\bSEX\b|\bGENDER\b', line_upper):
                        # Label found — check next token on the same line
                        m = re.search(r'(?:SEX|GENDER).*?\b([MF])\b', line_upper)
                        if m:
                            result['gender'] = 'MALE' if m.group(1) == 'M' else 'FEMALE'

            # ── Name candidates ──────────────────────────────────────────
            # Conditions (relaxed vs v2):
            #   • 4–55 characters long
            #   • ≥ 50% uppercase chars (was 65% — lowered to tolerate OCR noise)
            #   • No digits
            #   • Not dominated by skip-keywords
            if 4 <= len(line_upper) <= 55:
                alpha_chars = [c for c in line_upper if c.isalpha() or c == ' ']
                if not alpha_chars:
                    continue
                upper_ratio = sum(1 for c in alpha_chars if c.isupper()) / len(alpha_chars)
                if upper_ratio >= 0.50 and not any(c.isdigit() for c in line):
                    words_upper = set(line.upper().split())
                    skip_hits   = words_upper.intersection(_SKIP_KEYWORDS)
                    # Accept if fewer than half the words are skip-keywords
                    if len(skip_hits) < max(1, len(words_upper) // 2):
                        # Score: higher upper_ratio + longer line = better name
                        score = upper_ratio * len(line)
                        name_candidates.append((score, line))

        # Best DOB selection
        if dob_candidates:
            # Group by date string and sum scores
            dob_scores = {}
            for cand in dob_candidates:
                d = cand['date']
                dob_scores[d] = dob_scores.get(d, 0) + cand['score']

            # Sort by score descending
            best_dob = sorted(dob_scores.items(), key=lambda x: x[1], reverse=True)[0][0]
            result['dob'] = best_dob

        # ── Name combination — Indian passport labeled layout ────────────
        # Try to extract Surname + Given Names from labeled fields first,
        # then fall back to best single candidate.
        surname_from_label   = None
        given_from_label     = None
        prev_was_surname_lbl = False
        prev_was_given_lbl   = False

        for line in lines:
            lu = line.strip().upper()
            if not lu:
                continue
            # Detect label lines
            if re.search(r'\bSURNAME\b', lu):
                prev_was_surname_lbl = True
                prev_was_given_lbl   = False
                continue
            if re.search(r'\bGIVEN\b', lu):
                prev_was_given_lbl   = True
                prev_was_surname_lbl = False
                continue

            # Line following a label — capture as name token if all-alpha
            if prev_was_surname_lbl:
                prev_was_surname_lbl = False
                if re.match(r'^[A-Z][A-Z\s]{1,40}$', lu):
                    surname_from_label = lu.strip()
                continue
            if prev_was_given_lbl:
                prev_was_given_lbl = False
                if re.match(r'^[A-Z][A-Z\s]{1,40}$', lu):
                    given_from_label = lu.strip()
                continue

        if surname_from_label or given_from_label:
            parts = [p for p in [given_from_label, surname_from_label] if p]
            result['name'] = ' '.join(parts)
        elif name_candidates:
            name_candidates.sort(key=lambda x: x[0], reverse=True)
            result['name'] = name_candidates[0][1]

    except Exception as e:
        print(f"[WARN] VIZ extraction error: {e}")
        import traceback
        traceback.print_exc()

    return result


def compare_mrz_viz(mrz_data, viz_data):
    """Compare MRZ fields with VIZ (visual zone) fields."""
    comparison = {'all_match': True, 'checks': []}

    viz_raw_text = (viz_data.get('raw_text') or '').upper()

    # Compare Name
    # Build a union of ALL MRZ name words (full_name + surname + given_names)
    # so a VIZ that only has "SHARMA" or only "RAHUL KUMAR" can still match.
    mrz_full    = mrz_data.get('full_name', '').strip().upper()
    mrz_surname = mrz_data.get('surname', '').strip().upper()
    mrz_given   = mrz_data.get('given_names', '').strip().upper()
    viz_name    = (viz_data.get('name') or '').strip().upper()

    # All words across all MRZ name components
    all_mrz_name_words: set = set()
    for nm_str in [mrz_full, mrz_surname, mrz_given]:
        if nm_str:
            all_mrz_name_words.update(nm_str.split())

    match = False
    used_viz_name = viz_name if viz_name else "Not found"

    if all_mrz_name_words:
        # Step 1: word-overlap between extracted VIZ name and MRZ word pool
        if viz_name:
            name_words_viz = set(viz_name.split())
            common = all_mrz_name_words & name_words_viz
            # Threshold: at least 1 word matches (or 33% of whichever side is smaller)
            if len(common) >= max(1, min(len(all_mrz_name_words), len(name_words_viz)) * 0.33):
                match = True

        # Step 2: if still no match, search raw OCR text for any MRZ name word
        # (multi-PSM OCR blob very likely contains at least surname or given name)
        if not match and viz_raw_text:
            long_words = [w for w in all_mrz_name_words if len(w) > 2]
            if long_words:
                found_words = [w for w in long_words if w in viz_raw_text]
                # Require at least 1 long word found (or 33%)
                min_required = max(1, int(len(long_words) * 0.33))
                if len(found_words) >= min_required:
                    match = True
                    used_viz_name = " ".join(found_words) + " (found in OCR text)"
                else:
                    used_viz_name = viz_name if viz_name else "Not found in document text"

        comparison['checks'].append({
            'name': 'Name Match (MRZ vs VIZ)',
            'passed': match,
            'detail': (
                f'MRZ: {mrz_full}'
                f' (Surname: {mrz_surname} | Given: {mrz_given})'
                f' | VIZ: {used_viz_name}'
            ),
        })
        if not match:
            comparison['all_match'] = False
    else:
        comparison['checks'].append({
            'name': 'Name Match (MRZ vs VIZ)',
            'passed': True,
            'warning': True,
            'detail': 'MRZ name not parsed — comparison skipped',
        })

    # Compare DOB
    mrz_dob = mrz_data.get('dob_formatted', '')
    viz_dob = (viz_data.get('dob') or '').replace('-', '/').replace('.', '/')

    if mrz_dob and viz_dob:
        dob_match = mrz_dob == viz_dob
        comparison['checks'].append({
            'name': 'DOB Match (MRZ vs VIZ)',
            'passed': dob_match,
            'detail': f'MRZ: {mrz_dob} | VIZ: {viz_dob}',
        })
        if not dob_match:
            comparison['all_match'] = False
    else:
        comparison['checks'].append({
            'name': 'DOB Match (MRZ vs VIZ)',
            'passed': True,
            'warning': True,
            'detail': 'VIZ DOB not extracted — comparison skipped',
        })

    # Compare Gender
    mrz_gender = mrz_data.get('gender_full', '').strip().upper()
    viz_gender = (viz_data.get('gender') or '').strip().upper()
    
    if not viz_gender and viz_raw_text:
        m = re.search(r'\b(MALE|FEMALE)\b', viz_raw_text, re.IGNORECASE)
        if m:
            viz_gender = m.group(1).upper()
        else:
            m = re.search(r'(?:SEX|GENDER)\s*[:\-]?\s*([MF])\b', viz_raw_text, re.IGNORECASE)
            if m:
                viz_gender = 'MALE' if m.group(1).upper() == 'M' else 'FEMALE'

    if mrz_gender and mrz_gender != 'UNSPECIFIED':
        if viz_gender:
            gender_match = mrz_gender == viz_gender
            comparison['checks'].append({
                'name': 'Gender Match (MRZ vs VIZ)',
                'passed': gender_match,
                'detail': f'MRZ: {mrz_gender} | VIZ: {viz_gender}',
            })
            if not gender_match:
                comparison['all_match'] = False
        else:
            comparison['checks'].append({
                'name': 'Gender Match (MRZ vs VIZ)',
                'passed': True,
                'warning': True,
                'detail': 'VIZ Gender not extracted — comparison skipped',
            })

    # Compare Nationality
    mrz_nationality = mrz_data.get('nationality', '').strip().upper()
    if mrz_nationality:
        nat_match = mrz_nationality in viz_raw_text
        comparison['checks'].append({
            'name': 'Nationality Match (MRZ vs VIZ)',
            'passed': nat_match,
            'detail': f'MRZ: {mrz_nationality} | VIZ: {"Found in document" if nat_match else "Not found in document"}',
        })
        if not nat_match:
            # We don't fail the whole comparison for nationality as it's often represented differently (e.g., 'INDIAN' vs 'IND')
            comparison['checks'][-1]['warning'] = True
            comparison['checks'][-1]['passed'] = True

    return comparison
