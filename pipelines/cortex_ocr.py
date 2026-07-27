"""
Cortex / Gemini vision-based OCR and field comparison for Aadhaar documents.

Credentials are read from environment variables (or .env file loaded by server.py):
  CORTEX_BASE_URL  — e.g. https://cortex.lloydsbanking.cloud/api/v1
  CORTEX_API_KEY   — Bearer token
  GEMINI_MODEL     — e.g. gemini-2.5-flash
"""

import base64
import io
import json
import os
import re

import httpx
from openai import OpenAI
from PIL import Image


CORTEX_BASE_URL: str = os.getenv('CORTEX_BASE_URL', 'https://cortex.lloydsbanking.cloud/api/v1')
CORTEX_API_KEY:  str = os.getenv('CORTEX_API_KEY', '')
GEMINI_MODEL:    str = os.getenv('GEMINI_MODEL', 'gemini-2.5-flash')


def _cortex_client(api_key: str, base_url: str) -> OpenAI:
    """Build an OpenAI-compatible client pointed at the Cortex endpoint."""
    return OpenAI(
        base_url=base_url,
        api_key=api_key,
        http_client=httpx.Client(verify=False),  # internal Cortex cert may be self-signed
    )


def _image_to_base64(image: Image.Image) -> str:
    buf = io.BytesIO()
    image.convert('RGB').save(buf, format='PNG')
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('utf-8')


def cortex_compare_aadhaar(
    page_image: Image.Image,
    qr_data: dict,
    api_key: str = '',
    base_url: str = '',
    model: str = '',
) -> dict:
    """
    Send the rendered Aadhaar page image + QR-decoded ground-truth to the
    Cortex API (Gemini vision model) and ask it to:
      1. Extract name / DOB / gender from the PRINTED VISIBLE TEXT only
         (explicitly NOT the QR barcode).
      2. Compare extracted values with the QR ground-truth.
      3. Flag any mismatch — especially DOB differences — as suspected tampering.

    Returns:
        {
            'success': bool,
            'ocr_extracted': {'name': str, 'dob': str, 'gender': str},
            'comparison': {
                'name_match': bool, 'dob_match': bool, 'gender_match': bool,
                'any_mismatch': bool, 'tampering_suspected': bool, 'notes': str
            },
            'raw_response': str,
            'error': str,   # only present on failure
        }
    """
    _api_key  = api_key  or CORTEX_API_KEY
    _base_url = (base_url or CORTEX_BASE_URL).rstrip('/')
    _model    = model    or GEMINI_MODEL

    if not _api_key:
        return {'success': False, 'error': 'CORTEX_API_KEY not configured'}

    qr_summary = (
        f"Name  : {qr_data.get('name',   'N/A')}\n"
        f"DOB   : {qr_data.get('dob',    'N/A')}\n"
        f"Gender: {qr_data.get('gender', 'N/A')}"
    )

    prompt = (
        "You are a document verification assistant analysing an Aadhaar card image.\n\n"
        "TASK\n"
        "1. Extract the following fields from the PRINTED/VISIBLE TEXT on the card face only.\n"
        "   DO NOT read the QR code barcode — only read the human-readable printed text:\n"
        "   - Full name in English\n"
        "   - Date of birth as printed on the card face (e.g. 25/04/2001)\n"
        "   - Gender (MALE / FEMALE / TRANSGENDER)\n\n"
        "2. Compare what you extracted with these QR-decoded ground-truth values:\n"
        f"{qr_summary}\n\n"
        "3. Evaluate whether the printed values match the QR values.\n"
        "   - If the DOB printed on the card face differs from the QR DOB, "
        "set tampering_suspected = true.\n"
        "   - If any field is missing from the card face, set that match field to false.\n\n"
        "Return ONLY valid JSON — no markdown fences, no explanation — in this exact schema:\n"
        '{"ocr_name":"...","ocr_dob":"...","ocr_gender":"...",'
        '"name_match":true,"dob_match":true,"gender_match":true,'
        '"any_mismatch":false,"tampering_suspected":false,"notes":"..."}'
    )

    raw_content = ''
    try:
        client = _cortex_client(_api_key, _base_url)

        response = client.chat.completions.create(
            model=_model,
            temperature=0,
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/png;base64,{_image_to_base64(page_image)}"
                            },
                        },
                        {"type": "text", "text": prompt},
                    ],
                }
            ],
        )

        raw_content = response.choices[0].message.content.strip()

        # Strip markdown fences in case the model wraps the JSON
        json_text = re.sub(r'^```(?:json)?\s*|\s*```$', '', raw_content, flags=re.MULTILINE).strip()
        parsed = json.loads(json_text)

        return {
            'success': True,
            'ocr_extracted': {
                'name':   str(parsed.get('ocr_name',   '') or ''),
                'dob':    str(parsed.get('ocr_dob',    '') or ''),
                'gender': str(parsed.get('ocr_gender', '') or ''),
            },
            'comparison': {
                'name_match':          bool(parsed.get('name_match',          False)),
                'dob_match':           bool(parsed.get('dob_match',           False)),
                'gender_match':        bool(parsed.get('gender_match',        False)),
                'any_mismatch':        bool(parsed.get('any_mismatch',        False)),
                'tampering_suspected': bool(parsed.get('tampering_suspected', False)),
                'notes':               str(parsed.get('notes', '') or ''),
            },
            'raw_response': raw_content,
        }

    except (json.JSONDecodeError, KeyError) as exc:
        return {
            'success': False,
            'error': f'Failed to parse Cortex response: {exc}',
            'raw_response': raw_content,
        }
    except Exception as exc:
        return {
            'success': False,
            'error': f'Cortex API error: {exc}',
            'raw_response': raw_content,
        }


def cortex_compare_passport(
    page_image: Image.Image,
    mrz_data: dict,
    api_key: str = '',
    base_url: str = '',
    model: str = '',
) -> dict:
    """
    Send the passport page image + MRZ-decoded ground-truth to the
    Cortex API (Gemini vision model) and ask it to:
      1. Extract name / DOB / gender from the PRINTED VISUAL TEXT only
         (the upper VIZ portion — NOT the MRZ strip at the bottom).
      2. Compare extracted values with the MRZ ground-truth.
      3. Flag any mismatch as suspected tampering.

    Returns:
        {
            'success': bool,
            'ocr_extracted': {
                'surname': str, 'given_names': str, 'full_name': str,
                'dob': str, 'gender': str, 'nationality': str
            },
            'comparison': {
                'name_match': bool, 'dob_match': bool, 'gender_match': bool,
                'any_mismatch': bool, 'tampering_suspected': bool, 'notes': str
            },
            'raw_response': str,
            'error': str,   # only present on failure
        }
    """
    _api_key  = api_key  or CORTEX_API_KEY
    _base_url = (base_url or CORTEX_BASE_URL).rstrip('/')
    _model    = model    or GEMINI_MODEL

    if not _api_key:
        return {'success': False, 'error': 'CORTEX_API_KEY not configured'}

    mrz_summary = (
        f"Full Name   : {mrz_data.get('full_name',       'N/A')}\n"
        f"Surname     : {mrz_data.get('surname',          'N/A')}\n"
        f"Given Names : {mrz_data.get('given_names',      'N/A')}\n"
        f"DOB         : {mrz_data.get('dob_formatted',    'N/A')}\n"
        f"Gender      : {mrz_data.get('gender_full',      'N/A')}\n"
        f"Nationality : {mrz_data.get('nationality',      'N/A')}\n"
        f"Passport No.: {mrz_data.get('passport_number',  'N/A')}\n"
        f"Expiry      : {mrz_data.get('expiry_formatted', 'N/A')}"
    )

    prompt = (
        "You are a document verification assistant analysing an Indian passport image.\n\n"
        "TASK\n"
        "1. From the VISUAL INSPECTION ZONE (the printed text in the upper portion of the\n"
        "   passport — NOT the two-line MRZ strip at the very bottom), extract:\n"
        "   - Surname (उपनाम / Surname field)\n"
        "   - Given name(s) (दिया गया नाम / Given Name(s) field)\n"
        "   - Full name = Given Names + Surname combined\n"
        "   - Date of birth exactly as printed (e.g. 25/04/2001)\n"
        "   - Gender/Sex as MALE or FEMALE\n"
        "   - Nationality as printed\n\n"
        "2. Compare what you extracted with these MRZ machine-decoded ground-truth values:\n"
        f"{mrz_summary}\n\n"
        "3. Evaluate whether the printed values match the MRZ values.\n"
        "   - If DOB on the card face differs from MRZ DOB, set tampering_suspected = true.\n"
        "   - If the name on the card face differs significantly from MRZ name, "
        "set tampering_suspected = true.\n"
        "   - If a field is missing from the card face, set that match field to false.\n\n"
        "Return ONLY valid JSON — no markdown fences, no explanation — in this exact schema:\n"
        '{"ocr_surname":"...","ocr_given_names":"...","ocr_full_name":"...",'
        '"ocr_dob":"...","ocr_gender":"...","ocr_nationality":"...",'
        '"name_match":true,"dob_match":true,"gender_match":true,'
        '"any_mismatch":false,"tampering_suspected":false,"notes":"..."}'
    )

    raw_content = ''
    try:
        client = _cortex_client(_api_key, _base_url)

        response = client.chat.completions.create(
            model=_model,
            temperature=0,
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/png;base64,{_image_to_base64(page_image)}"
                            },
                        },
                        {"type": "text", "text": prompt},
                    ],
                }
            ],
        )

        raw_content = response.choices[0].message.content.strip()
        json_text = re.sub(r'^```(?:json)?\s*|\s*```$', '', raw_content, flags=re.MULTILINE).strip()
        parsed = json.loads(json_text)

        given  = str(parsed.get('ocr_given_names', '') or '')
        surname = str(parsed.get('ocr_surname',    '') or '')
        full   = str(parsed.get('ocr_full_name',   '') or (f'{given} {surname}'.strip()))

        return {
            'success': True,
            'ocr_extracted': {
                'surname':     surname,
                'given_names': given,
                'full_name':   full,
                'dob':         str(parsed.get('ocr_dob',         '') or ''),
                'gender':      str(parsed.get('ocr_gender',      '') or ''),
                'nationality': str(parsed.get('ocr_nationality', '') or ''),
            },
            'comparison': {
                'name_match':          bool(parsed.get('name_match',          False)),
                'dob_match':           bool(parsed.get('dob_match',           False)),
                'gender_match':        bool(parsed.get('gender_match',        False)),
                'any_mismatch':        bool(parsed.get('any_mismatch',        False)),
                'tampering_suspected': bool(parsed.get('tampering_suspected', False)),
                'notes':               str(parsed.get('notes', '') or ''),
            },
            'raw_response': raw_content,
        }

    except (json.JSONDecodeError, KeyError) as exc:
        return {
            'success': False,
            'error': f'Failed to parse Cortex response: {exc}',
            'raw_response': raw_content,
        }
    except Exception as exc:
        return {
            'success': False,
            'error': f'Cortex API error: {exc}',
            'raw_response': raw_content,
        }
