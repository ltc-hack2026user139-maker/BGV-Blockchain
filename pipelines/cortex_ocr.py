"""
Vertex AI / Gemini vision-based OCR and field comparison for Aadhaar and Passport documents.

Credentials are read from environment variables (or .env file loaded by server.py):
  GOOGLE_CLOUD_PROJECT  — GCP project ID (required)
  GOOGLE_CLOUD_LOCATION — e.g. global (default: global)
  GEMINI_MODEL          — e.g. gemini-2.5-flash
"""

import io
import json
import os
import re

from google import genai
from google.genai import types
from PIL import Image


GOOGLE_CLOUD_PROJECT:  str = os.getenv('GOOGLE_CLOUD_PROJECT', '')
GOOGLE_CLOUD_LOCATION: str = os.getenv('GOOGLE_CLOUD_LOCATION', 'global')
GEMINI_MODEL:          str = os.getenv('GEMINI_MODEL', 'gemini-2.5-flash')

# Backward-compat alias — aadhaar.py and passport.py check CORTEX_API_KEY to decide
# whether to call the vision model. Re-use the project ID as a truthy sentinel.
CORTEX_API_KEY: str = GOOGLE_CLOUD_PROJECT


def _vertex_client() -> genai.Client:
    return genai.Client(
        vertexai=True,
        project=GOOGLE_CLOUD_PROJECT,
        location=GOOGLE_CLOUD_LOCATION,
    )


def _image_to_bytes(image: Image.Image) -> bytes:
    buf = io.BytesIO()
    image.convert('RGB').save(buf, format='PNG')
    buf.seek(0)
    return buf.read()


def cortex_compare_aadhaar(
    page_image: Image.Image,
    qr_data: dict,
    api_key: str = '',
    base_url: str = '',
    model: str = '',
) -> dict:
    """
    Send the rendered Aadhaar page image + QR-decoded ground-truth to the
    Vertex AI Gemini vision model and ask it to:
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
    _model = model or GEMINI_MODEL

    if not GOOGLE_CLOUD_PROJECT:
        return {'success': False, 'error': 'GOOGLE_CLOUD_PROJECT not configured'}

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
        "   - Compare dates by their actual day/month/year values ONLY — ignore separator differences\n"
        "     (e.g. '25/04/2001' and '25-04-2001' are the SAME date, set dob_match = true).\n"
        "   - Only set tampering_suspected = true if the actual date digits differ (e.g. year changed).\n"
        "   - If any field is missing from the card face, set that match field to false.\n\n"
        "Return ONLY valid JSON — no markdown fences, no explanation — in this exact schema:\n"
        '{"ocr_name":"...","ocr_dob":"...","ocr_gender":"...",'
        '"name_match":true,"dob_match":true,"gender_match":true,'
        '"any_mismatch":false,"tampering_suspected":false,"notes":"..."}'
    )

    raw_content = ''
    try:
        client = _vertex_client()

        response = client.models.generate_content(
            model=_model,
            contents=[
                prompt,
                types.Part.from_bytes(
                    data=_image_to_bytes(page_image),
                    mime_type='image/png',
                ),
            ],
            config=types.GenerateContentConfig(
                temperature=0,
                response_mime_type='application/json',
            ),
        )

        raw_content = response.text.strip()
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
            'error': f'Failed to parse Gemini response: {exc}',
            'raw_response': raw_content,
        }
    except Exception as exc:
        return {
            'success': False,
            'error': f'Vertex AI error: {exc}',
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
    Vertex AI Gemini vision model and ask it to:
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
    _model = model or GEMINI_MODEL

    if not GOOGLE_CLOUD_PROJECT:
        return {'success': False, 'error': 'GOOGLE_CLOUD_PROJECT not configured'}

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
        client = _vertex_client()

        response = client.models.generate_content(
            model=_model,
            contents=[
                prompt,
                types.Part.from_bytes(
                    data=_image_to_bytes(page_image),
                    mime_type='image/png',
                ),
            ],
            config=types.GenerateContentConfig(
                temperature=0,
                response_mime_type='application/json',
            ),
        )

        raw_content = response.text.strip()
        json_text = re.sub(r'^```(?:json)?\s*|\s*```$', '', raw_content, flags=re.MULTILINE).strip()
        parsed = json.loads(json_text)

        given   = str(parsed.get('ocr_given_names', '') or '')
        surname = str(parsed.get('ocr_surname',     '') or '')
        full    = str(parsed.get('ocr_full_name',   '') or (f'{given} {surname}'.strip()))

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
            'error': f'Failed to parse Gemini response: {exc}',
            'raw_response': raw_content,
        }
    except Exception as exc:
        return {
            'success': False,
            'error': f'Vertex AI error: {exc}',
            'raw_response': raw_content,
        }
