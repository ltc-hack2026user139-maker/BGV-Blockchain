"""
BGV Document Verification — Flask API Server v3.0
Serves the frontend and handles document verification through pipelines.
New in v3.0: Digital fingerprinting + blockchain-style audit ledger anchoring.
             Duplicate detection via fingerprint lookup before pipeline execution.
"""

import os
import sys
import json
import traceback
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename

# Load .env if present (before any pipeline imports that read env vars)
_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
if os.path.exists(_env_path):
    with open(_env_path) as _ef:
        for _line in _ef:
            _line = _line.strip()
            if _line and not _line.startswith('#') and '=' in _line:
                _k, _v = _line.split('=', 1)
                os.environ[_k.strip()] = _v.strip()

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pipelines.aadhaar import verify_aadhaar
from pipelines.passport import verify_passport
from pipelines.tamper import detect_tampering
from pipelines.decision_engine import compute_verdict
from pipelines.fingerprint import (
    compute_document_fingerprint,
    create_verification_record,
    compute_sha256,
    phash_similarity,
)
from pipelines.blockchain_ledger import (
    append_record,
    verify_chain_integrity,
    get_ledger_stats,
    lookup_document,
    lookup_candidate,
    classify_document_against_ledger,
)

app = Flask(__name__, static_folder='public', static_url_path='')

# Config
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png'}
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ─────────────────────────────────────────────────────────────────────────────
# Duplicate Detection Helper
# ─────────────────────────────────────────────────────────────────────────────

def _check_duplicate(filepath: str, password: str = '') -> dict | None:
    """
    Check if this document already exists in the ledger by comparing all four
    fingerprint hashes (crypto, perceptual, content, composite).
    Returns the most-recent matching block, or None if not found.
    """
    try:
        # Check by crypto_hash first (cheapest — no pipeline needed)
        crypto_hash = compute_sha256(filepath)
        existing = lookup_document(crypto_hash)
        if existing:
            return existing

        # Also check composite_hash in case a re-encoded version was uploaded
        # (same visual/content identity, different byte representation)
        try:
            fp = compute_document_fingerprint(filepath, {}, password=password)
            for h in (fp.get('composite_hash'), fp.get('content_hash')):
                if h:
                    block = lookup_document(h)
                    if block:
                        return block
        except Exception:
            pass
    except Exception as e:
        print(f"[WARN] Duplicate check failed (non-fatal): {e}")
    return None


def _build_cached_response(existing_block: dict) -> dict:
    """
    Build a response from a previously verified document's ledger block.
    Skips the entire pipeline — returns the stored verdict directly.
    """
    record = existing_block.get('record', {})
    verification = record.get('verification', {})
    fingerprint = record.get('fingerprint', {})

    return {
        'pipeline': verification.get('pipeline', 'unknown'),
        'verdict': verification.get('verdict', 'UNKNOWN'),
        'confidenceScore': verification.get('confidence_score', 0),
        'verdictReason': (
            'This document was previously verified and exists in the '
            'blockchain ledger. The original verdict has been returned.'
        ),
        'checks': [
            {
                'name': 'Blockchain Duplicate Detection',
                'passed': True,
                'detail': (
                    f'Document found in ledger at Block #{existing_block.get("seq", "?")} '
                    f'(anchored {record.get("timestamp_utc", "unknown")})'
                ),
            },
            {
                'name': 'Original Verdict (Cached)',
                'passed': verification.get('verdict') == 'VERIFIED',
                'warning': verification.get('verdict') == 'SUSPICIOUS',
                'detail': (
                    f'{verification.get("verdict")} with '
                    f'{verification.get("confidence_score", 0)}% confidence'
                ),
            },
        ],
        'flags': [
            {
                'module': 'BLOCKCHAIN',
                'severity': 'INFO',
                'description': (
                    f'Document already verified on {record.get("timestamp_utc", "N/A")}. '
                    f'Original verdict: {verification.get("verdict")} '
                    f'({verification.get("confidence_score", 0)}% confidence). '
                    f'Pipeline was skipped — cached result returned from Block '
                    f'#{existing_block.get("seq", "?")}.'
                ),
            },
        ],
        'duplicate_detected': True,
        'original_block': {
            'seq': existing_block.get('seq'),
            'block_hash': existing_block.get('block_hash', ''),
            'timestamp': record.get('timestamp_utc', ''),
            'document_id': record.get('document_id', ''),
            'candidate_id': record.get('candidate_id', ''),
        },
        'fingerprint': {
            'crypto_hash': fingerprint.get('crypto_hash', ''),
            'perceptual_hash': fingerprint.get('perceptual_hash', ''),
            'composite_hash': fingerprint.get('composite_hash', ''),
            'ledger_block': existing_block.get('seq'),
            'ledger_hash': (existing_block.get('block_hash', '')[:16] + '...'
                           if existing_block.get('block_hash') else ''),
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('public', 'index.html')


@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('public', path)


@app.route('/api/verify', methods=['POST'])
def verify_document():
    """Main verification endpoint with duplicate detection."""
    try:
        # Check file
        if 'document' not in request.files:
            return jsonify({'error': 'No document file uploaded'}), 400

        file = request.files['document']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type. Allowed: PDF, JPG, PNG'}), 400

        doc_type = request.form.get('docType', 'other')
        password = request.form.get('password', '')
        candidate_name = request.form.get('candidateName', '')
        candidate_dob = request.form.get('candidateDob', '')
        # is_scanned: only relevant for the 'other' (tamper) pipeline
        is_scanned = request.form.get('isScanned', 'false').lower() in ('true', '1', 'yes')

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        try:
            file.save(filepath)
            # ── Phase 0: Duplicate Check ────────────────────────────────────
            existing_block = _check_duplicate(filepath, password)
            if existing_block:
                return jsonify(_build_cached_response(existing_block))

            # ── Phase 1: Pipeline Execution ─────────────────────────────────
            pipeline_results = {}

            if doc_type == 'aadhaar':
                pipeline_results = verify_aadhaar(filepath, password)
                if pipeline_results.get('password_error'):
                    return jsonify({
                        'verdict': 'PENDING',
                        'verdictReason': pipeline_results['error'],
                        'error': pipeline_results['error'],
                        'password_error': True,
                        'checks': pipeline_results.get('checks', []),
                    }), 400
            elif doc_type == 'passport':
                pipeline_results = verify_passport(filepath)
            else:
                pipeline_results = detect_tampering(filepath, is_scanned=is_scanned)

            # ── Phase 2: Decision Engine ────────────────────────────────────
            final_result = compute_verdict(
                pipeline_results, doc_type, candidate_name, candidate_dob
            )

            # ── Phase 3: Digital Fingerprint + Blockchain Anchoring ─────────
            fingerprint = {}
            ledger_block = {}
            try:
                fingerprint = compute_document_fingerprint(filepath, pipeline_results, password=password)
                candidate_id = f"CAND-{hash(candidate_name + candidate_dob) & 0xFFFFFF:06X}"

                # Extract cross-check results from the decision engine output so the
                # ledger records name/DOB match status separately from the document verdict.
                cross_check_info: dict = {}
                if candidate_name or candidate_dob:
                    for check in final_result.get('checks', []):
                        if check.get('name') == 'Candidate Name Cross-Check':
                            cross_check_info['name_match'] = check.get('passed')
                            cross_check_info['name_provided'] = bool(candidate_name)
                        elif check.get('name') == 'Candidate DOB Cross-Check':
                            cross_check_info['dob_match'] = check.get('passed')
                    if cross_check_info:
                        cross_check_info['name_mismatch_caused_rejection'] = (
                            cross_check_info.get('name_match') is False
                            and final_result.get('verdict') == 'REJECTED'
                        )

                # Store the document-intrinsic verdict and confidence (before cross-check penalties)
                # in the ledger so a wrong candidate name input doesn't permanently taint the record.
                ledger_verdict = final_result.get('doc_intrinsic_verdict', final_result.get('verdict', 'UNKNOWN'))
                ledger_confidence = final_result.get('doc_intrinsic_confidence', final_result.get('confidenceScore', 0))

                verification_record = create_verification_record(
                    filepath=filepath,
                    doc_type=doc_type,
                    candidate_id=candidate_id,
                    fingerprint=fingerprint,
                    pipeline_result=pipeline_results,
                    verdict=ledger_verdict,
                    confidence=ledger_confidence,
                    cross_check=cross_check_info if cross_check_info else None,
                )
                # Classify against ledger using per-hash-type comparison (three-hash matrix)
                # This runs BEFORE appending so we compare against existing records only.
                ledger_classification = classify_document_against_ledger(fingerprint)

                ledger_block = append_record(verification_record)

                matched = ledger_classification.get('matched_block')

                # Build previous-submission context when this document was seen before
                prev_context: dict = {}
                if matched:
                    prev_rec = matched.get('record', {})
                    prev_verif = prev_rec.get('verification', {})
                    prev_cross = prev_verif.get('cross_check', {})
                    prev_context = {
                        'previous_block_seq': matched.get('seq'),
                        'previous_verdict': prev_verif.get('verdict'),
                        'previous_confidence': prev_verif.get('confidence_score'),
                        'previous_timestamp': prev_rec.get('timestamp_utc'),
                        'previous_name_mismatch': prev_cross.get('name_mismatch_caused_rejection', False),
                    }

                final_result['fingerprint'] = {
                    'crypto_hash': fingerprint.get('crypto_hash', ''),
                    'perceptual_hash': fingerprint.get('perceptual_hash', ''),
                    'content_hash': fingerprint.get('content_hash', ''),
                    'composite_hash': fingerprint.get('composite_hash', ''),
                    'ledger_block': ledger_block.get('seq'),
                    'ledger_hash': (ledger_block.get('block_hash', '')[:16] + '...'
                                   if ledger_block.get('block_hash') else ''),
                    'ledger_classification': {
                        'classification': ledger_classification.get('classification'),
                        'label': ledger_classification.get('label'),
                        'hash_comparison': ledger_classification.get('hash_comparison'),
                        'matched_block_seq': matched.get('seq') if matched else None,
                        **prev_context,
                    },
                }
            except Exception as fp_err:
                print(f"[WARN] Fingerprinting/ledger error (non-fatal): {fp_err}")
                final_result['fingerprint'] = {'error': str(fp_err)}

            return jsonify(final_result)

        finally:
            # Clean up uploaded file
            if os.path.exists(filepath):
                try:
                    os.remove(filepath)
                except:
                    pass

    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500



# ─────────────────────────────────────────────────────────────────────────────
# Cortex API Test Endpoint
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/test/cortex', methods=['GET'])
def test_cortex():
    """
    Smoke-test the Cortex API connection without uploading a document.
    Sends a 1x1 white pixel image with a simple prompt to verify auth + connectivity.
    GET /api/test/cortex
    """
    try:
        from pipelines.cortex_ocr import CORTEX_API_KEY, CORTEX_BASE_URL, GEMINI_MODEL, _cortex_client
        import httpx
        from PIL import Image as PILImage
        import io, base64

        if not CORTEX_API_KEY:
            return jsonify({'ok': False, 'error': 'CORTEX_API_KEY not set'}), 400

        # Tiny white image — just to test auth + connectivity, not a real document
        buf = io.BytesIO()
        PILImage.new('RGB', (8, 8), color=(255, 255, 255)).save(buf, format='PNG')
        img_b64 = base64.b64encode(buf.getvalue()).decode()

        client = _cortex_client(CORTEX_API_KEY, CORTEX_BASE_URL)
        response = client.chat.completions.create(
            model=GEMINI_MODEL,
            temperature=0,
            messages=[{
                "role": "user",
                "content": [
                    {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{img_b64}"}},
                    {"type": "text",      "text": "Reply with exactly: OK"},
                ],
            }],
        )
        reply = response.choices[0].message.content.strip()
        return jsonify({
            'ok': True,
            'model': GEMINI_MODEL,
            'base_url': CORTEX_BASE_URL,
            'reply': reply,
        })

    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# Ledger API Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/ledger/verify', methods=['GET'])
def ledger_verify():
    """Verify the integrity of the entire blockchain audit ledger."""
    try:
        result = verify_chain_integrity()
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/health', methods=['GET'])
def health():
    """Docker healthcheck endpoint."""
    return jsonify({'status': 'ok'}), 200


@app.route('/api/ledger/stats', methods=['GET'])
def ledger_stats():
    """Get summary statistics of the audit ledger."""
    try:
        stats = get_ledger_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ledger/lookup', methods=['GET'])
def ledger_lookup():
    """
    Look up past verifications by document hash or candidate ID.

    Query params:
      ?hash=<any_fingerprint_hash>  — look up by any of the 4 fingerprint hashes
      ?candidate=<candidate_id>     — look up all records for a candidate

    Examples:
      GET /api/ledger/lookup?hash=a3f1b2c3...
      GET /api/ledger/lookup?candidate=CAND-A1B2C3
    """
    try:
        doc_hash = request.args.get('hash', '').strip()
        cand_id  = request.args.get('candidate', '').strip()

        if doc_hash:
            block = lookup_document(doc_hash)
            if block:
                return jsonify({
                    'found': True,
                    'block': block,
                    'message': f'Document found at Block #{block.get("seq")}',
                })
            return jsonify({
                'found': False,
                'message': 'No matching document found in ledger',
            })

        if cand_id:
            blocks = lookup_candidate(cand_id)
            return jsonify({
                'found': bool(blocks),
                'count': len(blocks),
                'blocks': blocks,
                'message': (
                    f'Found {len(blocks)} record(s) for candidate {cand_id}'
                    if blocks else f'No records found for candidate {cand_id}'
                ),
            })

        return jsonify({
            'error': 'Provide ?hash=<fingerprint_hash> or ?candidate=<candidate_id>',
        }), 400

    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', '5000'))
    print("\n" + "=" * 60)
    print("  BGV Document Verification Engine v3.0")
    print("  Fingerprinting + Blockchain Audit Ledger ENABLED")
    print("  Duplicate detection: ON (crypto_hash pre-check)")
    print(f"  Server running at: http://0.0.0.0:{port}")
    print("=" * 60 + "\n")
    app.run(host='0.0.0.0', port=port, debug=False)

 
