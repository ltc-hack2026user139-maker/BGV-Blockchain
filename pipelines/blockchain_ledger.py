"""
BGV v3.0 — Hyperledger Fabric Blockchain Ledger
=================================================
Uses the Fabric peer CLI (subprocess) for on-chain storage when
FABRIC_GATEWAY_PEER is set, falling back to a local NDJSON file otherwise.

Required env vars for Fabric mode:
    FABRIC_GATEWAY_PEER       — peer address, e.g. localhost:7051
    FABRIC_MSP_ID             — MSP ID, e.g. Org1MSP
    FABRIC_MSP_CONFIG_PATH    — path to user MSP directory (contains signcerts/keystore)
    FABRIC_TLS_CERT_PATH      — path to peer TLS CA cert PEM
    FABRIC_ORDERER_ADDRESS    — orderer address, e.g. localhost:7050
    FABRIC_ORDERER_TLS_CERT   — path to orderer TLS CA cert PEM
    FABRIC_CFG_PATH           — path to Fabric config directory (core.yaml location)
    FABRIC_CHANNEL            — channel name, default bgvchannel
    FABRIC_CHAINCODE          — chaincode name, default bgv
"""

import hashlib
import json
import os
import re
import subprocess
import time
from typing import Optional

# ─── local fallback ledger (used when Fabric is not configured) ───────────────
_DEFAULT_LEDGER_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'bgv_ledger.ndjson'
)
LEDGER_PATH = os.environ.get('BGV_LEDGER_PATH', _DEFAULT_LEDGER_PATH)
_GENESIS_SENTINEL = 'BGV-GENESIS-v3.0'
_GENESIS_HASH_INPUT = 'BGV-GENESIS-v3.0|bgv_ledger.ndjson'

_USE_FABRIC = bool(os.environ.get('FABRIC_GATEWAY_PEER'))


# ─── Fabric CLI helpers ───────────────────────────────────────────────────────

def _peer_bin() -> str:
    """Return the absolute path to the peer binary (peer.exe on Windows, peer on Unix)."""
    fabric_bin = os.environ.get('FABRIC_BIN_PATH', '')
    if fabric_bin:
        for name in ('peer.exe', 'peer'):
            candidate = os.path.join(fabric_bin, name)
            if os.path.isfile(candidate):
                return candidate
    return 'peer'  # fall back to PATH lookup


def _peer_env() -> dict:
    """Build an env dict for peer CLI subprocesses from BGV env vars."""
    env = os.environ.copy()
    env['CORE_PEER_TLS_ENABLED']       = 'true'
    env['CORE_PEER_LOCALMSPID']        = os.environ.get('FABRIC_MSP_ID', 'Org1MSP')
    env['CORE_PEER_ADDRESS']           = os.environ.get('FABRIC_GATEWAY_PEER', 'localhost:7051')
    env['CORE_PEER_TLS_ROOTCERT_FILE'] = os.environ.get('FABRIC_TLS_CERT_PATH', '')
    env['CORE_PEER_MSPCONFIGPATH']     = os.environ.get('FABRIC_MSP_CONFIG_PATH', '')
    if os.environ.get('FABRIC_CFG_PATH'):
        env['FABRIC_CFG_PATH'] = os.environ['FABRIC_CFG_PATH']
    return env


def _fabric_evaluate(function: str, *args: str) -> bytes:
    """Run a peer chaincode query (read-only). Returns raw JSON bytes."""
    channel   = os.environ.get('FABRIC_CHANNEL', 'bgvchannel')
    chaincode = os.environ.get('FABRIC_CHAINCODE', 'bgv')
    payload   = json.dumps({'function': function, 'Args': list(args)})

    result = subprocess.run(
        [_peer_bin(), 'chaincode', 'query', '-C', channel, '-n', chaincode, '-c', payload],
        capture_output=True, text=True, env=_peer_env(), timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"peer query {function} failed: {result.stderr.strip()}")
    return result.stdout.strip().encode()


def _fabric_submit(function: str, *args: str) -> bytes:
    """Run a peer chaincode invoke (state-changing). Returns chaincode response bytes."""
    channel   = os.environ.get('FABRIC_CHANNEL', 'bgvchannel')
    chaincode = os.environ.get('FABRIC_CHAINCODE', 'bgv')
    orderer   = os.environ.get('FABRIC_ORDERER_ADDRESS', 'localhost:7050')
    cafile    = os.environ.get('FABRIC_ORDERER_TLS_CERT', '')
    peer1     = os.environ.get('FABRIC_GATEWAY_PEER', 'localhost:7051')
    tls1      = os.environ.get('FABRIC_TLS_CERT_PATH', '')
    peer2     = os.environ.get('FABRIC_PEER2_ADDRESS', '')
    tls2      = os.environ.get('FABRIC_PEER2_TLS_CERT', '')
    payload   = json.dumps({'function': function, 'Args': list(args)})

    cmd = [
        _peer_bin(), 'chaincode', 'invoke',
        '-o', orderer,
        '--ordererTLSHostnameOverride', 'orderer.example.com',
        '--tls', '--cafile', cafile,
        '-C', channel, '-n', chaincode,
        '--peerAddresses', peer1, '--tlsRootCertFiles', tls1,
        '-c', payload,
        '--waitForEvent',
    ]
    if peer2 and tls2:
        # Insert second org peer before the -c flag for endorsement policy
        idx = cmd.index('-c')
        cmd[idx:idx] = ['--peerAddresses', peer2, '--tlsRootCertFiles', tls2]

    result = subprocess.run(
        cmd, capture_output=True, text=True, env=_peer_env(), timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(f"peer invoke {function} failed: {result.stderr.strip()}")

    # Fabric CLI prints the chaincode response payload in stderr as:
    #   Chaincode invoke successful. result: status:200 payload:"<escaped-json>"
    match = re.search(r'payload:"((?:[^"\\]|\\.)*)"', result.stderr)
    if match:
        raw = match.group(1).replace('\\"', '"').replace('\\\\', '\\')
        return raw.encode()
    return b'{}'


# ─── local fallback helpers ───────────────────────────────────────────────────

def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def _read_ledger() -> list:
    if not os.path.exists(LEDGER_PATH):
        return []
    blocks = []
    with open(LEDGER_PATH, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    blocks.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return blocks


def _append_block(block: dict) -> None:
    os.makedirs(os.path.dirname(LEDGER_PATH) if os.path.dirname(LEDGER_PATH) else '.', exist_ok=True)
    with open(LEDGER_PATH, 'a', encoding='utf-8') as f:
        f.write(json.dumps(block, sort_keys=True, default=str) + '\n')


def _get_latest_hash() -> str:
    blocks = _read_ledger()
    if not blocks:
        return _sha256(_GENESIS_HASH_INPUT)
    return blocks[-1].get('block_hash', _sha256(_GENESIS_SENTINEL))


# ─── Public API ───────────────────────────────────────────────────────────────

def append_record(verification_record: dict) -> dict:
    """Append a VerificationRecord to the immutable ledger."""
    if _USE_FABRIC:
        result = _fabric_submit('AppendRecord', json.dumps(verification_record, default=str))
        block = json.loads(result) if result and result != b'{}' else {}
        print(f"[LEDGER/FABRIC] Block #{block.get('seq', '?')} anchored — hash: {str(block.get('block_hash', ''))[:16]}...")
        return block

    # ── local fallback ────────────────────────────────────────────────────────
    prev_hash = _get_latest_hash()
    blocks = _read_ledger()
    seq = len(blocks)
    timestamp_utc = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

    block = {
        'seq': seq,
        'prev_hash': prev_hash,
        'timestamp_utc': timestamp_utc,
        'record': verification_record,
    }
    block_json = json.dumps(block, sort_keys=True, default=str)
    block['block_hash'] = _sha256(block_json)
    _append_block(block)
    print(f"[LEDGER] Block #{seq} anchored — hash: {block['block_hash'][:16]}...")
    return block


def lookup_document(doc_hash: str) -> Optional[dict]:
    """Look up a verification record by any fingerprint hash."""
    if _USE_FABRIC:
        result = _fabric_evaluate('LookupDocument', doc_hash)
        data = json.loads(result)
        return data if data else None

    blocks = _read_ledger()
    for block in reversed(blocks):
        record = block.get('record', {})
        fingerprint = record.get('fingerprint', {})
        if doc_hash in (
            fingerprint.get('crypto_hash'),
            fingerprint.get('perceptual_hash'),
            fingerprint.get('content_hash'),
            fingerprint.get('composite_hash'),
            record.get('document_id'),
        ):
            return block
    return None


def classify_document_against_ledger(fingerprint: dict) -> dict:
    """Compare a document's fingerprint against all ledger blocks."""
    if _USE_FABRIC:
        result = _fabric_evaluate('ClassifyDocument', json.dumps(fingerprint, default=str))
        return json.loads(result)

    blocks = _read_ledger()
    new_crypto  = fingerprint.get('crypto_hash')
    new_phash   = fingerprint.get('perceptual_hash')
    new_content = fingerprint.get('content_hash')

    best_match: Optional[dict] = None
    best_comparison: dict = {'crypto': False, 'phash': False, 'content': False}

    for block in reversed(blocks):
        fp = block.get('record', {}).get('fingerprint', {})
        crypto_match  = bool(new_crypto  and fp.get('crypto_hash')  == new_crypto)
        phash_match   = bool(new_phash   and fp.get('perceptual_hash') and fp.get('perceptual_hash') == new_phash)
        content_match = bool(new_content and fp.get('content_hash') == new_content)
        if crypto_match or phash_match or content_match:
            best_match = block
            best_comparison = {
                'crypto': crypto_match,
                'phash': phash_match,
                'content': content_match,
                'phash_available': bool(new_phash and fp.get('perceptual_hash')),
            }
            break

    if best_match is None:
        return {
            'classification': 'new_document',
            'label': 'New document',
            'matched_block': None,
            'hash_comparison': {'crypto': False, 'phash': False, 'content': False},
        }

    c = best_comparison['crypto']
    p = best_comparison['phash']
    n = best_comparison['content']
    p_avail = best_comparison.get('phash_available', False)

    if c and n:
        label, key = 'Duplicate exact file', 'duplicate'
    elif c and not n:
        label, key = 'Suspicious corruption: byte match but metrics diverge', 'suspicious_corruption'
    elif not c and p_avail and p and n:
        label, key = 'Same document resubmitted in another format', 'resubmit_different_format'
    elif not c and p_avail and p and not n:
        label, key = 'Possible tampering: same image, OCR/content changed — review', 'possible_tamper'
    elif not c and n:
        label, key = 'Same identity document, different capture or scan', 'different_scan'
    else:
        label, key = 'New document', 'new_document'

    return {
        'classification': key,
        'label': label,
        'matched_block': best_match,
        'hash_comparison': best_comparison,
    }


def lookup_candidate(candidate_id: str) -> list:
    """Return all verification records for a given candidate."""
    if _USE_FABRIC:
        result = _fabric_evaluate('LookupCandidate', candidate_id)
        return json.loads(result) or []

    blocks = _read_ledger()
    return [
        b for b in blocks
        if b.get('record', {}).get('candidate_id') == candidate_id
    ]


def verify_chain_integrity() -> dict:
    """Walk the entire ledger and verify every block's hash chain."""
    if _USE_FABRIC:
        result = _fabric_evaluate('VerifyChainIntegrity')
        return json.loads(result)

    blocks = _read_ledger()
    errors = []
    chain_details = []
    genesis_hash = _sha256(_GENESIS_HASH_INPUT)

    if not blocks:
        return {'valid': True, 'total_blocks': 0, 'errors': [], 'chain': []}

    expected_prev = genesis_hash

    for idx, block in enumerate(blocks):
        seq = block.get('seq')
        actual_prev = block.get('prev_hash', '')
        record = block.get('record', {})
        block_errors = []

        if seq != idx:
            msg = f"Block {idx}: seq mismatch (expected {idx}, got {seq})"
            errors.append(msg); block_errors.append(msg)

        chain_ok = actual_prev == expected_prev
        if not chain_ok:
            msg = f"Block {idx}: prev_hash broken"
            errors.append(msg); block_errors.append(msg)

        stored_hash = block.pop('block_hash', None)
        recomputed_json = json.dumps(block, sort_keys=True, default=str)
        recomputed_hash = _sha256(recomputed_json)
        block['block_hash'] = stored_hash

        hash_ok = recomputed_hash == stored_hash
        if not hash_ok:
            msg = f"Block {idx}: block_hash invalid — record tampered"
            errors.append(msg); block_errors.append(msg)

        chain_details.append({
            'seq': idx,
            'block_hash': (stored_hash[:24] + '...') if stored_hash else None,
            'block_hash_full': stored_hash,
            'chain_link_valid': chain_ok,
            'block_hash_valid': hash_ok,
            'valid': chain_ok and hash_ok,
            'timestamp': block.get('timestamp_utc', record.get('timestamp_utc', '')),
            'doc_type': record.get('doc_type', ''),
            'verdict': record.get('verification', {}).get('verdict', ''),
            'candidate_id': record.get('candidate_id', ''),
            'errors': block_errors,
        })
        expected_prev = stored_hash or recomputed_hash

    return {
        'valid': len(errors) == 0,
        'total_blocks': len(blocks),
        'errors': errors,
        'chain': chain_details,
    }


def get_ledger_stats() -> dict:
    """Return summary statistics about the current ledger state."""
    if _USE_FABRIC:
        result = _fabric_evaluate('GetLedgerStats')
        stats = json.loads(result)
        stats['ledger_path'] = 'hyperledger-fabric'
        return stats

    blocks = _read_ledger()
    verdicts: dict = {}
    doc_types: dict = {}

    for block in blocks:
        record = block.get('record', {})
        verdict = record.get('verification', {}).get('verdict', 'UNKNOWN')
        doc_type = record.get('doc_type', 'UNKNOWN')
        verdicts[verdict] = verdicts.get(verdict, 0) + 1
        doc_types[doc_type] = doc_types.get(doc_type, 0) + 1

    latest_hash = blocks[-1].get('block_hash', 'N/A') if blocks else 'N/A'

    return {
        'total_records': len(blocks),
        'latest_hash': latest_hash,
        'verdicts': verdicts,
        'doc_types': doc_types,
        'ledger_path': LEDGER_PATH,
    }
