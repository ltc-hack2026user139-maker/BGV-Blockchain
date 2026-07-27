# BGV v3.0 — Blockchain Audit Ledger

## Table of Contents

1. [Overview](#overview)
2. [Dual-Mode Architecture](#dual-mode-architecture)
3. [Three-Layer Fingerprint](#three-layer-fingerprint)
4. [Local Hash-Chain Ledger (Development)](#local-hash-chain-ledger-development)
5. [Hyperledger Fabric Ledger (Production)](#hyperledger-fabric-ledger-production)
6. [JavaScript Chaincode](#javascript-chaincode)
7. [Duplicate Detection Flow](#duplicate-detection-flow)
8. [API Endpoints](#api-endpoints)
9. [Security Properties](#security-properties)
10. [Deployment Guide](#deployment-guide)

---

## Overview

Every document processed by the BGV engine receives a **three-layer digital fingerprint** and its verification record is permanently anchored to an **immutable hash-chained ledger**.

This transforms the system from a point-in-time verification check into a **verifiable, tamper-proof audit ecosystem** that:

| Capability | Description |
|---|---|
| **Replay Detection** | Same document → same SHA-256 → flagged as duplicate, pipeline skipped |
| **Cross-Employer Portability** | Candidate shares `composite_hash`; new employer queries `/api/ledger/lookup` |
| **Non-Repudiation** | Block timestamp + chain hash proves when verification occurred |
| **Tamper Evidence** | Any modification to historical records breaks all subsequent hashes |
| **PII Protection** | Only hashes stored — no names, DOBs, or document images |
| **Legal Audit Trail** | Immutable ledger provides compliance-ready verification history |

---

## Dual-Mode Architecture

The BGV application supports two ledger backends, selected automatically via environment variable:

```
FABRIC_GATEWAY_PEER=           →  Local NDJSON mode (development / demo)
FABRIC_GATEWAY_PEER=peer0.org1.example.com:7051  →  Hyperledger Fabric mode (production)
```

No code changes are needed to switch modes — `blockchain_ledger.py` detects `_USE_FABRIC = bool(os.environ.get('FABRIC_GATEWAY_PEER'))` at startup and routes all calls accordingly.

```
                    ┌─────────────────────────────────────┐
                    │  blockchain_ledger.py               │
                    │                                     │
                    │   _USE_FABRIC = bool(env var)       │
                    │          │                          │
                    │     ┌────┴─────┐                    │
                    │     │         │                     │
                    │  False     True                     │
                    │     │         │                     │
                    │     ▼         ▼                     │
                    │  NDJSON    Fabric                   │
                    │  (local)   Gateway                  │
                    └─────────────────────────────────────┘
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `FABRIC_GATEWAY_PEER` | *(empty)* | Fabric peer endpoint — blank = local mode |
| `FABRIC_MSP_ID` | `Org1MSP` | MSP identifier for the submitting organization |
| `FABRIC_CERT_PATH` | `/fabric/certs/...` | Path to signing certificate |
| `FABRIC_KEY_PATH` | `/fabric/keystore/priv_sk` | Path to private key |
| `FABRIC_TLS_CERT_PATH` | `/fabric/tls/ca.crt` | TLS root CA certificate |
| `FABRIC_CHANNEL` | `bgvchannel` | Channel where chaincode is deployed |
| `FABRIC_CHAINCODE` | `bgv` | Chaincode name |
| `BGV_LEDGER_PATH` | `bgv_ledger.ndjson` | Path for local NDJSON fallback |

---

## Three-Layer Fingerprint

Each document gets a unique composite fingerprint constructed from three independent hash layers:

| Layer | Hash Type | What It Captures | Tamper Sensitivity |
|---|---|---|---|
| **Layer 1** | SHA-256 (raw bytes) | Byte-exact file identity | Any single byte change → completely different hash |
| **Layer 2** | Perceptual Hash (pHash) | Visual appearance of rendered document | Detects visual edits; robust to minor encoding changes |
| **Layer 3** | Content Hash (SHA-256) | MRZ data / QR payload / OCR text | Binds fingerprint to semantic document content |
| **Composite** | SHA-256(L1\|L2\|L3) | All three layers combined | Single tamper-proof identifier |

### Implementation

```python
# Layer 1: Cryptographic Hash
crypto_hash = SHA256(raw_file_bytes)

# Layer 2: Perceptual Hash (64-bit DCT-based pHash)
# Resize to 32×32 greyscale → 2D DCT → top-left 8×8 → median threshold → 64-bit
perceptual_hash = pHash(rendered_image)

# Layer 3: Content Hash (document-type-specific)
# Passport: SHA256(passport_number|dob|expiry|nationality|full_name)
# Aadhaar:  SHA256(name|dob|gender)
# Other:    SHA256(flags + module_scores)
content_hash = SHA256(extracted_fields)

# Composite: binds all three layers
composite_hash = SHA256(crypto_hash | perceptual_hash | content_hash)
```

### pHash Similarity

Two documents are considered visually identical if their pHash Hamming distance is ≤ 10 bits:

```python
similarity = 1.0 - (hamming_distance / 64.0)
# similarity ≥ 0.84 → same visual document
```

---

## Local Hash-Chain Ledger (Development)

### Storage Format

The ledger is stored as **NDJSON** (Newline-Delimited JSON) at `bgv_ledger.ndjson`. Each line is one block:

```
{"seq":0,"prev_hash":"<genesis>","timestamp_utc":"...","record":{...},"block_hash":"..."}
{"seq":1,"prev_hash":"<block_0_hash>","timestamp_utc":"...","record":{...},"block_hash":"..."}
```

### Chain Structure

```
Genesis Hash = SHA256("BGV-GENESIS-v3.0|bgv_ledger.ndjson")   ← constant, not path-dependent
     │
Block 0: { seq:0, prev_hash: genesis_hash, record: {...}, timestamp }
     │  block_hash_0 = SHA256(sort_keys_canonical_JSON_of_block_0_without_block_hash)
     │
Block 1: { seq:1, prev_hash: block_hash_0, record: {...}, timestamp }
     │  block_hash_1 = SHA256(sort_keys_canonical_JSON_of_block_1_without_block_hash)
     │
Block 2: { seq:2, prev_hash: block_hash_1, record: {...}, timestamp }
     ⋮
```

**Important:** The genesis sentinel string is `"BGV-GENESIS-v3.0|bgv_ledger.ndjson"` — a fixed constant in both Python (`_GENESIS_HASH_INPUT`) and the JavaScript chaincode (`GENESIS_SENTINEL`). Both compute the same genesis hash, ensuring chain continuity when migrating from local to Fabric.

### Block Schema

```json
{
    "seq": 0,
    "prev_hash": "a1b2c3...",
    "timestamp_utc": "2026-06-28T08:00:00Z",
    "record": {
        "schema_version": "3.0",
        "document_id": "DOC-1751097600000",
        "doc_type": "passport",
        "candidate_id": "CAND-A1B2C3",
        "timestamp_utc": "2026-06-28T08:00:00Z",
        "engine_version": "tamper-detection-v3.0",
        "fingerprint": {
            "crypto_hash": "a3f1...",
            "perceptual_hash": "f0e1d2c3b4a59687",
            "content_hash": "7b2c...",
            "composite_hash": "9d4e..."
        },
        "verification": {
            "verdict": "VERIFIED",
            "confidence_score": 95,
            "flags": [],
            "pipeline": "passport"
        },
        "record_hash": "e5f6..."
    },
    "block_hash": "d4e5f6..."
}
```

### Integrity Verification

`verify_chain_integrity()` walks the entire ledger and checks:

1. **Block hash validity**: Each block's `block_hash` equals `SHA256(sorted_JSON(block_without_block_hash))`
2. **Chain continuity**: Each block's `prev_hash` equals the previous block's `block_hash`
3. **Sequence continuity**: Block sequence numbers are contiguous (0, 1, 2, ...)

Any tampering with any historical record breaks all subsequent hashes, making fraud detectable via `GET /api/ledger/verify`.

---

## Hyperledger Fabric Ledger (Production)

### Network

The production BGV ledger runs on Hyperledger Fabric **2.5.16** using the `fabric-samples` test-network topology:

```
┌──────────────────────────────────────────────────────────┐
│                  BGV Flask Application                    │
│                                                          │
│   fabric-gateway (Python SDK)  ──gRPC──►  peer0.org1    │
│   grpcio + credentials from .env                        │
└──────────────────────────────────────────────────────────┘
                        │ gRPC :7051
                        ▼
┌──────────────────────────────────────────────────────────┐
│              Hyperledger Fabric 2.5 Network               │
│                                                          │
│  ┌──────────────────────┐  ┌──────────────────────────┐  │
│  │     Org1             │  │     Org2                 │  │
│  │  peer0 (:7051)       │  │  peer0 (:9051)           │  │
│  │  CouchDB world state │  │  CouchDB world state     │  │
│  └──────────┬───────────┘  └──────────┬───────────────┘  │
│             │                         │                   │
│  ┌──────────▼─────────────────────────▼───────────────┐   │
│  │          Raft Ordering Service (:7050)             │   │
│  └─────────────────────────────────────────────────── ┘   │
│                                                          │
│  Channel: bgvchannel                                     │
│  Chaincode: bgv  (Node.js, bgv-chaincode-js)             │
└──────────────────────────────────────────────────────────┘
```

### Python Gateway Integration

`blockchain_ledger.py` uses the `fabric-gateway` Python SDK:

```python
import grpc
from grpc import ssl_channel_credentials
import fabric_gateway

# Fabric connection (when FABRIC_GATEWAY_PEER is set)
def _fabric_connection():
    tls_cert = open(FABRIC_TLS_CERT_PATH, 'rb').read()
    creds = ssl_channel_credentials(root_certificates=tls_cert)
    channel = grpc.secure_channel(FABRIC_GATEWAY_PEER, creds)
    # ... connect with signing identity from FABRIC_CERT_PATH / FABRIC_KEY_PATH
```

### Chaincode Functions (JavaScript)

The deployed chaincode (`bgv-chaincode-js/index.js`) exposes:

| Function | Type | Description |
|---|---|---|
| `AppendRecord(recordJSON)` | invoke | Append a new verification block to the ledger |
| `LookupDocument(docHash)` | query | Find the most recent block matching any fingerprint hash |
| `LookupCandidate(candidateId)` | query | Return all blocks for a candidate (oldest first) |
| `ClassifyDocument(fingerprintJSON)` | query | Compare fingerprint against ledger, return classification |
| `VerifyChainIntegrity()` | query | Walk all blocks and verify hash chain + block hashes |
| `GetLedgerStats()` | query | Return total counts, verdicts, doc types, latest hash |

### Document Classification Matrix

`ClassifyDocument` returns one of these classifications based on 3-hash comparison:

| crypto | phash | content | Classification | Key |
|---|---|---|---|---|
| ✅ | — | ✅ | Duplicate exact file | `duplicate` |
| ✅ | — | ❌ | Suspicious: byte match but metrics diverge | `suspicious_corruption` |
| ❌ | ✅ | ✅ | Same document in different format | `resubmit_different_format` |
| ❌ | ✅ | ❌ | Possible tampering: same image, OCR changed | `possible_tamper` |
| ❌ | ❌ | ✅ | Same identity doc, different scan | `different_scan` |
| ❌ | ❌ | ❌ | New document | `new_document` |

---

## JavaScript Chaincode

The chaincode in `~/fabric-samples/bgv-chaincode-js/index.js` is production-ready:

```javascript
'use strict';

const { Contract } = require('fabric-contract-api');
const crypto = require('crypto');

const BLOCK_COUNTER_KEY = 'BLOCK_COUNTER';
const GENESIS_SENTINEL = 'BGV-GENESIS-v3.0|bgv_ledger.ndjson';  // matches Python

// Deterministic JSON matching Python's json.dumps(sort_keys=True)
function sortedJSON(obj) {
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
        return JSON.stringify(obj);
    }
    const sorted = Object.keys(obj).sort().reduce((acc, k) => {
        acc[k] = obj[k];
        return acc;
    }, {});
    return '{' + Object.keys(sorted).map(k =>
        JSON.stringify(k) + ':' + sortedJSON(sorted[k])
    ).join(',') + '}';
}
```

**Critical design points:**
- `sortedJSON()` ensures deterministic serialization matching Python's `json.dumps(sort_keys=True)` — both sides produce the same block hash
- `GENESIS_SENTINEL` is an exact string constant — not a path, not derived from environment — so genesis hash is identical across Python and JavaScript
- Block hash is `SHA256(sortedJSON(block_body_without_block_hash_field))`
- `VerifyChainIntegrity` returns a full `chain` array with per-block status for the `/api/ledger/verify` endpoint

### package.json

```json
{
  "name": "bgv-chaincode",
  "version": "1.0.0",
  "scripts": {
    "start": "fabric-chaincode-node start"
  },
  "dependencies": {
    "fabric-shim": "~2.5.6",
    "fabric-contract-api": "~2.5.6"
  }
}
```

---

## Duplicate Detection Flow

When a new document is uploaded, the system performs early detection **before** running any pipeline:

```
Upload Document
     │
     ▼
Phase 0: compute SHA-256(file_bytes)
     │
     ▼
lookup_document(crypto_hash) in ledger
     │
     ├── MATCH FOUND ──► Return cached verdict instantly
     │                    (skip pipeline entirely)
     │                    Response includes:
     │                    • duplicate_detected: true
     │                    • original_block: { seq, hash, timestamp }
     │                    • Original verdict + confidence
     │
     └── NO MATCH ────► Run full pipeline (Phase 1–3)
                         Anchor new block to ledger
```

### Classification on Ledger Lookup

| Hash | Purpose |
|---|---|
| `crypto_hash` (SHA-256 of raw bytes) | Exact file duplicate detection |
| `perceptual_hash` (pHash) | Near-visual-duplicate detection |
| `content_hash` (SHA-256 of fields) | Semantic content duplicate detection |
| `composite_hash` (SHA-256 of all) | Combined fingerprint lookup |

### Performance

- **Duplicate detected**: < 50ms (hash lookup only)
- **Full pipeline**: 5–30s (OCR, ELA, noise analysis, Cortex API)

---

## API Endpoints

### `POST /api/verify`

Main verification endpoint. Automatically checks for duplicates before running the pipeline.

**Response with duplicate detected:**
```json
{
    "duplicate_detected": true,
    "verdict": "VERIFIED",
    "confidenceScore": 95,
    "verdictReason": "This document was previously verified...",
    "original_block": {
        "seq": 3,
        "block_hash": "a1b2c3...",
        "timestamp": "2026-06-28T08:00:00Z"
    },
    "fingerprint": {
        "crypto_hash": "...",
        "perceptual_hash": "...",
        "composite_hash": "...",
        "ledger_block": 3
    }
}
```

### `GET /api/ledger/verify`

Verify the integrity of the entire blockchain audit ledger.

```json
{
    "valid": true,
    "total_blocks": 42,
    "errors": [],
    "chain": [
        {
            "seq": 0,
            "block_hash": "a1b2c3d4e5f6789012345678...",
            "chain_link_valid": true,
            "block_hash_valid": true,
            "valid": true,
            "timestamp": "2026-06-28T08:00:00Z",
            "doc_type": "passport",
            "verdict": "VERIFIED"
        }
    ]
}
```

### `GET /api/ledger/stats`

Get summary statistics of the audit ledger.

```json
{
    "total_records": 42,
    "latest_hash": "d4e5f6...",
    "verdicts": { "VERIFIED": 35, "SUSPICIOUS": 5, "REJECTED": 2 },
    "doc_types": { "passport": 20, "aadhaar": 15, "other": 7 }
}
```

### `GET /api/ledger/lookup?hash=<hash>`

Look up a past verification by any of the 4 fingerprint hashes.

```json
{
    "found": true,
    "block": { "seq": 3, "record": {...}, "block_hash": "..." },
    "message": "Document found at Block #3"
}
```

### `GET /api/ledger/lookup?candidate=<candidate_id>`

Look up all verification records for a candidate.

```json
{
    "found": true,
    "count": 3,
    "blocks": [ {...}, {...}, {...} ],
    "message": "Found 3 record(s) for candidate CAND-A1B2C3"
}
```

---

## Security Properties

| Property | Local NDJSON | Hyperledger Fabric |
|---|---|---|
| **Non-repudiation** | Block timestamp + chain hash | Block timestamp + Fabric orderer proof |
| **Tamper-evidence** | SHA-256 chain breaks on modification | Distributed peer consensus + chain hashing |
| **PII-protection** | Only hashes stored | Only hashes stored |
| **Replay detection** | SHA-256 lookup | SHA-256 lookup via CouchDB world state |
| **Immutability** | File-based (deletable) | Distributed append-only ledger |
| **Access control** | None (file permissions) | Channel-based MSP policies |
| **Consensus** | Single-node (no consensus) | Raft ordering (crash fault tolerant) |

---

## Deployment Guide

### Local Development (NDJSON mode)

```bash
# No Fabric required — just run the Flask app
FABRIC_GATEWAY_PEER=  # blank = local mode
python server.py
```

### Deploy Chaincode to Fabric Test Network

```bash
cd ~/fabric-samples/test-network

# 1. Start the network with CA and CouchDB
./network.sh up createChannel -c bgvchannel -ca -s couchdb

# 2. Install npm dependencies in chaincode directory
cd ~/fabric-samples/bgv-chaincode-js
npm install

# 3. Deploy chaincode
cd ~/fabric-samples/test-network
./network.sh deployCC \
  -c bgvchannel \
  -ccn bgv \
  -ccp ~/fabric-samples/bgv-chaincode-js \
  -ccl javascript

# 4. Test chaincode
peer chaincode query -C bgvchannel -n bgv \
  -c '{"function":"GetLedgerStats","Args":[]}'
```

### Connect BGV App to Fabric

Set these in `.env` (or Docker environment):

```bash
FABRIC_GATEWAY_PEER=peer0.org1.example.com:7051
FABRIC_MSP_ID=Org1MSP
FABRIC_CERT_PATH=/fabric/certs/User1@org1.example.com-cert.pem
FABRIC_KEY_PATH=/fabric/keystore/priv_sk
FABRIC_TLS_CERT_PATH=/fabric/tls/ca.crt
FABRIC_CHANNEL=bgvchannel
FABRIC_CHAINCODE=bgv
```

### Docker Compose Deployment

The `docker-compose.yml` in the BGV repo mounts Fabric crypto material:

```yaml
volumes:
  - ~/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/signcerts:/fabric/certs:ro
  - ~/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/keystore:/fabric/keystore:ro
  - ~/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls:/fabric/tls:ro
```

---

## File Reference

| File | Purpose |
|---|---|
| `pipelines/fingerprint.py` | Three-layer fingerprint computation |
| `pipelines/blockchain_ledger.py` | Dual-mode ledger (NDJSON + Fabric gateway) |
| `server.py` | API routes including duplicate detection and ledger endpoints |
| `bgv_ledger.ndjson` | Local NDJSON ledger data file (auto-created) |
| `~/fabric-samples/bgv-chaincode-js/index.js` | Hyperledger Fabric chaincode (JavaScript) |
| `~/fabric-samples/bgv-chaincode-js/package.json` | Chaincode npm dependencies |
| `.env` | Fabric connection config (FABRIC_GATEWAY_PEER etc.) |
| `docker-compose.yml` | Container deployment with Fabric crypto mounts |
| `BLOCKCHAIN.md` | This documentation |
