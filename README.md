# BGV Document Verification Engine

Automated document authenticity verification for Background Verification (BGV) workflows.
Supports Aadhaar, Passport, and general documents (degree certificates, payslips, experience letters).
Every verification is anchored as an immutable block on a Hyperledger Fabric blockchain.

---

## Project Structure

```
BGV-Tamper-detection/
│
├── server.py                        # Flask API server — entry point
├── requirements.txt                 # Python dependencies
├── docker-compose.yml               # Optional: run BGV server in Docker
├── Dockerfile
├── .env.example                     # Environment variable template
│
├── pipelines/                       # Verification pipeline modules
│   ├── aadhaar.py                   # Aadhaar: QR signature + OCR field cross-check
│   ├── passport.py                  # Passport: MRZ checksum + VIZ field cross-check
│   ├── tamper.py                    # Universal tamper detection (ELA, metadata, fonts, copy-move)
│   ├── decision_engine.py           # Aggregates pipeline scores → VERIFIED / SUSPICIOUS / REJECTED
│   ├── fingerprint.py               # SHA-256 + perceptual hash + content hash fingerprinting
│   ├── blockchain_ledger.py         # Hyperledger Fabric integration (peer CLI via subprocess)
│   └── cortex_ocr.py                # OCR via Cortex / Gemini API
│
├── public/                          # Frontend (static HTML/CSS/JS served by Flask)
│
├── Blockchain-fabric/               # Hyperledger Fabric components
│   ├── bgv-chaincode-js/            # Smart contract (Node.js / fabric-contract-api)
│   │   ├── index.js                 # Chaincode entry point
│   │   ├── bgvContract.js           # AppendRecord, LookupDocument, GetLedgerStats, etc.
│   │   └── package.json
│   └── test-network/                # Fabric test network setup scripts
│       ├── network.sh               # Bring network up/down
│       └── deployChaincode.sh       # Deploy bgv chaincode to bgvchannel
│
└── Architecture-docs/               # System design documentation
    ├── ARCHITECTURE_DIAGRAMS.md
    ├── BLOCKCHAIN.md
    ├── VALIDATION_ARCHITECTURE.md
    └── *.png                        # Pipeline and architecture diagrams
```

---

## How It Works

```
Browser → Flask API (server.py)
              ↓
    ┌─────────────────────┐
    │  Pipeline Selection  │
    │  Aadhaar / Passport  │
    │  / Tamper Detection  │
    └─────────────────────┘
              ↓
    ┌─────────────────────┐
    │   Decision Engine    │
    │  Confidence scoring  │
    │  VERIFIED/SUSPICIOUS │
    │  /REJECTED verdict   │
    └─────────────────────┘
              ↓
    ┌─────────────────────┐
    │  Blockchain Ledger   │
    │  peer CLI → Fabric   │
    │  Block anchored on   │
    │  bgvchannel (Fabric) │
    └─────────────────────┘
```

### Pipelines

| Pipeline | Documents | Key Checks |
|----------|-----------|------------|
| Aadhaar | Aadhaar card (PDF/image) | QR RSA-SHA256 signature (UIDAI key), QR vs OCR field match |
| Passport | Passport (PDF/image) | MRZ ICAO-9303 checksums, MRZ vs visual zone match |
| Tamper Detection | Any document | ELA, metadata forensics, font consistency, pixel boundary, copy-move detection |

### Blockchain (Hyperledger Fabric)

- Channel: `bgvchannel`, Chaincode: `bgv` (Node.js)
- Every verified document writes a block: fingerprint hashes + verdict + timestamp
- Duplicate detection: before running the pipeline, the document's SHA-256 is checked against the ledger — if found, the cached verdict is returned instantly
- Chaincode functions: `AppendRecord`, `LookupDocument`, `ClassifyDocument`, `LookupCandidate`, `VerifyChainIntegrity`, `GetLedgerStats`

---

## Quick Start

### Prerequisites
- Python 3.11+
- Docker Desktop (for Hyperledger Fabric)
- Hyperledger Fabric binaries (`peer`, `configtxgen`) in PATH or set `FABRIC_BIN_PATH`

### 1. Start Fabric Network

```bash
cd Blockchain-fabric/test-network
./network.sh up createChannel -c bgvchannel -ca
./deployChaincode.sh
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env — fill in cert paths and Fabric peer addresses
```

Key `.env` variables:

```
FABRIC_GATEWAY_PEER=localhost:7051
FABRIC_MSP_ID=Org1MSP
FABRIC_MSP_CONFIG_PATH=<path-to-Admin-msp-dir>
FABRIC_TLS_CERT_PATH=<path-to-org1-tlsca-cert>
FABRIC_PEER2_ADDRESS=localhost:9051
FABRIC_PEER2_TLS_CERT=<path-to-org2-tlsca-cert>
FABRIC_ORDERER_ADDRESS=localhost:7050
FABRIC_ORDERER_TLS_CERT=<path-to-orderer-tlsca-cert>
FABRIC_CFG_PATH=<path-to-fabric-samples/config/>
FABRIC_BIN_PATH=<path-to-fabric-samples/bin>
FABRIC_CHANNEL=bgvchannel
FABRIC_CHAINCODE=bgv
```

Leave `FABRIC_GATEWAY_PEER` blank to run with a local NDJSON ledger (no Fabric required).

### 3. Install Dependencies and Run

```bash
pip install -r requirements.txt
python server.py
```

App runs at `http://localhost:5000`

### 4. Verify Blockchain is Connected

```bash
peer chaincode query -C bgvchannel -n bgv -c '{"function":"GetLedgerStats","Args":[]}'
# {"total_records":0,"latest_hash":"N/A","verdicts":{},"doc_types":{}}
```

After submitting a document, `total_records` increments.

---

## Verdict Logic

| Verdict | Meaning |
|---------|---------|
| VERIFIED | Document is authentic |
| SUSPICIOUS | Passed structural checks but anomalies detected |
| REJECTED | Forged or tampered — failed critical checks |

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| API Server | Python / Flask |
| OCR | Cortex API / Gemini / Tesseract |
| Image Forensics | OpenCV, Pillow, NumPy, SciPy |
| PDF Processing | PyMuPDF, pdfplumber, pikepdf |
| Aadhaar QR | pyaadhaar, cryptography |
| Blockchain | Hyperledger Fabric 2.x |
| Smart Contract | Node.js (fabric-contract-api) |
| Fabric Client | peer CLI via subprocess |
| Frontend | Static HTML/CSS/JS |

---

> Engine Version: v3.0 | Last Updated: July 2026
