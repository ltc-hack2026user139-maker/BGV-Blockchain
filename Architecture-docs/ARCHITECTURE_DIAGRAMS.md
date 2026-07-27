# BGV v3.1 Architecture Diagrams (Mermaid Source)
# Render at: https://mermaid.live or any Mermaid-compatible viewer

---

## 1. Full System Architecture (with Fabric + Cortex)

```mermaid
flowchart TD
    User["👤 User / HR Portal\nUploads Document + Candidate Details"] --> API

    API["🌐 Flask API Server\nPOST /api/verify"] --> Phase0

    Phase0["Phase 0: Duplicate Detection\nSHA-256 → lookup_document()"] -->|Duplicate found| CachedResult["Cached Verdict\nduplicate_detected: true"]
    Phase0 -->|New document| Router

    Router["Document Router\ndocType?"] -->|aadhaar| Aadhaar
    Router -->|passport| Passport
    Router -->|other| Tamper

    subgraph Aadhaar ["Pipeline 1: Aadhaar"]
        A1["Stage 1: PDF Decrypt\npikepdf"] --> A2
        A2["Stage 2: Image Extract\nPyMuPDF 2x/4x DPI"] --> A3
        A3["Stage 3: QR Decode\nZXing → pyzbar → OpenCV"] --> A4
        A4["Stage 4: Secure QR Parse\nBigInt→Gzip→0xFF fields"] --> A5
        A5["Stage 5: PDF Signature\npyHanko vs UIDAI cert"] --> A6
        A6["Stage 6: Field Compare\nQR vs Visible Text"]
        Cortex1["🤖 Cortex API\nGemini-2.5-flash\nOCR printed text only\ntampering_suspected"] -.->|if CORTEX_API_KEY set| A6
    end

    subgraph Passport ["Pipeline 2: Passport"]
        P1["Stage 1: Load\nPyMuPDF / PIL"] --> P2
        P2["Stage 2: MRZ Extract\nPDF text / OCR bottom 35%"] --> P3
        P3["Stage 3: MRZ Parse\nICAO 9303"] --> P4
        P4["Stage 4: Checksum Validate\n5× weighted mod-10"] --> P5
        P5["Stage 5: VIZ Extract\nCLAHE + 2x + Otsu + OCR"] --> P6
        P6["Stage 6: MRZ vs VIZ"]
        Cortex2["🤖 Cortex API\nGemini-2.5-flash\nVIZ field extraction\ntampering_suspected"] -.->|if CORTEX_API_KEY set| P6
    end

    subgraph Tamper ["Pipeline 3: Tamper Detection"]
        T1["Module A: ELA\nJPEG re-save diff\n(skipped for PDF/PNG)"]
        T2["Module B: Noise\nLaplacian + MAD"]
        T3["Module C: DCT\n8×8 block AC energy"]
        T4["Module D: Copy-Move\n32×32 pHash pairs"]
        T5["Module E: Metadata\nCreator tool + timestamps"]
        T6["Module F: CNN Font\nMobileNetV2 + KMeans"]
        T7["Module G: Char Paste\nNoise bimodality + pHash"]
        T8["Module H: PDF Stream\nIncremental updates"]
        Cortex3["🤖 Module I: Cortex AI\nVisual edit detection"] -.->|if CORTEX_API_KEY set| TScore
        T1 & T2 & T3 & T4 & T5 & T6 & T7 & T8 --> TScore["Weighted Score\n0.0 → 1.0"]
    end

    Aadhaar --> DE
    Passport --> DE
    Tamper --> DE

    DE["Decision Engine\n• Pipeline-specific verdict logic\n• Candidate name/DOB cross-check\n• Confidence scoring 0-100"]

    DE --> FP["3-Layer Fingerprinting\nLayer 1: SHA-256 crypto\nLayer 2: pHash (64-bit DCT)\nLayer 3: content hash\nComposite = SHA256(L1|L2|L3)"]

    FP --> Ledger

    subgraph Ledger ["Blockchain Ledger\n(FABRIC_GATEWAY_PEER controls mode)"]
        LocalMode["Local NDJSON\nbgv_ledger.ndjson\n(dev / demo)"]
        FabricMode["Hyperledger Fabric 2.5\nfabric-gateway + grpcio\nChaincode: bgv (JS)\nChannel: bgvchannel\n(production)"]
    end

    Ledger --> Result["Final Response\n✅ VERIFIED / ⚠️ SUSPICIOUS / ❌ REJECTED\n+ confidenceScore + fingerprint + ledger_block"]
```

---

## 2. Blockchain Dual-Mode Detail

```mermaid
flowchart LR
    App["blockchain_ledger.py\n_USE_FABRIC = bool(FABRIC_GATEWAY_PEER)"]

    App -->|False| NDJSON["Local NDJSON Mode\nbgv_ledger.ndjson\n\nBlock structure:\n seq, prev_hash,\n timestamp_utc,\n record, block_hash\n\nGenesis = SHA256(\n'BGV-GENESIS-v3.0|\nbgv_ledger.ndjson'\n)"]

    App -->|True| FabricGW["Fabric Gateway Mode\ngrpc.secure_channel(\n peer0.org1.example.com:7051\n)\n\nChaincode functions:\n AppendRecord\n LookupDocument\n LookupCandidate\n ClassifyDocument\n VerifyChainIntegrity\n GetLedgerStats"]

    FabricGW --> Peer["Fabric Peer\npeer0.org1.example.com:7051\n\nChannel: bgvchannel\nChaincode: bgv\n\nWorld state: CouchDB\nConsensus: Raft"]

    Peer --> Chaincode["bgv-chaincode-js/index.js\n\nconst Contract = require('fabric-contract-api')\n\nsortedJSON() matches Python\njson.dumps(sort_keys=True)\n\nSame GENESIS_SENTINEL\nconstant as Python"]
```

---

## 3. Cortex OCR Flow

```mermaid
flowchart TD
    DocImage["Document Image (PIL)"] --> B64["base64 encode PNG"]
    QRorMRZ["QR/MRZ ground truth\n(name, dob, gender)"] --> Prompt

    B64 --> CortexReq["Cortex API Request\nPOST /chat/completions\nmodel: gemini-2.5-flash\ntemperature: 0"]
    Prompt["Structured prompt:\n1. Extract from PRINTED TEXT ONLY\n   (not QR barcode / MRZ strip)\n2. Compare with ground truth\n3. Flag if DOB mismatch"] --> CortexReq

    CortexReq -->|OpenAI-compatible| CortexAPI["https://cortex.lloydsbanking.cloud/api/v1\nBearer CORTEX_API_KEY\nhttpx (verify=False, internal cert)"]

    CortexAPI --> JSONResp["JSON Response\nocr_name, ocr_dob, ocr_gender\nname_match, dob_match, gender_match\nany_mismatch\ntampering_suspected\nnotes"]

    JSONResp --> Pipeline["Aadhaar / Passport Pipeline\nmerge Cortex result\ninto Stage 6 comparison"]

    CortexAPI -->|CORTEX_API_KEY blank| Fallback["Tesseract OCR fallback\nno Cortex call made"]
```

---

## 4. Three-Layer Fingerprint

```mermaid
flowchart TD
    File["Raw Document File\n(PDF / JPG / PNG)"] --> L1
    File --> Render

    L1["Layer 1: Crypto Hash\nSHA-256(raw file bytes)\n→ crypto_hash"]
    Render["Render first page\n(PyMuPDF @ 2× DPI)"] --> L2
    L2["Layer 2: Perceptual Hash\n32×32 greyscale → 2D DCT\ntop-left 8×8 → 64-bit pHash\n→ perceptual_hash"]

    Pipeline["Pipeline extracted fields\nPassport: passport_no|dob|expiry|name\nAadhaar: name|dob|gender\nOther: flags+scores"] --> L3
    L3["Layer 3: Content Hash\nSHA-256(extracted fields)\n→ content_hash"]

    L1 & L2 & L3 --> Composite
    Composite["Composite Hash\nSHA-256(crypto|phash|content)\n→ composite_hash"]

    Composite --> Ledger["Appended to blockchain ledger\nas part of VerificationRecord"]

    L1 -->|Phase 0| DupCheck["Duplicate Detection\nlookup_document(crypto_hash)\nbefore pipeline runs"]
```
