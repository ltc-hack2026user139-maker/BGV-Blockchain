# Blockchain-fabric — BGV Hyperledger Fabric Setup

This folder contains the Hyperledger Fabric network configuration and the BGV smart contract (chaincode) that provides the immutable audit ledger for document verifications.

---

## Folder Structure

```
Blockchain-fabric/
│
├── bgv-chaincode-js/              # BGV smart contract (Node.js)
│   ├── index.js                   # Chaincode — all ledger logic
│   ├── package.json               # fabric-contract-api dependency
│   └── node_modules/              # Installed dependencies
│
└── test-network/                  # Hyperledger Fabric test network
    ├── network.sh                 # Main script — bring network up/down
    ├── setOrgEnv.sh               # Export peer environment variables
    ├── bgv.tar.gz                 # Pre-packaged BGV chaincode (ready to install)
    ├── log.txt                    # Last network operation log
    │
    ├── configtx/                  # Channel and orderer configuration
    ├── compose/                   # Docker Compose files for all network nodes
    ├── organizations/             # Generated crypto material (certs, keys, MSP)
    ├── channel-artifacts/         # Genesis block and channel transaction files
    │
    └── scripts/                   # Helper scripts
        ├── deployCC.sh            # Install + approve + commit chaincode
        ├── createChannel.sh       # Create and join bgvchannel
        ├── envVar.sh              # Peer environment variable helpers
        └── ccutils.sh             # Chaincode utility functions
```

---

## What the Chaincode Does

`bgv-chaincode-js/index.js` is a Node.js Hyperledger Fabric smart contract with 6 functions:

| Function | Type | Description |
|----------|------|-------------|
| `AppendRecord` | Invoke (write) | Appends a BGV verification as a new block with SHA-256 hash chain |
| `LookupDocument` | Query (read) | Finds a block by any fingerprint hash (crypto, perceptual, content, composite) |
| `LookupCandidate` | Query (read) | Returns all blocks for a given candidate ID |
| `ClassifyDocument` | Query (read) | Compares a fingerprint against all blocks — detects duplicates and tampering |
| `VerifyChainIntegrity` | Query (read) | Walks all blocks and validates the hash chain — detects any tampering of ledger |
| `GetLedgerStats` | Query (read) | Returns total records, latest hash, verdict counts, doc type counts |

Each block stores: `seq`, `prev_hash`, `timestamp_utc`, `block_hash`, and the full verification record (fingerprints, verdict, confidence, doc type, candidate ID).

---

## Prerequisites

### 1. Install Docker Desktop
Download from https://www.docker.com/products/docker-desktop  
Ensure Docker is running before proceeding.

### 2. Install Hyperledger Fabric Binaries

```bash
# Creates ~/fabric-samples/ and downloads peer, orderer, configtxgen binaries
curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.5.0 1.5.7
```

This installs binaries to `~/fabric-samples/bin/`. Add to PATH:

```bash
export PATH=$PATH:$HOME/fabric-samples/bin
export FABRIC_CFG_PATH=$HOME/fabric-samples/config/
```

### 3. Install Node.js 18+
Required for the chaincode container.  
Download from https://nodejs.org or use `nvm install 18`.

---

## Full Setup — Step by Step

### Step 1 — Start the Fabric Network

```bash
cd Blockchain-fabric/test-network

# Bring up network with Certificate Authority, create bgvchannel
./network.sh up createChannel -c bgvchannel -ca
```

This starts 5 Docker containers:
- `orderer.example.com` — orders and commits transactions
- `peer0.org1.example.com` — Org1 peer (port 7051)
- `peer0.org2.example.com` — Org2 peer (port 9051)
- `ca_org1`, `ca_org2` — Certificate Authorities

### Step 2 — Deploy the BGV Chaincode

```bash
# Deploy the pre-packaged chaincode to bgvchannel
./scripts/deployCC.sh bgvchannel bgv ../bgv-chaincode-js/ NA 1.0 node
```

Or use the packaged `.tar.gz` directly:

```bash
# Set Org1 peer environment
source setOrgEnv.sh Org1

# Install on Org1 peer
peer lifecycle chaincode install bgv.tar.gz

# Set Org2 peer environment
source setOrgEnv.sh Org2

# Install on Org2 peer
peer lifecycle chaincode install bgv.tar.gz

# Approve for Org1
source setOrgEnv.sh Org1
peer lifecycle chaincode approveformyorg -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.example.com \
  --channelID bgvchannel --name bgv --version 1.0 \
  --package-id $(peer lifecycle chaincode queryinstalled | grep bgv | awk '{print $3}' | tr -d ',') \
  --sequence 1 --tls \
  --cafile organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem

# Approve for Org2
source setOrgEnv.sh Org2
peer lifecycle chaincode approveformyorg -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.example.com \
  --channelID bgvchannel --name bgv --version 1.0 \
  --package-id $(peer lifecycle chaincode queryinstalled | grep bgv | awk '{print $3}' | tr -d ',') \
  --sequence 1 --tls \
  --cafile organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem

# Commit chaincode definition
source setOrgEnv.sh Org1
peer lifecycle chaincode commit -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.example.com \
  --channelID bgvchannel --name bgv --version 1.0 --sequence 1 --tls \
  --cafile organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem \
  --peerAddresses localhost:7051 \
  --tlsRootCertFiles organizations/peerOrganizations/org1.example.com/tlsca/tlsca.org1.example.com-cert.pem \
  --peerAddresses localhost:9051 \
  --tlsRootCertFiles organizations/peerOrganizations/org2.example.com/tlsca/tlsca.org2.example.com-cert.pem
```

### Step 3 — Verify Deployment

```bash
source setOrgEnv.sh Org1

peer chaincode query -C bgvchannel -n bgv -c '{"function":"GetLedgerStats","Args":[]}'
# Expected: {"total_records":0,"latest_hash":"N/A","verdicts":{},"doc_types":{}}
```

---

## Set Peer Environment Variables (for manual CLI use)

```bash
export FABRIC_CFG_PATH=$HOME/fabric-samples/config/
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_TLS_ROOTCERT_FILE=$PWD/organizations/peerOrganizations/org1.example.com/tlsca/tlsca.org1.example.com-cert.pem
export CORE_PEER_MSPCONFIGPATH=$PWD/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export CORE_PEER_ADDRESS=localhost:7051
```

---

## Useful Commands

```bash
# Check chaincode is running
peer lifecycle chaincode querycommitted -C bgvchannel

# Query ledger stats
peer chaincode query -C bgvchannel -n bgv -c '{"function":"GetLedgerStats","Args":[]}'

# Verify chain integrity
peer chaincode query -C bgvchannel -n bgv -c '{"function":"VerifyChainIntegrity","Args":[]}'

# Stop network (data preserved in Docker volumes)
./network.sh down

# Full reset — destroys all ledger data
./network.sh down
docker volume prune -f
```

---

## Network Architecture

```
                    ┌──────────────────────┐
                    │  orderer.example.com  │
                    │     port 7050        │
                    └──────────┬───────────┘
                               │ orders & commits
              ┌────────────────┴────────────────┐
              │                                 │
   ┌──────────▼──────────┐         ┌────────────▼────────────┐
   │  peer0.org1          │         │  peer0.org2             │
   │  port 7051           │         │  port 9051              │
   │  bgv chaincode v1.0  │         │  bgv chaincode v1.0     │
   └─────────────────────┘         └─────────────────────────┘
              │                                 │
              └────────────────┬────────────────┘
                        bgvchannel ledger
                     (shared, immutable state)
```

Both peers must endorse every `AppendRecord` transaction before the orderer commits it — this is the endorsement policy that makes the ledger tamper-proof.

---

## Troubleshooting

| Error | Fix |
|-------|-----|
| `Config File "core" Not Found` | Set `FABRIC_CFG_PATH` to the `fabric-samples/config/` directory |
| `ENDORSEMENT_POLICY_FAILURE` | Invoke must target both org peers (`--peerAddresses` for Org1 and Org2) |
| `[WinError 2] file not found` | Set `FABRIC_BIN_PATH` in `.env` to `fabric-samples/bin` full path |
| `connection refused localhost:7051` | Docker containers are not running — start with `./network.sh up` |

---

> Fabric Version: 2.5.x | Chaincode Runtime: Node.js 18 | Channel: bgvchannel
