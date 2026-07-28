'use strict';

const { Contract } = require('fabric-contract-api');
const crypto = require('crypto');

const BLOCK_COUNTER_KEY = 'BLOCK_COUNTER';
const GENESIS_SENTINEL = 'BGV-GENESIS-v3.0|bgv_ledger.ndjson';

// Produce deterministic JSON matching Python's json.dumps(sort_keys=True)
function sortedJSON(obj) {
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
        return JSON.stringify(obj);
    }
    const sorted = Object.keys(obj).sort().reduce((acc, k) => {
        acc[k] = obj[k];
        return acc;
    }, {});
    return '{' + Object.keys(sorted).map(k => JSON.stringify(k) + ':' + sortedJSON(sorted[k])).join(',') + '}';
}

function sha256hex(data) {
    return crypto.createHash('sha256').update(data, 'utf8').digest('hex');
}

function blockKey(seq) {
    return `BLOCK_${String(seq).padStart(10, '0')}`;
}

class BGVContract extends Contract {

    async _getBlockCount(ctx) {
        const raw = await ctx.stub.getState(BLOCK_COUNTER_KEY);
        if (!raw || raw.length === 0) return 0;
        return parseInt(raw.toString('utf8'), 10);
    }

    async _setBlockCount(ctx, count) {
        await ctx.stub.putState(BLOCK_COUNTER_KEY, Buffer.from(String(count)));
    }

    async _getLatestHash(ctx) {
        const count = await this._getBlockCount(ctx);
        if (count === 0) return sha256hex(GENESIS_SENTINEL);
        const raw = await ctx.stub.getState(blockKey(count - 1));
        const block = JSON.parse(raw.toString('utf8'));
        return block.block_hash;
    }

    // AppendRecord adds a verification record to the immutable ledger.
    async AppendRecord(ctx, recordJSON) {
        const prevHash = await this._getLatestHash(ctx);
        const count = await this._getBlockCount(ctx);
        const timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');

        const record = JSON.parse(recordJSON);

        const blockBody = {
            seq: count,
            prev_hash: prevHash,
            timestamp_utc: timestamp,
            record: record,
        };

        const canonical = sortedJSON(blockBody);
        const blockHash = sha256hex(canonical);
        blockBody.block_hash = blockHash;

        const blockBytes = Buffer.from(JSON.stringify(blockBody));
        await ctx.stub.putState(blockKey(count), blockBytes);
        await this._setBlockCount(ctx, count + 1);

        console.log(`[LEDGER] Block #${count} anchored — hash: ${blockHash.slice(0, 16)}...`);
        return JSON.stringify(blockBody);
    }

    // LookupDocument finds the most recent block matching any fingerprint hash.
    async LookupDocument(ctx, docHash) {
        const count = await this._getBlockCount(ctx);
        for (let i = count - 1; i >= 0; i--) {
            const raw = await ctx.stub.getState(blockKey(i));
            if (!raw || raw.length === 0) continue;
            const block = JSON.parse(raw.toString('utf8'));
            const rec = block.record || {};
            const fp = rec.fingerprint || {};
            if (
                fp.crypto_hash === docHash ||
                fp.perceptual_hash === docHash ||
                fp.content_hash === docHash ||
                fp.composite_hash === docHash ||
                rec.document_id === docHash
            ) {
                return raw.toString('utf8');
            }
        }
        return 'null';
    }

    // LookupCandidate returns all blocks for a given candidate_id (oldest first).
    async LookupCandidate(ctx, candidateId) {
        const count = await this._getBlockCount(ctx);
        const results = [];
        for (let i = 0; i < count; i++) {
            const raw = await ctx.stub.getState(blockKey(i));
            if (!raw || raw.length === 0) continue;
            const block = JSON.parse(raw.toString('utf8'));
            if ((block.record || {}).candidate_id === candidateId) {
                results.push(block);
            }
        }
        return JSON.stringify(results);
    }

    // ClassifyDocument compares a fingerprint against all ledger blocks.
    async ClassifyDocument(ctx, fingerprintJSON) {
        const newFP = JSON.parse(fingerprintJSON);
        const count = await this._getBlockCount(ctx);

        let matchedBlock = null;
        let comparison = { crypto: false, phash: false, content: false };
        let phashAvailable = false;

        for (let i = count - 1; i >= 0; i--) {
            const raw = await ctx.stub.getState(blockKey(i));
            if (!raw || raw.length === 0) continue;
            const block = JSON.parse(raw.toString('utf8'));
            const fp = (block.record || {}).fingerprint || {};

            const cryptoMatch = newFP.crypto_hash && fp.crypto_hash === newFP.crypto_hash;
            const phashMatch = newFP.perceptual_hash && fp.perceptual_hash &&
                fp.perceptual_hash === newFP.perceptual_hash;
            const contentMatch = newFP.content_hash && fp.content_hash === newFP.content_hash;
            const pAvail = !!(newFP.perceptual_hash && fp.perceptual_hash);

            if (cryptoMatch || phashMatch || contentMatch) {
                matchedBlock = block;
                comparison = { crypto: !!cryptoMatch, phash: !!phashMatch, content: !!contentMatch };
                phashAvailable = pAvail;
                break;
            }
        }

        if (!matchedBlock) {
            return JSON.stringify({
                classification: 'new_document',
                label: 'New document',
                matched_block: null,
                hash_comparison: { crypto: false, phash: false, content: false },
            });
        }

        const { crypto: c, phash: p, content: n } = comparison;
        let label, key;
        if (c && n)                       { label = 'Duplicate exact file';                                          key = 'duplicate'; }
        else if (c && !n)                 { label = 'Suspicious corruption: byte match but metrics diverge';         key = 'suspicious_corruption'; }
        else if (!c && phashAvailable && p && n)  { label = 'Same document resubmitted in another format';          key = 'resubmit_different_format'; }
        else if (!c && phashAvailable && p && !n) { label = 'Possible tampering: same image, OCR/content changed \u2014 review';  key = 'possible_tamper'; }
        else if (!c && n)                 { label = 'Same identity document, different capture or scan';             key = 'different_scan'; }
        else                              { label = 'New document';                                                  key = 'new_document'; }

        return JSON.stringify({
            classification: key,
            label,
            matched_block: matchedBlock,
            hash_comparison: comparison,
        });
    }

    // VerifyChainIntegrity walks all blocks and checks hash linkage.
    async VerifyChainIntegrity(ctx) {
        const count = await this._getBlockCount(ctx);
        const errors = [];
        const chain = [];
        let expectedPrev = sha256hex(GENESIS_SENTINEL);

        for (let i = 0; i < count; i++) {
            const raw = await ctx.stub.getState(blockKey(i));
            if (!raw || raw.length === 0) {
                errors.push(`Block ${i}: missing from ledger`);
                continue;
            }
            const block = JSON.parse(raw.toString('utf8'));
            const blockErrors = [];

            if (block.seq !== i) {
                const msg = `Block ${i}: seq mismatch (got ${block.seq})`;
                errors.push(msg); blockErrors.push(msg);
            }
            const chainOk = block.prev_hash === expectedPrev;
            if (!chainOk) {
                const msg = `Block ${i}: prev_hash broken`;
                errors.push(msg); blockErrors.push(msg);
            }

            const { block_hash: storedHash, ...bodyWithoutHash } = block;
            const recomputed = sha256hex(sortedJSON(bodyWithoutHash));
            const hashOk = recomputed === storedHash;
            if (!hashOk) {
                const msg = `Block ${i}: block_hash invalid — record tampered`;
                errors.push(msg); blockErrors.push(msg);
            }

            const rec = block.record || {};
            chain.push({
                seq: i,
                block_hash: storedHash ? storedHash.slice(0, 24) + '...' : null,
                block_hash_full: storedHash,
                chain_link_valid: chainOk,
                block_hash_valid: hashOk,
                valid: chainOk && hashOk,
                timestamp: block.timestamp_utc || rec.timestamp_utc || '',
                doc_type: rec.doc_type || '',
                verdict: (rec.verification || {}).verdict || '',
                candidate_id: rec.candidate_id || '',
                errors: blockErrors,
            });

            expectedPrev = storedHash;
        }

        return JSON.stringify({ valid: errors.length === 0, total_blocks: count, errors, chain });
    }

    // GetLedgerStats returns summary statistics.
    async GetLedgerStats(ctx) {
        const count = await this._getBlockCount(ctx);
        const verdicts = {};
        const docTypes = {};
        let latestHash = 'N/A';

        for (let i = 0; i < count; i++) {
            const raw = await ctx.stub.getState(blockKey(i));
            if (!raw || raw.length === 0) continue;
            const block = JSON.parse(raw.toString('utf8'));
            const rec = block.record || {};
            const verdict = (rec.verification || {}).verdict || 'UNKNOWN';
            const docType = rec.doc_type || 'UNKNOWN';
            verdicts[verdict] = (verdicts[verdict] || 0) + 1;
            docTypes[docType] = (docTypes[docType] || 0) + 1;
            if (i === count - 1) latestHash = block.block_hash;
        }

        return JSON.stringify({ total_records: count, latest_hash: latestHash, verdicts, doc_types: docTypes });
    }
}

exports.contracts = [BGVContract];
