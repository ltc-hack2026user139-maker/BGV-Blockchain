// ============================================
// BGV Document Verification — Frontend App
// ============================================

(function () {
    'use strict';

    // --- State ---
    let selectedDocType = 'aadhaar';
    let selectedFile = null;
    let isScanned = false;  // document origin flag (tamper pipeline only)

    // --- DOM Elements ---
    const docTypeBtns = document.querySelectorAll('.doc-type-btn');
    const fileDropZone = document.getElementById('file-drop-zone');
    const fileInput = document.getElementById('file-input');
    const dropZoneContent = document.getElementById('drop-zone-content');
    const filePreview = document.getElementById('file-preview');
    const fileNameEl = document.getElementById('file-name');
    const fileSizeEl = document.getElementById('file-size');
    const fileRemoveBtn = document.getElementById('file-remove');
    const passwordGroup = document.getElementById('password-group');
    const passwordInput = document.getElementById('pdf-password');
    const passwordToggle = document.getElementById('password-toggle');
    const docOriginGroup = document.getElementById('doc-origin-group');
    const passwordErrorMsg = document.getElementById('password-error-msg');
    const originDigitalLabel = document.getElementById('origin-digital-label');
    const originScannedLabel = document.getElementById('origin-scanned-label');
    const originDigital = document.getElementById('origin-digital');
    const originScanned = document.getElementById('origin-scanned');
    const candidateNameInput = document.getElementById('candidate-name');
    const candidateDobInput = document.getElementById('candidate-dob');
    const verifyForm = document.getElementById('verify-form');
    const verifyBtn = document.getElementById('verify-btn');
    const uploadSection = document.getElementById('upload-section');
    const resultsSection = document.getElementById('results-section');
    const backBtn = document.getElementById('back-btn');

    // Results
    const verdictCard = document.getElementById('verdict-card');
    const verdictIcon = document.getElementById('verdict-icon');
    const verdictLabel = document.getElementById('verdict-label');
    const verdictDesc = document.getElementById('verdict-desc');
    const confidenceCircle = document.getElementById('confidence-circle');
    const confidenceNumber = document.getElementById('confidence-number');
    const pipelineName = document.getElementById('pipeline-name');
    const checksGrid = document.getElementById('checks-grid');
    const flagsContainer = document.getElementById('flags-container');
    const flagsList = document.getElementById('flags-list');
    const rawJson = document.getElementById('raw-json');

    // --- Doc Type Selector ---
    docTypeBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            docTypeBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            selectedDocType = btn.dataset.type;

            // Show/hide password field
            if (selectedDocType === 'aadhaar') {
                passwordGroup.classList.remove('hidden-field');
            } else {
                passwordGroup.classList.add('hidden-field');
            }

            // Show/hide document origin toggle (only for tamper pipeline)
            if (selectedDocType === 'other') {
                docOriginGroup.classList.remove('hidden-field');
            } else {
                docOriginGroup.classList.add('hidden-field');
                isScanned = false;  // reset when not on tamper pipeline
            }
        });
    });

    // --- Document Origin Toggle ---
    [originDigitalLabel, originScannedLabel].forEach(lbl => {
        lbl.addEventListener('click', () => {
            originDigitalLabel.classList.remove('active');
            originScannedLabel.classList.remove('active');
            lbl.classList.add('active');
            isScanned = (lbl === originScannedLabel);
        });
    });

    // --- File Upload ---
    fileDropZone.addEventListener('click', (e) => {
        if (!e.target.closest('.file-remove') && !selectedFile) {
            fileInput.click();
        }
    });

    fileDropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        fileDropZone.classList.add('drag-over');
    });

    fileDropZone.addEventListener('dragleave', () => {
        fileDropZone.classList.remove('drag-over');
    });

    fileDropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        fileDropZone.classList.remove('drag-over');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFileSelect(files[0]);
        }
    });

    fileInput.addEventListener('change', () => {
        if (fileInput.files.length > 0) {
            handleFileSelect(fileInput.files[0]);
        }
    });

    fileRemoveBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        removeFile();
    });

    function handleFileSelect(file) {
        const validTypes = ['application/pdf', 'image/jpeg', 'image/png', 'image/jpg'];
        if (!validTypes.includes(file.type)) {
            showToast('❌', 'Invalid file type. Please upload PDF, JPG, or PNG.');
            return;
        }
        if (file.size > 10 * 1024 * 1024) {
            showToast('❌', 'File too large. Maximum size is 10MB.');
            return;
        }

        selectedFile = file;
        fileNameEl.textContent = file.name;
        fileSizeEl.textContent = formatFileSize(file.size);
        dropZoneContent.classList.add('hidden');
        filePreview.classList.remove('hidden');
        fileDropZone.classList.add('has-file');
    }

    function removeFile() {
        selectedFile = null;
        fileInput.value = '';
        dropZoneContent.classList.remove('hidden');
        filePreview.classList.add('hidden');
        fileDropZone.classList.remove('has-file');
    }

    function formatFileSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    }

    // --- Password Toggle ---
        // --- Password Toggle ---
    passwordToggle.addEventListener('click', () => {
        const isPassword = passwordInput.type === 'password';
        passwordInput.type = isPassword ? 'text' : 'password';
        passwordToggle.querySelector('.eye-open').classList.toggle('hidden', !isPassword);
        passwordToggle.querySelector('.eye-closed').classList.toggle('hidden', isPassword);
    });

    function showPasswordError() {
        passwordInput.classList.add('input-error');
        passwordErrorMsg.classList.remove('hidden');
        passwordInput.focus();
        passwordInput.select();
    }

    function clearPasswordError() {
        passwordInput.classList.remove('input-error');
        passwordErrorMsg.classList.add('hidden');
    }

    passwordInput.addEventListener('input', clearPasswordError);

    // --- Form Submit ---
    verifyForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        if (!selectedFile) {
            showToast('📄', 'Please upload a document first.');
            return;
        }

        if (selectedDocType === 'aadhaar' && !passwordInput.value.trim()) {
            showToast('🔒', 'Please enter the PDF password for Aadhaar document.');
            return;
        }

        // Show loading
        const btnText = verifyBtn.querySelector('.btn-text');
        const btnLoading = verifyBtn.querySelector('.btn-loading');
        btnText.classList.add('hidden');
        btnLoading.classList.remove('hidden');
        verifyBtn.disabled = true;

        try {
            const formData = new FormData();
            formData.append('document', selectedFile);
            formData.append('docType', selectedDocType);
            if (selectedDocType === 'aadhaar') {
                formData.append('password', passwordInput.value.trim());
            }
            if (selectedDocType === 'other') {
                formData.append('isScanned', isScanned ? 'true' : 'false');
            }
            if (candidateNameInput.value.trim()) {
                formData.append('candidateName', candidateNameInput.value.trim());
            }
            if (candidateDobInput.value) {
                formData.append('candidateDob', candidateDobInput.value);
            }

            const response = await fetch('/api/verify', {
                method: 'POST',
                body: formData,
            });

            const result = await response.json();

            if (!response.ok) {
                if (result.password_error) {
                    showPasswordError();
                    return;
                }
                throw new Error(result.error || 'Verification failed');
            }

            clearPasswordError();
            displayResults(result);
        } catch (err) {
            showToast('❌', err.message || 'An error occurred during verification.');
        } finally {
            btnText.classList.remove('hidden');
            btnLoading.classList.add('hidden');
            verifyBtn.disabled = false;
        }
    });

    // --- Display Results ---
    function displayResults(result) {
        uploadSection.classList.add('hidden');
        resultsSection.classList.remove('hidden');

        // ── Duplicate Detection Banner ────────────────────────────────
        // Remove any existing duplicate banner
        const existingBanner = document.getElementById('duplicate-banner');
        if (existingBanner) existingBanner.remove();

        if (result.duplicate_detected) {
            const orig = result.original_block || {};
            const banner = document.createElement('div');
            banner.id = 'duplicate-banner';
            banner.className = 'duplicate-banner';
            banner.innerHTML = `
                <div class="dup-icon">⛓️</div>
                <div class="dup-text">
                    <strong>Blockchain Duplicate Detected — Pipeline Skipped</strong>
                    <span>This exact document was previously verified and anchored at
                        <strong>Block #${orig.seq ?? '?'}</strong>
                        on <strong>${orig.timestamp || 'N/A'}</strong>.
                        The cached verdict has been returned instantly.
                    </span>
                </div>
            `;
            // Insert before the verdict card
            verdictCard.parentNode.insertBefore(banner, verdictCard);
        }

        // Verdict
        const verdict = (result.verdict || 'UNKNOWN').toUpperCase();
        verdictCard.className = 'verdict-card';

        if (verdict === 'VERIFIED') {
            verdictCard.classList.add('verdict-verified');
            verdictIcon.textContent = '✅';
            verdictLabel.textContent = 'VERIFIED';
            verdictDesc.textContent = result.verdictReason || 'Document passed all verification checks';
        } else if (verdict === 'SUSPICIOUS') {
            verdictCard.classList.add('verdict-suspicious');
            verdictIcon.textContent = '⚠️';
            verdictLabel.textContent = 'SUSPICIOUS';
            verdictDesc.textContent = result.verdictReason || 'Document has some inconsistencies — review recommended';
        } else {
            verdictCard.classList.add('verdict-rejected');
            verdictIcon.textContent = '❌';
            verdictLabel.textContent = 'REJECTED';
            verdictDesc.textContent = result.verdictReason || 'Document failed verification checks';
        }


        // Confidence Ring
        const confidence = result.confidenceScore || 0;
        const circumference = 2 * Math.PI * 52; // r=52
        const offset = circumference - (confidence / 100) * circumference;

        const ringGrad = document.getElementById('ring-grad');
        if (verdict === 'VERIFIED') {
            ringGrad.innerHTML = '<stop stop-color="#22C55E"/><stop offset="1" stop-color="#16A34A"/>';
        } else if (verdict === 'SUSPICIOUS') {
            ringGrad.innerHTML = '<stop stop-color="#F59E0B"/><stop offset="1" stop-color="#D97706"/>';
        } else {
            ringGrad.innerHTML = '<stop stop-color="#EF4444"/><stop offset="1" stop-color="#DC2626"/>';
        }

        animateNumber(confidenceNumber, 0, confidence, 1000);
        setTimeout(() => {
            confidenceCircle.style.transition = 'stroke-dashoffset 1s ease';
            confidenceCircle.style.strokeDashoffset = offset;
        }, 100);

        // Pipeline badge
        const pipelineMap = {
            aadhaar: '📘 Aadhaar Pipeline',
            passport: '📗 Passport Pipeline',
            other: '📕 Tamper Detection Engine',
        };
        pipelineName.textContent = pipelineMap[result.pipeline] || result.pipeline;

        // Checks Grid
        checksGrid.innerHTML = '';
        if (result.checks && result.checks.length > 0) {
            result.checks.forEach(check => {
                const statusClass = check.passed ? 'pass' : (check.warning ? 'warn' : 'fail');
                const statusIcon = check.passed ? '✓' : (check.warning ? '!' : '✗');
                const el = document.createElement('div');
                el.className = 'check-item';
                el.innerHTML = `
                    <div class="check-status ${statusClass}">${statusIcon}</div>
                    <span class="check-name">${escapeHtml(check.name)}</span>
                    <span class="check-detail">${escapeHtml(check.detail || '')}</span>
                `;
                checksGrid.appendChild(el);
            });
        }

        // ── P3: MRZ Data Card (passport only) ──────────────────────────────
        const mrzCard   = document.getElementById('mrz-card');
        const mrzGrid   = document.getElementById('mrz-grid');
        if (result.pipeline === 'passport' && result.mrz_data && Object.keys(result.mrz_data).length > 0) {
            const mrz = result.mrz_data;
            const fields = [
                { label: 'Full Name',       value: mrz.full_name },
                { label: 'Passport No.',    value: mrz.passport_number,  mono: true },
                { label: 'Date of Birth',   value: mrz.dob_formatted },
                { label: 'Gender',          value: mrz.gender_full },
                { label: 'Nationality',     value: mrz.nationality,      mono: true },
                { label: 'Expiry Date',     value: mrz.expiry_formatted },
                { label: 'Issuing Country', value: mrz.issuing_country,  mono: true },
            ].filter(f => f.value);

            mrzGrid.innerHTML = fields.map(f => `
                <div class="data-field">
                    <div class="data-field-label">${escapeHtml(f.label)}</div>
                    <div class="data-field-value${f.mono ? ' mono' : ''}">${escapeHtml(String(f.value))}</div>
                </div>
            `).join('');
            mrzCard.classList.remove('hidden');
        } else {
            mrzCard.classList.add('hidden');
        }

        // ── P4: Tamper Module Score Breakdown ──────────────────────────────
        const tamperCard  = document.getElementById('tamper-card');
        const moduleScoresEl = document.getElementById('module-scores');
        const tamperRiskBadge = document.getElementById('tamper-risk-badge');

        if (result.pipeline === 'other' && result.moduleScores) {
            const MODULE_LABELS = {
                ela:        'ELA',
                noise:      'Noise',
                dct:        'DCT',
                copy_move:  'Copy-Move',
                metadata:   'Metadata',
                font_cnn:   'Font CNN',
                char_paste: 'Char Paste',
                pdf_layers: 'PDF Layers',
                cortex_ai:  'AI Analysis',
            };
            const scores = result.moduleScores;

            moduleScoresEl.innerHTML = Object.entries(MODULE_LABELS).map(([key, label]) => {
                const score = scores[key] != null ? scores[key] : null;
                if (score === null) return '';
                const pct   = Math.round(score * 100);
                const level = score >= 0.5 ? 'high' : score >= 0.25 ? 'medium' : 'low';
                return `
                    <div class="module-score-row">
                        <span class="module-score-label">${escapeHtml(label)}</span>
                        <div class="module-score-bar-track">
                            <div class="module-score-bar-fill level-${level}" data-pct="${pct}" style="width:0%"></div>
                        </div>
                        <span class="module-score-value">${(score).toFixed(3)}</span>
                    </div>
                `;
            }).join('');

            // Animate bars after render
            setTimeout(() => {
                moduleScoresEl.querySelectorAll('.module-score-bar-fill').forEach(bar => {
                    bar.style.width = bar.dataset.pct + '%';
                });
            }, 80);

            // Risk badge
            const riskLevel = (result.riskLevel || 'LOW').toLowerCase();
            tamperRiskBadge.textContent = (result.riskLevel || 'LOW') + ' RISK';
            tamperRiskBadge.className = `data-card-badge risk-${riskLevel}`;
            tamperCard.classList.remove('hidden');
        } else {
            tamperCard.classList.add('hidden');
        }

        // Flags
        if (result.flags && result.flags.length > 0) {
            flagsContainer.classList.remove('hidden');
            flagsList.innerHTML = '';
            result.flags.forEach(flag => {
                const severity = (flag.severity || 'medium').toLowerCase();
                const el = document.createElement('div');
                el.className = `flag-item severity-${severity}`;
                el.innerHTML = `
                    <span class="flag-module">${escapeHtml(flag.module)}</span>
                    <div class="flag-content">
                        <p class="flag-desc">${escapeHtml(flag.description)}</p>
                        <span class="flag-severity">${escapeHtml(flag.severity)} severity</span>
                    </div>
                `;
                flagsList.appendChild(el);
            });
        } else {
            flagsContainer.classList.add('hidden');
        }

        // ── P2: Digital Fingerprint + Blockchain Ledger ────────────────────
        const fpCard  = document.getElementById('fingerprint-card');
        const fpGrid  = document.getElementById('fingerprint-grid');
        const fp = result.fingerprint;

        if (fp && !fp.error) {
            const fpFields = [
                {
                    label: 'Crypto Hash (SHA-256)',
                    value: fp.crypto_hash ? fp.crypto_hash.substring(0, 32) + '…' : '—',
                },
                {
                    label: 'Perceptual Hash (pHash)',
                    value: fp.perceptual_hash || '—',
                },
                {
                    label: 'Composite Hash',
                    value: fp.composite_hash ? fp.composite_hash.substring(0, 32) + '…' : '—',
                },
            ];

            // Build previous-submission context HTML (shown when same doc was submitted before)
            let prevContextHtml = '';
            const lc = fp.ledger_classification;
            if (lc && lc.matched_block_seq != null) {
                const prevVerdict  = lc.previous_verdict || '—';
                const prevConf     = lc.previous_confidence != null ? lc.previous_confidence + '%' : '—';
                const prevTime     = lc.previous_timestamp
                    ? lc.previous_timestamp.replace('T', ' ').replace('Z', ' UTC') : '—';
                const verdictColor = prevVerdict === 'VERIFIED' ? '#27ae60'
                    : prevVerdict === 'SUSPICIOUS' ? '#e67e22' : '#e74c3c';
                const mismatchNote = lc.previous_name_mismatch
                    ? '<div style="font-size:11px;margin-top:6px;color:#e67e22;font-weight:600;">⚠ Previous run had candidate name mismatch — that run\'s score was lower</div>'
                    : '';
                prevContextHtml = `
                <div class="fp-field" style="grid-column:1/-1;border-top:1px solid rgba(255,255,255,0.15);padding-top:10px;margin-top:4px;">
                    <div class="fp-field-label" style="color:#3498db;">⛓ Already in Blockchain — Previous Submission (Block #${lc.matched_block_seq})</div>
                    <div style="font-size:12px;margin-top:5px;line-height:1.8;">
                        Verdict: <strong style="color:${verdictColor}">${escapeHtml(prevVerdict)}</strong>
                        &nbsp;|&nbsp; Confidence: <strong>${escapeHtml(prevConf)}</strong>
                        &nbsp;|&nbsp; ${escapeHtml(prevTime)}
                    </div>
                    ${mismatchNote}
                </div>`;
            }

            fpGrid.innerHTML = fpFields.map(f => `
                <div class="fp-field">
                    <div class="fp-field-label">${escapeHtml(f.label)}</div>
                    <div class="fp-field-value">${escapeHtml(f.value)}</div>
                </div>
            `).join('') + (fp.ledger_block != null ? `
                <div class="fp-field">
                    <div class="fp-field-label">⛓ Ledger Block</div>
                    <div class="fp-ledger-block">#${fp.ledger_block}</div>
                    ${fp.ledger_hash ? `<div class="fp-field-value" style="margin-top:4px;">${escapeHtml(fp.ledger_hash)}</div>` : ''}
                </div>
            ` : '') + prevContextHtml;

            fpCard.classList.remove('hidden');
        } else {
            fpCard.classList.add('hidden');
        }

        // Raw JSON
        rawJson.textContent = JSON.stringify(result, null, 2);
    }

    function animateNumber(el, from, to, duration) {
        const start = performance.now();
        const range = to - from;

        function update(now) {
            const progress = Math.min((now - start) / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3); // ease out cubic
            el.textContent = Math.round(from + range * eased);
            if (progress < 1) requestAnimationFrame(update);
        }

        requestAnimationFrame(update);
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // --- Back Button ---
    backBtn.addEventListener('click', () => {
        resultsSection.classList.add('hidden');
        uploadSection.classList.remove('hidden');
        // Reset confidence ring
        confidenceCircle.style.transition = 'none';
        confidenceCircle.style.strokeDashoffset = 327;
    });

    // --- Toast ---
    function showToast(icon, message) {
        // Remove existing toast
        const existing = document.querySelector('.toast');
        if (existing) existing.remove();

        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.innerHTML = `<span class="toast-icon">${icon}</span>${escapeHtml(message)}`;
        document.body.appendChild(toast);

        requestAnimationFrame(() => {
            toast.classList.add('show');
        });

        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 400);
        }, 4000);
    }

    // --- Chain Integrity Verifier ---
    const verifyChainBtn = document.getElementById('verify-chain-btn');
    const chainResult    = document.getElementById('chain-integrity-result');

    verifyChainBtn.addEventListener('click', async () => {
        verifyChainBtn.disabled = true;
        verifyChainBtn.textContent = 'Checking…';
        chainResult.innerHTML = '<p class="chain-hint" style="opacity:.6;">Scanning all blocks…</p>';

        try {
            const resp = await fetch('/api/ledger/verify');
            const data = await resp.json();
            renderChainIntegrity(data);
        } catch (err) {
            chainResult.innerHTML = `<p class="chain-hint" style="color:#e74c3c;">Error: ${escapeHtml(String(err))}</p>`;
        } finally {
            verifyChainBtn.disabled = false;
            verifyChainBtn.textContent = 'Verify Chain';
        }
    });

    function renderChainIntegrity(data) {
        const valid        = data.valid;
        const totalBlocks  = data.total_blocks || 0;
        const errors       = data.errors || [];
        const chain        = data.chain || [];

        const statusColor  = valid ? '#2ecc71' : '#e74c3c';
        const statusIcon   = valid ? '✅' : '❌';
        const statusLabel  = valid ? 'CHAIN INTACT' : 'CHAIN BROKEN — TAMPERING DETECTED';

        let html = `
        <div class="chain-status-banner" style="background:${valid ? 'rgba(46,204,113,0.12)' : 'rgba(231,76,60,0.12)'};border:1px solid ${statusColor};border-radius:8px;padding:12px 16px;margin-bottom:14px;display:flex;align-items:center;gap:10px;">
            <span style="font-size:20px;">${statusIcon}</span>
            <div>
                <div style="font-weight:700;font-size:14px;color:${statusColor};">${escapeHtml(statusLabel)}</div>
                <div style="font-size:12px;color:rgba(255,255,255,0.6);margin-top:2px;">${totalBlocks} block(s) verified</div>
            </div>
        </div>`;

        if (errors.length) {
            html += `<div style="margin-bottom:12px;">` +
                errors.map(e => `<div class="chain-error-msg">⚠ ${escapeHtml(e)}</div>`).join('') +
                `</div>`;
        }

        if (chain.length === 0) {
            html += `<p class="chain-hint">Ledger is empty — no blocks to verify.</p>`;
        } else {
            html += `<div class="chain-blocks-list">`;
            chain.forEach((blk, i) => {
                const blkValid = blk.valid;
                const blkColor = blkValid ? '#2ecc71' : '#e74c3c';
                const prevLabel = i === 0 ? 'Genesis' : `Block #${i - 1}`;
                const chainArrow = blk.chain_link_valid
                    ? `<span class="chain-arrow chain-arrow-ok" title="prev_hash matches block #${i - 1}">→</span>`
                    : `<span class="chain-arrow chain-arrow-bad" title="BROKEN: prev_hash does not match block #${i - 1}">⚡</span>`;

                // Show full hash when there's a mismatch so the difference is visible
                const prevStoredDisplay   = !blk.chain_link_valid
                    ? (blk.prev_hash_stored_full   || blk.prev_hash_stored   || '—')
                    : (blk.prev_hash_stored   || '—');
                const prevExpectedDisplay = !blk.chain_link_valid
                    ? (blk.prev_hash_expected_full || blk.prev_hash_expected || prevLabel)
                    : (blk.prev_hash_expected || prevLabel);
                const blockHashDisplay = !blk.block_hash_valid
                    ? (blk.block_hash_full || blk.block_hash || '—')
                    : (blk.block_hash || '—');

                html += `
                <div class="chain-block-row" style="border-left:3px solid ${blkColor};">
                    <div class="chain-block-header">
                        <span class="chain-block-seq" style="color:${blkColor};">Block #${blk.seq}</span>
                        <span class="chain-block-meta">${escapeHtml(blk.doc_type || '—')} &nbsp;|&nbsp; ${escapeHtml(blk.verdict || '—')} &nbsp;|&nbsp; ${escapeHtml((blk.timestamp || '').replace('T',' ').replace('Z',''))} UTC</span>
                        <span class="chain-block-status" style="color:${blkColor};">${blkValid ? '✓ OK' : '✗ INVALID'}</span>
                    </div>
                    <div class="chain-block-hashes">
                        <div class="chain-hash-row">
                            <span class="chain-hash-label">block_hash</span>
                            <code class="chain-hash-val ${blk.block_hash_valid ? '' : 'chain-hash-bad'}">${escapeHtml(blockHashDisplay)}</code>
                            <span class="chain-hash-note">${blk.block_hash_valid ? '✓ content intact' : '✗ HASH MISMATCH — content was altered'}</span>
                        </div>
                        <div class="chain-hash-row" style="margin-top:4px;">
                            ${i > 0 ? chainArrow : ''}
                            <span class="chain-hash-label">prev_hash</span>
                            <code class="chain-hash-val ${blk.chain_link_valid ? '' : 'chain-hash-bad'}">${escapeHtml(prevStoredDisplay)}</code>
                            ${!blk.chain_link_valid ? `<span class="chain-hash-note" style="color:#e74c3c;">expected: ${escapeHtml(prevExpectedDisplay)}</span>` : `<span class="chain-hash-note">✓ links to ${escapeHtml(prevLabel)}</span>`}
                        </div>
                    </div>
                    ${blk.errors && blk.errors.length ? `<div class="chain-block-errors">${blk.errors.map(e => escapeHtml(e)).join('<br>')}</div>` : ''}
                </div>`;
            });
            html += `</div>`;
        }

        chainResult.innerHTML = html;
    }
})();
