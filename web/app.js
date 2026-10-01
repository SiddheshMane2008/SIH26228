/**
 * VisionGuard Offline Web Dashboard Controller
 */

let currentPassport = null;

function switchTab(tabId) {
    document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));

    const targetTab = document.getElementById(`tab-${tabId}`);
    if (targetTab) targetTab.classList.add('active');

    // Highlight nav button
    const buttons = document.querySelectorAll('.nav-item');
    buttons.forEach(btn => {
        if (btn.getAttribute('onclick').includes(tabId)) {
            btn.classList.add('active');
        }
    });

    if (tabId === 'blast') {
        traceBlastRadius();
    }
}

async function changeEmbedder(name) {
    try {
        const res = await fetch(`/api/embedder/select?name=${name}`, { method: 'POST' });
        const data = await res.json();
        document.getElementById('embedder-status').innerText = `Embedder: ${data.selected_embedder} (${data.dimension}d)`;
    } catch (e) {
        console.error("Failed to switch embedder:", e);
    }
}

async function runScenario(scenarioId) {
    showProgress(true, `Executing Scenario ${scenarioId}...`);
    try {
        const res = await fetch(`/api/demo/run-scenario/${scenarioId}`);
        const data = await res.json();
        renderAuditResults(data.passport, data.report_url);
        switchTab('dashboard');
    } catch (e) {
        alert("Error executing scenario: " + e);
    } finally {
        showProgress(false);
    }
}

async function runCustomAudit() {
    showProgress(true, "Auditing configured assets...");
    try {
        // Run scenario 2 as default custom demonstration
        const res = await fetch(`/api/demo/run-scenario/2`);
        const data = await res.json();
        renderAuditResults(data.passport, data.report_url);
    } catch (e) {
        alert("Error running audit: " + e);
    } finally {
        showProgress(false);
    }
}

function renderAuditResults(passport, reportUrl) {
    currentPassport = passport;

    // Update Topbar Stats
    const dispEl = document.getElementById('val-disp');
    dispEl.innerText = passport.overall_disposition;
    dispEl.className = `stat-value badge-${passport.overall_disposition.toLowerCase()}`;

    document.getElementById('val-conf').innerText = `${Math.round(passport.overall_confidence * 100)}%`;
    document.getElementById('val-findings').innerText = passport.findings_summary ? passport.findings_summary.total : passport.top_findings.length;
    document.getElementById('val-passport-id').innerText = passport.passport_id;

    // Update Findings Table
    const tbody = document.getElementById('findings-tbody');
    tbody.innerHTML = '';

    if (!passport.top_findings || passport.top_findings.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--emerald);">✅ No integrity violations detected. All modules verified clean.</td></tr>`;
    } else {
        passport.top_findings.forEach(f => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td style="font-family: monospace; font-weight: 600;">${f.finding_id}</td>
                <td><span class="badge badge-module">${f.module}</span></td>
                <td style="font-family: monospace;">${f.asset}</td>
                <td>${f.reason}</td>
                <td><span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span></td>
                <td><span class="badge badge-${f.disposition.toLowerCase()}">${f.disposition}</span></td>
                <td style="font-size: 12px;">${f.recommended_action}</td>
            `;
            tbody.appendChild(tr);
        });
    }

    document.getElementById('findings-count-badge').innerText = `${passport.top_findings.length} Flagged`;

    // Update Passport Tab
    document.getElementById('pp-id').innerText = `PASSPORT: ${passport.passport_id}`;
    document.getElementById('pp-summary').innerText = passport.executive_summary;
    const ppDisp = document.getElementById('pp-disp-badge');
    ppDisp.innerText = passport.overall_disposition;
    ppDisp.className = `badge badge-${passport.overall_disposition.toLowerCase()}`;

    document.getElementById('pp-conf').innerText = `${Math.round(passport.overall_confidence * 100)}%`;
    document.getElementById('pp-pubkey').innerText = passport.signer_public_key_hex;
    document.getElementById('pp-digest').innerText = passport.passport_digest;
    document.getElementById('pp-sig').innerText = passport.signature_hex;

    if (reportUrl) {
        const btnRep = document.getElementById('btn-view-html-report');
        btnRep.href = reportUrl;
        btnRep.classList.remove('hidden');
    }
}

async function verifyCurrentPassport() {
    if (!currentPassport) {
        alert("No active passport to verify. Run an audit first.");
        return;
    }
    const resultBox = document.getElementById('passport-verify-result');
    resultBox.classList.remove('hidden', 'success', 'error');
    resultBox.innerText = "Verifying Ed25519 digital signature and canonical hash...";

    try {
        const res = await fetch('/api/passport/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(currentPassport)
        });
        const data = await res.json();
        if (data.is_valid) {
            resultBox.className = 'verify-alert success';
            resultBox.innerHTML = `✅ <strong>VALID PASSPORT</strong>: ${data.message} (Public Key: ${currentPassport.signer_public_key_hex.slice(0, 16)}...)`;
        } else {
            resultBox.className = 'verify-alert error';
            resultBox.innerHTML = `❌ <strong>VERIFICATION FAILED</strong>: ${data.message}`;
        }
    } catch (e) {
        resultBox.className = 'verify-alert error';
        resultBox.innerText = "Verification request failed: " + e;
    }
}

async function traceBlastRadius() {
    const rootId = document.getElementById('blast-root-input').value || "Contributor_B_External";
    try {
        const res = await fetch(`/api/blast-radius?root_id=${encodeURIComponent(rootId)}`);
        const data = await res.json();
        const trace = data.trace;

        document.getElementById('blast-results-box').classList.remove('hidden');
        document.getElementById('blast-summary-text').innerText = trace.description;
        document.getElementById('blast-val-datasets').innerText = trace.affected_datasets.length;
        document.getElementById('blast-val-models').innerText = trace.affected_models.length;
        document.getElementById('blast-val-inferences').innerText = trace.affected_inference_records.length;
        document.getElementById('blast-val-sev').innerText = trace.severity;

        document.getElementById('blast-mermaid').innerText = data.mermaid;
    } catch (e) {
        console.error("Blast radius query failed:", e);
    }
}

async function runRedTeamBenchmark() {
    try {
        const res = await fetch('/api/redteam/benchmark?seed=42');
        const data = await res.json();

        document.getElementById('rt-macro-p').innerText = `${(data.macro_precision * 100).toFixed(1)}%`;
        document.getElementById('rt-macro-r').innerText = `${(data.macro_recall * 100).toFixed(1)}%`;
        document.getElementById('rt-macro-f1').innerText = `${(data.macro_f1 * 100).toFixed(1)}%`;

        const tbody = document.getElementById('rt-tbody');
        tbody.innerHTML = '';
        data.scenarios_evaluated.forEach(s => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${s.attack_name}</strong></td>
                <td><span class="badge badge-module">${s.attack_family.toUpperCase()}</span></td>
                <td>${s.sample_count}</td>
                <td>${s.detected_count}</td>
                <td>${(s.precision * 100).toFixed(1)}%</td>
                <td>${(s.recall * 100).toFixed(1)}%</td>
                <td><strong>${s.f1_score.toFixed(2)}</strong></td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        alert("Benchmark failed: " + e);
    }
}

function showProgress(show, text) {
    const box = document.getElementById('audit-progress');
    if (show) {
        box.classList.remove('hidden');
        if (text) document.getElementById('progress-status-text').innerText = text;
    } else {
        box.classList.add('hidden');
    }
}

// Initial status fetch on load
window.addEventListener('DOMContentLoaded', async () => {
    try {
        const res = await fetch('/api/status');
        const data = await res.json();
        document.getElementById('embedder-status').innerText = `Embedder: ${data.active_embedder} (${data.embedder_dimension}d)`;
    } catch (e) {}
});

/* ========================================================================= */
/* UPLOAD & AUDIT WORKFLOW CONTROLLERS                                       */
/* ========================================================================= */

function switchUploadSubtab(subtabId) {
    document.querySelectorAll('.upload-pane').forEach(el => el.classList.add('hidden'));
    document.querySelectorAll('.subnav-btn').forEach(btn => btn.classList.remove('active'));

    const targetPane = document.getElementById(`subtab-${subtabId}`);
    if (targetPane) targetPane.classList.remove('hidden');

    const buttons = document.querySelectorAll('.subnav-btn');
    buttons.forEach(btn => {
        if (btn.getAttribute('onclick') && btn.getAttribute('onclick').includes(subtabId)) {
            btn.classList.add('active');
        }
    });
}

function previewUploadImage(input) {
    if (input.files && input.files[0]) {
        const reader = new FileReader();
        reader.onload = function(e) {
            const preview = document.getElementById('image-preview-thumb');
            if (preview) preview.src = e.target.result;
        };
        reader.readAsDataURL(input.files[0]);
    }
}

async function submitSingleImageUpload() {
    const fileInput = document.getElementById('upload-image-file');
    if (!fileInput.files || fileInput.files.length === 0) {
        alert("Please select an image file to audit.");
        return;
    }

    const expectedLabel = document.getElementById('upload-image-expected').value.trim();
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    if (expectedLabel) {
        formData.append('expected_label', expectedLabel);
    }

    showProgress(true, "Extracting photometrics, embeddings & analyzing integrity...");
    try {
        const res = await fetch('/api/upload/image', {
            method: 'POST',
            body: formData
        });
        const data = await res.json();
        if (data.error) {
            alert("Upload failed: " + data.error);
            return;
        }

        currentPassport = data.passport;
        const resultsBox = document.getElementById('image-audit-results');
        resultsBox.classList.remove('hidden');

        // Disclaimer Banner
        const discBanner = document.getElementById('image-disclaimer-banner');
        const discText = document.getElementById('image-disclaimer-text');
        if (data.ground_truth_disclaimer) {
            discBanner.classList.remove('hidden');
            discText.innerText = data.ground_truth_disclaimer;
        } else {
            discBanner.classList.add('hidden');
        }

        // Stats & Badges
        const disp = data.disposition;
        const dispEl = document.getElementById('img-val-disp');
        dispEl.innerText = disp;
        dispEl.className = `stat-value badge-${disp.toLowerCase()}`;

        const statusBadge = document.getElementById('image-status-badge');
        statusBadge.innerText = disp;
        statusBadge.className = `badge badge-${disp.toLowerCase()}`;

        document.getElementById('img-val-conf').innerText = `${Math.round(data.confidence * 100)}%`;
        document.getElementById('img-val-sharpness').innerText = Math.round(data.forensics.laplacian_sharpness || 0);
        document.getElementById('img-val-ref').innerText = `${data.reference_classification.top_class} (${(data.reference_classification.confidence * 100).toFixed(1)}%)`;

        // Forensic Table
        document.getElementById('img-ev-sha').innerText = data.forensics.sha256;
        document.getElementById('img-ev-phash').innerText = data.forensics.phash;
        document.getElementById('img-ev-dims').innerText = `${data.forensics.dimensions} (${data.forensics.file_size_bytes} bytes)`;
        document.getElementById('img-ev-photometrics').innerText = `Brightness: ${data.forensics.mean_brightness.toFixed(1)}, Contrast: ${data.forensics.std_contrast.toFixed(1)}`;
        
        const top5Str = data.reference_classification.top5.map(c => `${c.class} (${(c.confidence * 100).toFixed(1)}%)`).join(', ');
        document.getElementById('img-ev-topclasses').innerText = top5Str;

        // Findings
        const findingsList = document.getElementById('img-findings-list');
        findingsList.innerHTML = '';
        if (!data.findings || data.findings.length === 0) {
            findingsList.innerHTML = '<p style="color: var(--emerald); font-size: 13px;">✅ Clean image — no integrity anomalies or trigger patterns detected.</p>';
        } else {
            data.findings.forEach(f => {
                const item = document.createElement('div');
                item.style.padding = '8px 12px';
                item.style.marginBottom = '6px';
                item.style.borderRadius = '6px';
                item.style.background = '#030712';
                item.style.border = '1px solid var(--border)';
                item.innerHTML = `
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                        <span style="font-weight: 600; font-family: monospace;">${f.finding_id}</span>
                        <span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span>
                    </div>
                    <div style="font-size: 13px; color: var(--text);">${f.reason}</div>
                    <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">Action: ${f.recommended_action}</div>
                `;
                findingsList.appendChild(item);
            });
        }
    } catch (e) {
        alert("Image audit failed: " + e);
    } finally {
        showProgress(false);
    }
}

async function submitDatasetUpload() {
    const fileInput = document.getElementById('upload-dataset-file');
    if (!fileInput.files || fileInput.files.length === 0) {
        alert("Please select a dataset ZIP archive.");
        return;
    }

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);

    showProgress(true, "Unpacking dataset, inspecting annotations & auditing samples...");
    try {
        const res = await fetch('/api/upload/dataset', {
            method: 'POST',
            body: formData
        });
        const data = await res.json();
        if (data.error) {
            alert("Dataset audit failed: " + data.error);
            return;
        }

        currentPassport = data.passport;
        document.getElementById('dataset-audit-results').classList.remove('hidden');

        document.getElementById('ds-val-format').innerText = data.format.toUpperCase();
        document.getElementById('ds-val-samples').innerText = `${data.clean_samples} / ${data.total_samples}`;
        
        const dispEl = document.getElementById('ds-val-disp');
        dispEl.innerText = data.disposition;
        dispEl.className = `stat-value badge-${data.disposition.toLowerCase()}`;

        document.getElementById('ds-val-findings').innerText = data.findings_count;

        const reportBox = document.getElementById('ds-report-link-box');
        if (data.report_url) {
            reportBox.innerHTML = `<a href="${data.report_url}" target="_blank" class="btn btn-secondary">📄 View Generated HTML Audit Report</a>`;
        }

        const tbody = document.getElementById('ds-findings-tbody');
        tbody.innerHTML = '';
        if (!data.findings || data.findings.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--emerald);">✅ No dataset integrity anomalies detected.</td></tr>`;
        } else {
            data.findings.forEach(f => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td style="font-family: monospace; font-weight: 600;">${f.finding_id}</td>
                    <td><span class="badge badge-module">${f.module}</span></td>
                    <td style="font-family: monospace;">${f.asset}</td>
                    <td>${f.reason}</td>
                    <td><span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span></td>
                    <td style="font-size: 12px;">${f.recommended_action}</td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch (e) {
        alert("Dataset audit failed: " + e);
    } finally {
        showProgress(false);
    }
}

async function submitModelUpload() {
    const fileInput = document.getElementById('upload-model-file');
    if (!fileInput.files || fileInput.files.length === 0) {
        alert("Please select a model file (.onnx, .pt, .pth).");
        return;
    }

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);

    showProgress(true, "Validating model format, hashing parameters & auditing...");
    try {
        const res = await fetch('/api/upload/model', {
            method: 'POST',
            body: formData
        });
        const data = await res.json();
        if (data.error) {
            alert("Model audit failed: " + data.error);
            return;
        }

        currentPassport = data.passport;
        document.getElementById('model-audit-results').classList.remove('hidden');

        document.getElementById('mod-val-access').innerText = data.access_level;
        document.getElementById('mod-val-params').innerText = data.total_parameters.toLocaleString();

        const dispEl = document.getElementById('mod-val-disp');
        dispEl.innerText = data.disposition;
        dispEl.className = `stat-value badge-${data.disposition.toLowerCase()}`;

        document.getElementById('mod-val-conf').innerText = `${Math.round(data.confidence * 100)}%`;
        document.getElementById('mod-ev-weight-sha').innerText = data.weight_sha256;
        document.getElementById('mod-ev-graph-sha').innerText = data.graph_sha256;

        const findingsList = document.getElementById('mod-findings-list');
        findingsList.innerHTML = '';
        if (!data.findings || data.findings.length === 0) {
            findingsList.innerHTML = '<p style="color: var(--emerald); font-size: 13px;">✅ Model structure & weights verified clean against assurance specifications.</p>';
        } else {
            data.findings.forEach(f => {
                const item = document.createElement('div');
                item.style.padding = '8px 12px';
                item.style.marginBottom = '6px';
                item.style.borderRadius = '6px';
                item.style.background = '#030712';
                item.style.border = '1px solid var(--border)';
                item.innerHTML = `
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                        <span style="font-weight: 600; font-family: monospace;">${f.finding_id}</span>
                        <span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span>
                    </div>
                    <div style="font-size: 13px; color: var(--text);">${f.reason}</div>
                    <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">Action: ${f.recommended_action}</div>
                `;
                findingsList.appendChild(item);
            });
        }
    } catch (e) {
        alert("Model audit failed: " + e);
    } finally {
        showProgress(false);
    }
}

async function submitShiftUpload() {
    const baseFiles = document.getElementById('upload-shift-base').files;
    const opFiles = document.getElementById('upload-shift-op').files;

    if (!baseFiles || baseFiles.length < 2 || !opFiles || opFiles.length < 2) {
        alert("Please provide at least 2 baseline images and 2 operational images to calculate statistical shift distributions.");
        return;
    }

    const formData = new FormData();
    for (let i = 0; i < baseFiles.length; i++) {
        formData.append('baseline_files', baseFiles[i]);
    }
    for (let i = 0; i < opFiles.length; i++) {
        formData.append('operational_files', opFiles[i]);
    }

    showProgress(true, "Computing photometric PSI, Wasserstein distance & color distributions...");
    try {
        const res = await fetch('/api/shift/diagnose', {
            method: 'POST',
            body: formData
        });
        const data = await res.json();
        if (data.error) {
            alert("Shift diagnosis failed: " + data.error);
            return;
        }

        currentPassport = data.passport;
        document.getElementById('shift-audit-results').classList.remove('hidden');

        document.getElementById('sh-val-bpsi').innerText = data.metrics.brightness_psi.toFixed(3);
        document.getElementById('sh-val-cpsi').innerText = data.metrics.contrast_psi.toFixed(3);
        document.getElementById('sh-val-sharpness').innerText = data.metrics.sharpness_wasserstein.toFixed(2);
        document.getElementById('sh-val-risk').innerText = (data.composite_drift_score * 100).toFixed(1) + '%';

        document.getElementById('sh-characterization').innerText = data.shift_characterization;

        const findingsList = document.getElementById('sh-findings-list');
        findingsList.innerHTML = '';
        if (!data.findings || data.findings.length === 0) {
            findingsList.innerHTML = '<p style="color: var(--emerald); font-size: 13px;">✅ Shift is within acceptable operational tolerance thresholds.</p>';
        } else {
            data.findings.forEach(f => {
                const item = document.createElement('div');
                item.style.padding = '8px 12px';
                item.style.marginBottom = '6px';
                item.style.borderRadius = '6px';
                item.style.background = '#030712';
                item.style.border = '1px solid var(--border)';
                item.innerHTML = `
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                        <span style="font-weight: 600; font-family: monospace;">${f.finding_id}</span>
                        <span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span>
                    </div>
                    <div style="font-size: 13px; color: var(--text);">${f.reason}</div>
                    <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">Action: ${f.recommended_action}</div>
                `;
                findingsList.appendChild(item);
            });
        }
    } catch (e) {
        alert("Shift analysis failed: " + e);
    } finally {
        showProgress(false);
    }
}
