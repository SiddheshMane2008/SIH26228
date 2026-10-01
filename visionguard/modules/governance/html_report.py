"""
Self-Contained Offline HTML Report Generator for VisionGuard

Generates a standalone, fully air-gapped HTML report with embedded CSS/JS.
Zero external CDN dependencies (works completely without internet).
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from visionguard.core.schemas import (
    BlastRadiusTrace,
    DataSentinelResult,
    ModelAuditorResult,
    ProvenanceAuditResult,
    ShiftDiagnosticianResult,
    TrustPassport
)


class HTMLReportGenerator:
    """Renders comprehensive offline HTML audit reports."""

    @staticmethod
    def generate_report(
        passport: TrustPassport,
        data_sentinel_res: Optional[DataSentinelResult] = None,
        model_auditor_res: Optional[ModelAuditorResult] = None,
        provenance_res: Optional[ProvenanceAuditResult] = None,
        shift_res: Optional[ShiftDiagnosticianResult] = None,
        blast_radius: Optional[BlastRadiusTrace] = None,
        output_file: Optional[Path] = None
    ) -> str:
        # Determine theme colors based on overall disposition
        disp = passport.overall_disposition.value
        disp_colors = {
            "ACCEPT": {"bg": "#064e3b", "border": "#10b981", "badge": "#059669", "text": "#34d399"},
            "REVIEW": {"bg": "#78350f", "border": "#f59e0b", "badge": "#d97706", "text": "#fbbf24"},
            "QUARANTINE": {"bg": "#881337", "border": "#f43f5e", "badge": "#e11d48", "text": "#fda4af"}
        }
        theme = disp_colors.get(disp, disp_colors["REVIEW"])

        # Format findings rows
        findings_rows = []
        for f in passport.top_findings:
            sev_class = f"badge-{f.severity.value.lower()}"
            disp_class = f"badge-{f.disposition.value.lower()}"
            evidence_str = json.dumps(f.evidence, indent=2)
            findings_rows.append(f"""
            <tr>
                <td style="font-family: monospace; font-weight: bold;">{f.finding_id}</td>
                <td><span class="badge badge-module">{f.module.value}</span></td>
                <td style="font-family: monospace;">{f.asset}</td>
                <td><strong>{f.reason}</strong></td>
                <td><span class="badge {sev_class}">{f.severity.value}</span></td>
                <td><span class="badge {disp_class}">{f.disposition.value}</span></td>
                <td>{f.recommended_action}</td>
            </tr>
            """)

        limitations_html = "".join([f"<li>{lim}</li>" for lim in passport.explicit_limitations])
        coverage_html = "".join([f"<li>{cov}</li>" for cov in passport.coverage_statement])

        # Blast Radius Summary
        br_html = "<p>No downstream blast radius trace requested for this run.</p>"
        if blast_radius:
            br_html = f"""
            <div style="background: rgba(15, 23, 42, 0.6); padding: 16px; border-radius: 8px; border: 1px solid #334155;">
                <p><strong>Downstream Impact Description:</strong> {blast_radius.description}</p>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-top: 12px;">
                    <div class="stat-card">
                        <div class="stat-label">Impacted Datasets</div>
                        <div class="stat-value">{len(blast_radius.affected_datasets)}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Impacted Models</div>
                        <div class="stat-value">{len(blast_radius.affected_models)}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Inference Records</div>
                        <div class="stat-value">{len(blast_radius.affected_inference_records)}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Assessed Severity</div>
                        <div class="stat-value" style="color: #f43f5e;">{blast_radius.severity.value}</div>
                    </div>
                </div>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VisionGuard Trust Passport & Assurance Report</title>
    <style>
        :root {{
            --bg-color: #0b0f19;
            --card-bg: #111827;
            --border-color: #1f2937;
            --text-main: #f9fafb;
            --text-muted: #9ca3af;
            --accent: #3b82f6;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            line-height: 1.5;
            padding: 24px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 16px;
            margin-bottom: 24px;
        }}
        .brand {{ display: flex; align-items: center; gap: 12px; }}
        .brand h1 {{ font-size: 24px; letter-spacing: -0.5px; }}
        .passport-banner {{
            background: linear-gradient(135deg, {theme['bg']} 0%, #111827 100%);
            border: 2px solid {theme['border']};
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
        }}
        .passport-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 16px;
        }}
        .passport-title {{ font-size: 20px; font-weight: 700; color: {theme['text']}; }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge-disposition {{ background: {theme['badge']}; color: #fff; font-size: 14px; padding: 6px 14px; }}
        .badge-critical {{ background: #be123c; color: #fff; }}
        .badge-high {{ background: #e11d48; color: #fff; }}
        .badge-medium {{ background: #d97706; color: #fff; }}
        .badge-low {{ background: #2563eb; color: #fff; }}
        .badge-accept {{ background: #059669; color: #fff; }}
        .badge-review {{ background: #d97706; color: #fff; }}
        .badge-quarantine {{ background: #be123c; color: #fff; }}
        .badge-module {{ background: #374151; color: #e5e7eb; }}
        .grid-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            padding: 16px;
            border-radius: 8px;
        }}
        .stat-label {{ font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }}
        .stat-value {{ font-size: 22px; font-weight: 700; margin-top: 4px; }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 24px;
        }}
        .card-title {{ font-size: 16px; font-weight: 600; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        th, td {{
            text-align: left;
            padding: 10px 12px;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{ background: #1f2937; color: var(--text-muted); text-transform: uppercase; font-size: 11px; }}
        tr:hover {{ background: rgba(255, 255, 255, 0.02); }}
        .crypto-box {{
            background: #030712;
            border: 1px solid #1f2937;
            padding: 12px;
            border-radius: 6px;
            font-family: monospace;
            font-size: 11px;
            word-break: break-all;
            margin-top: 8px;
            color: #60a5fa;
        }}
        ul {{ padding-left: 20px; font-size: 13px; color: var(--text-muted); }}
        li {{ margin-bottom: 6px; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <span style="font-size: 28px;">🛡️</span>
                <div>
                    <h1>VisionGuard</h1>
                    <p style="font-size: 12px; color: var(--text-muted);">Fully Offline Computer-Vision Assurance Engine</p>
                </div>
            </div>
            <div style="text-align: right;">
                <span class="badge" style="background: #1e293b; border: 1px solid #3b82f6;">AIR-GAPPED AUDIT</span>
                <p style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">{passport.generated_at}</p>
            </div>
        </header>

        <!-- Trust Passport Hero Card -->
        <div class="passport-banner">
            <div class="passport-header">
                <div>
                    <div style="font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: #94a3b8;">Cryptographic Assurance Artifact</div>
                    <div class="passport-title">Trust Passport: {passport.passport_id}</div>
                </div>
                <span class="badge badge-disposition">{disp}</span>
            </div>
            <p style="margin-bottom: 16px; font-size: 14px;">{passport.executive_summary}</p>
            <div style="display: flex; gap: 16px; flex-wrap: wrap;">
                <div><span style="color: var(--text-muted); font-size: 12px;">Confidence:</span> <strong>{passport.overall_confidence:.0%}</strong></div>
                <div><span style="color: var(--text-muted); font-size: 12px;">Signer Algorithm:</span> <strong>Ed25519</strong></div>
                <div><span style="color: var(--text-muted); font-size: 12px;">Engine Version:</span> <strong>{passport.engine_version}</strong></div>
            </div>
            <div class="crypto-box">
                <div><strong>Ed25519 Public Key:</strong> {passport.signer_public_key_hex}</div>
                <div><strong>Payload SHA-256 Digest:</strong> {passport.passport_digest}</div>
                <div><strong>Digital Signature:</strong> {passport.signature_hex}</div>
            </div>
        </div>

        <!-- Lifecycle Overview Statistics -->
        <div class="grid-stats">
            <div class="stat-card">
                <div class="stat-label">Total Findings</div>
                <div class="stat-value">{passport.findings_summary.get('total', 0)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Critical Findings</div>
                <div class="stat-value" style="color: #f43f5e;">{passport.findings_summary.get('critical', 0)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">High Findings</div>
                <div class="stat-value" style="color: #fb7185;">{passport.findings_summary.get('high', 0)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Medium Findings</div>
                <div class="stat-value" style="color: #fbbf24;">{passport.findings_summary.get('medium', 0)}</div>
            </div>
        </div>

        <!-- Top Findings Table -->
        <div class="card">
            <div class="card-title">🔍 Priority Forensic Findings</div>
            <table>
                <thead>
                    <tr>
                        <th>Finding ID</th>
                        <th>Module</th>
                        <th>Asset</th>
                        <th>Reason</th>
                        <th>Severity</th>
                        <th>Disposition</th>
                        <th>Recommended Action</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(findings_rows) if findings_rows else "<tr><td colspan='7' style='text-align: center;'>No critical findings detected. All modules verified clean.</td></tr>"}
                </tbody>
            </table>
        </div>

        <!-- Downstream Blast Radius -->
        <div class="card">
            <div class="card-title">💥 Source & Downstream Impact (Blast Radius)</div>
            {br_html}
        </div>

        <!-- Explicit Coverage Statement -->
        <div class="card">
            <div class="card-title">📋 Defined Coverage Statement</div>
            <ul>{coverage_html}</ul>
        </div>

        <!-- Explicit Limitations -->
        <div class="card" style="border-left: 4px solid #f59e0b;">
            <div class="card-title" style="color: #fbbf24;">⚠️ Explicit Operational Limitations & Non-Claims</div>
            <ul>{limitations_html}</ul>
        </div>
    </div>
</body>
</html>
"""
        if output_file:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(html)

        return html
