// DEV FIXTURES — used only when VITE_VISIONGUARD_API is unset AND the same-origin backend is unreachable.
// Every value here is synthetic. The UI labels fixture-sourced data explicitly; never ship these as evidence.
import type { BlastResponse, EmbedderSelectResponse, Finding, Passport, RedTeamResponse, ScenarioResponse, StatusResponse } from './types'

export const FIXTURE_NOTICE = 'Synthetic dev fixture — not produced by the VisionGuard backend.'

const EMBEDDERS: Record<string, number> = { 'clip-vit-b32': 512, 'dinov2-small': 384, 'resnet50-pool': 2048 }
let active = 'clip-vit-b32'

export const status: StatusResponse = {
  get active_embedder() { return active },
  get embedder_dimension() { return EMBEDDERS[active] },
  available_embedders: Object.keys(EMBEDDERS),
  fixture: true,
} as StatusResponse

export function selectEmbedder(name: string): EmbedderSelectResponse {
  if (!(name in EMBEDDERS)) throw new Error(`Unknown embedder "${name}" (fixture)`)
  active = name
  return { selected_embedder: name, dimension: EMBEDDERS[name] }
}

const f = (id: string, module: string, asset: string, reason: string, severity: string, disposition: string, recommended_action: string, confidence: number, evidence?: unknown): Finding =>
  ({ finding_id: id, module, asset, reason, severity, disposition, recommended_action, confidence, evidence })

const FINDINGS: Record<number, Finding[]> = {
  1: [
    f('FX-1-001', 'data_sentinel', 'dataset:traffic-v3', 'No duplicate, trigger or label-noise anomalies above threshold.', 'LOW', 'CLEAR', 'None', 0.97),
    f('FX-1-002', 'provenance', 'model:yolo-traffic@1.4.0', 'Artefact digest matches signed lineage record.', 'LOW', 'CLEAR', 'None', 0.99),
  ],
  2: [
    f('FX-2-001', 'data_sentinel', 'dataset:traffic-v3/shard-07', '212 images share a 14×14 high-frequency patch in the lower-right quadrant.', 'CRITICAL', 'QUARANTINE', 'Quarantine shard-07 and retrain from last clean snapshot', 0.94, { cluster_size: 212, patch_px: 14, cosine_to_centroid: 0.981 }),
    f('FX-2-002', 'model_auditor', 'model:yolo-traffic@1.4.1', 'Trigger-conditioned misclassification: stop → speed-limit at 88% ASR.', 'HIGH', 'QUARANTINE', 'Block deployment; run neural-cleanse on final layers', 0.88, { attack_success_rate: 0.88 }),
    f('FX-2-003', 'data_sentinel', 'dataset:traffic-v3/shard-07', 'Label disagreement with ensemble oracle on 9.1% of shard.', 'MEDIUM', 'REVIEW', 'Send shard for human relabel audit', 0.71),
  ],
  3: [
    f('FX-3-001', 'model_auditor', 'model:yolo-traffic@1.4.1', 'Behavioral divergence: model outputs diverge from registered golden fingerprint.', 'CRITICAL', 'QUARANTINE', 'Block model deployment; restore verified checkpoint', 0.96, { divergence_rate: 0.14 }),
    f('FX-3-002', 'provenance', 'model:yolo-traffic@1.4.1', 'Fingerprint hash mismatch vs signed governance registry.', 'HIGH', 'QUARANTINE', 'Revoke model certificate', 0.99),
  ],
  4: [
    f('FX-4-001', 'provenance', 'inf:cam-north-12/2026-09-28', 'Output payload modified: SHA-256 digest ≠ recorded block digest.', 'CRITICAL', 'QUARANTINE', 'Isolate inference log shard and verify cryptographic chain links', 0.99, { payload_tampered: true }),
    f('FX-4-002', 'provenance', 'inf:cam-north-12/2026-09-28', 'Invalid Ed25519 digital signature on block header.', 'HIGH', 'QUARANTINE', 'Audit edge device credentials', 0.98),
  ],
  5: [
    f('FX-5-001', 'shift_diagnostician', 'stream:cam-north-12', 'Photometric plunge under environmental fog (Sharpness Wasserstein: 18.4, Contrast PSI: 0.38).', 'HIGH', 'REVIEW', 'Collect adverse weather samples; recalibrate confidence threshold', 0.88, { wasserstein: 18.4, contrast_psi: 0.38 }),
    f('FX-5-002', 'model_auditor', 'model:yolo-traffic@1.4.0', 'Expected calibration error rose from 0.04 to 0.17 on shifted slice.', 'MEDIUM', 'REVIEW', 'Apply temperature scaling on field slice', 0.76),
  ],
}

const ORDER = ['CLEAR', 'REVIEW', 'QUARANTINE']
export function scenario(id: number): ScenarioResponse {
  const top = FINDINGS[id]
  if (!top) throw new Error(`Scenario ${id} has no fixture`)
  const overall = top.reduce((w, x) => (ORDER.indexOf(x.disposition) > ORDER.indexOf(w) ? x.disposition : w), 'CLEAR')
  const conf = top.reduce((s, x) => s + (x.confidence ?? 0), 0) / top.length
  const passport: Passport = {
    passport_id: `FIXTURE-${id}-${Date.now().toString(36).toUpperCase()}`,
    overall_disposition: overall,
    overall_confidence: Number(conf.toFixed(3)),
    findings_summary: { total: top.length, critical: top.filter((x) => x.severity === 'CRITICAL').length },
    top_findings: top,
    executive_summary: `[fixture] ${top.length} finding(s) across ${new Set(top.map((x) => x.module)).size} module(s); overall disposition ${overall}.`,
    // Fixtures are unsigned by design — verification must not pass.
    signer_public_key_hex: '',
    passport_digest: '',
    signature_hex: '',
    fixture: true,
  }
  return { passport }
}

export function blast(rootId: string): BlastResponse {
  const id = rootId.trim() || 'dataset:traffic-v3/shard-07'
  return {
    trace: {
      description: `[fixture] Downstream closure of ${id}`,
      affected_datasets: [id, 'dataset:traffic-v3-aug'],
      affected_models: ['model:yolo-traffic@1.4.1', 'model:yolo-traffic-distilled@0.9'],
      affected_inference_records: ['inf:cam-north-12/2026-09-28', 'inf:cam-east-04/2026-09-28', 'inf:cam-east-04/2026-09-29'],
      severity: 'HIGH',
    },
    mermaid: `graph LR\n  A["${id}"] --> B["dataset:traffic-v3-aug"]\n  A --> M1["model:yolo-traffic@1.4.1"]\n  B --> M2["model:yolo-traffic-distilled@0.9"]\n  M1 --> I1["inf:cam-north-12"]\n  M2 --> I2["inf:cam-east-04"]`,
  }
}

const rt = (attack_name: string, attack_family: string, sample_count: number, detected_count: number, precision: number, recall: number) =>
  ({ attack_name, attack_family, sample_count, detected_count, precision, recall, f1_score: Number(((2 * precision * recall) / (precision + recall)).toFixed(3)) })

const SC = [
  rt('BadNets patch', 'backdoor', 200, 188, 0.96, 0.94),
  rt('Blended trigger', 'backdoor', 200, 171, 0.91, 0.855),
  rt('Label flip 10%', 'poisoning', 300, 246, 0.88, 0.82),
  rt('Near-duplicate flood', 'poisoning', 150, 147, 0.99, 0.98),
  rt('Gaussian fog shift', 'shift', 250, 221, 0.9, 0.884),
  rt('Weight bit-flip', 'tamper', 50, 50, 1, 1),
]
const mean = (k: 'precision' | 'recall' | 'f1_score') => Number((SC.reduce((s, x) => s + x[k], 0) / SC.length).toFixed(3))
export const redteam: RedTeamResponse = { macro_precision: mean('precision'), macro_recall: mean('recall'), macro_f1: mean('f1_score'), scenarios_evaluated: SC }

// ── Extended-contract fixtures (dev only) ──
import type { AssetKind, EmbedderList, IngestResponse, ModelAudit, ProvenanceChain, ShiftMetrics } from './types'

export const embedders = (): EmbedderList => ({
  embedders: [
    ...Object.entries(EMBEDDERS).map(([name, dimension]) => ({ name, dimension, available: true, loaded: name === active })),
    { name: 'siglip2-base', available: false, loaded: false, note: 'weights not present in local model store' },
  ],
})

export const ingest = (kind: AssetKind, sha256: string): IngestResponse => ({
  registration_id: `FX-REG-${sha256.slice(0, 8).toUpperCase()}`, sha256, kind, registered_at: new Date().toISOString(),
  analysis: kind === 'image' ? { embedding: 'VERIFIED', duplicate: 'VERIFIED', ood: 'SUSPICIOUS', trigger: 'NOT_EVALUATED', expected_label: undefined, observed_label: undefined, findings: [] } : undefined,
})

const hx = (seed: number) => Array.from({ length: 64 }, (_, i) => ((seed * 2654435761 + i * 40503) >>> 0) % 16).map((n) => n.toString(16)).join('')
const recs = ['input', 'model', 'configuration', 'output', 'passport'].map((kind, i) => ({ kind, i }))
export const provenance: ProvenanceChain = {
  records: recs.map(({ kind, i }) => ({
    sequence: i + 1, kind, subject: ['dataset:traffic-v3', 'model:yolo-traffic@1.4.0', 'config:audit-default', 'inf:cam-north-12', 'passport'][i],
    hash: hx(i + 7), previous_hash: i === 0 ? '0'.repeat(64) : i === 3 ? hx(99) : hx(i + 6), nonce: hx(i + 30).slice(0, 16),
    timestamp: new Date(Date.UTC(2026, 8, 29, 9, 12 + i * 3)).toISOString(),
  })),
  verified: false, message: '[fixture] record 4 previous_hash does not match record 3 hash',
}

const bins = Array.from({ length: 24 }, (_, i) => i / 23)
const g = (mu: number, s: number) => bins.map((x) => Math.exp(-((x - mu) ** 2) / (2 * s * s)))
export const shift: ShiftMetrics = {
  features: [
    { name: 'brightness', histogram: { bins, baseline: g(0.55, 0.14), current: g(0.3, 0.11) }, psi: 0.41, wasserstein: 0.23 },
    { name: 'contrast', histogram: { bins, baseline: g(0.5, 0.16), current: g(0.42, 0.13) }, psi: 0.12, wasserstein: 0.07 },
    { name: 'sharpness', histogram: { bins, baseline: g(0.6, 0.12), current: g(0.44, 0.17) }, psi: 0.27, wasserstein: 0.14 },
    { name: 'color', histogram: { bins, baseline: g(0.48, 0.15), current: g(0.47, 0.15) }, psi: 0.02, wasserstein: 0.01 },
  ],
  embedding_drift: 0.31, threshold: 0.12, note: '[fixture] synthetic distributions',
}

export const modelAudit: ModelAudit = {
  identity: { name: 'yolo-traffic@1.4.1', format: 'ONNX', sha256: hx(11), access: 'black-box' },
  blackbox: { golden_battery: { passed: 46, total: 50 }, trigger_sweep: { triggers_tested: 32, flagged: 3 } },
  whitebox: null,
  fingerprint: { digest: hx(12), matches_registry: false },
  behavioral: [
    { name: 'Stop-sign invariance under patch', passed: false, detail: 'flips to speed-limit with 14px patch' },
    { name: 'Brightness robustness ±30%', passed: true },
    { name: 'Horizontal flip consistency', passed: true },
  ],
  limitations: ['ONNX graph loaded without weights introspection — white-box assessment not performed.'],
}
