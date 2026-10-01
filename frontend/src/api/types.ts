// VisionGuard backend contract — mirrors the FastAPI endpoints used by the existing dashboard (app.js).
// Optional fields are tolerated but never required; the UI only renders what the backend returns.

export interface StatusResponse { active_embedder: string; embedder_dimension: number; [k: string]: unknown }
export interface EmbedderSelectResponse { selected_embedder: string; dimension: number }

export interface Finding {
  finding_id: string
  module: string
  asset: string
  reason: string
  severity: string // CRITICAL | HIGH | MEDIUM | LOW
  disposition: string // QUARANTINE | REVIEW | CLEAR …
  recommended_action: string
  confidence?: number
  evidence?: unknown
  [k: string]: unknown
}

export interface Passport {
  passport_id: string
  overall_disposition: string
  overall_confidence: number
  findings_summary?: { total: number; [k: string]: unknown }
  top_findings: Finding[]
  executive_summary: string
  signer_public_key_hex: string
  passport_digest: string
  signature_hex: string
  [k: string]: unknown
}

export interface ScenarioResponse { passport: Passport; report_url?: string }
export interface VerifyResponse { is_valid: boolean; message: string }

export interface BlastResponse {
  trace: { description: string; affected_datasets: string[]; affected_models: string[]; affected_inference_records: string[]; severity: string; [k: string]: unknown }
  mermaid: string
}

export interface RedTeamScenario { attack_name: string; attack_family: string; sample_count: number; detected_count: number; precision: number; recall: number; f1_score: number }
export interface RedTeamResponse { macro_precision: number; macro_recall: number; macro_f1: number; scenarios_evaluated: RedTeamScenario[] }

export interface AuditRun {
  id: string
  scenario: number
  label: string
  startedAt: string
  completedAt?: string
  state: 'running' | 'complete' | 'failed'
  error?: string
  passport?: Passport
  reportUrl?: string
  source: 'backend' | 'fixture'
  blast?: BlastResponse
  verify?: VerifyResponse | null
  reviewed?: boolean
}

export interface Asset {
  key: string; name: string; size: number; format: string; kind: AssetKind; addedAt: string
  stage: 'validating' | 'hashing' | 'registering' | 'registered' | 'unregistered' | 'rejected'
  sha256?: string; registration?: IngestResponse; error?: string; preview?: string
}

// ── Extended contracts (proposed). The console calls these endpoints; a 404/405 is surfaced as
// "endpoint not implemented" rather than filled with invented data.

export interface EmbedderInfo { name: string; dimension?: number; available: boolean; loaded: boolean; note?: string }
export interface EmbedderList { embedders: EmbedderInfo[] }

export type AssetKind = 'image' | 'dataset' | 'model' | 'inference'
export interface IngestResponse {
  registration_id: string; sha256: string; kind: AssetKind; registered_at: string
  analysis?: {
    embedding?: string; duplicate?: string; ood?: string; trigger?: string // VERIFIED | SUSPICIOUS | UNAVAILABLE | NOT_EVALUATED
    expected_label?: string; observed_label?: string
    findings?: Finding[]
  }
}

export interface ProvenanceRecord {
  sequence: number; kind: string; subject: string; hash: string; previous_hash: string
  nonce?: string; timestamp: string; signature_hex?: string
}
export interface ProvenanceChain { records: ProvenanceRecord[]; verified?: boolean; message?: string }

export interface Histogram { bins: number[]; baseline: number[]; current: number[] }
export interface ShiftFeature { name: string; histogram?: Histogram; psi?: number; wasserstein?: number }
export interface ShiftMetrics { features: ShiftFeature[]; embedding_drift?: number; threshold?: number; note?: string }

export interface ModelAudit {
  identity: { name: string; format?: string; sha256?: string; access: 'black-box' | 'white-box' | 'unknown' }
  blackbox?: { golden_battery?: { passed: number; total: number }; trigger_sweep?: { triggers_tested: number; flagged: number } }
  whitebox?: { parameter_stats?: Record<string, number>; activation_stats?: Record<string, number> } | null
  fingerprint?: { digest: string; matches_registry?: boolean }
  behavioral?: { name: string; passed: boolean; detail?: string }[]
  limitations?: string[]
}
