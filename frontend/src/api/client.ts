import * as fx from './fixtures'
import type { EmbedderList, IngestResponse, ModelAudit, ProvenanceChain, ShiftMetrics, AssetKind, BlastResponse, EmbedderSelectResponse, RedTeamResponse, ScenarioResponse, StatusResponse, VerifyResponse, Passport } from './types'

// Same-origin by default (FastAPI serves the console). Override with VITE_VISIONGUARD_API.
export const BASE = ((import.meta as any).env?.VITE_VISIONGUARD_API as string | undefined) ?? ''

export type Source = 'backend' | 'fixture'
let source: Source = 'backend'
export const setSource = (s: Source) => { source = s }
export const getSource = () => source

/** Thrown when the backend has no such route — the UI renders a contract-missing state. */
export class NotImplemented extends Error { constructor(public path: string) { super(`Endpoint not implemented on backend: ${path}`) } }

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(`${BASE}${path}`, init)
  if (r.status === 404 || r.status === 405 || r.status === 501) throw new NotImplemented(path)
  if (!r.ok) throw new Error(`${r.status} ${r.statusText} · ${init?.method ?? 'GET'} ${path}`)
  const ct = r.headers.get('content-type') ?? ''
  if (!ct.includes('json')) throw new Error(`Non-JSON response from ${path} — backend not reachable at this origin`)
  return r.json()
}

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms))

export const api = {
  /** Probe only — always hits the real backend. */
  probe: () => call<StatusResponse>('/api/status'),
  status: async () => (source === 'fixture' ? fx.status : call<StatusResponse>('/api/status')),
  selectEmbedder: async (name: string) =>
    source === 'fixture'
      ? (await delay(300), fx.selectEmbedder(name))
      : call<EmbedderSelectResponse>(`/api/embedder/select?name=${encodeURIComponent(name)}`, { method: 'POST' }),
  runScenario: async (id: number) =>
    source === 'fixture' ? (await delay(1400), fx.scenario(id)) : call<ScenarioResponse>(`/api/demo/run-scenario/${id}`),
  verifyPassport: async (p: Passport): Promise<VerifyResponse | null> =>
    source === 'fixture'
      ? null // fixtures carry no signature; verification cannot honestly succeed
      : call<VerifyResponse>('/api/passport/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(p) }),
  blastRadius: async (rootId: string) =>
    source === 'fixture' ? (await delay(400), fx.blast(rootId)) : call<BlastResponse>(`/api/blast-radius?root_id=${encodeURIComponent(rootId)}`),
  redteam: async (seed = 42) =>
    source === 'fixture' ? (await delay(900), fx.redteam) : call<RedTeamResponse>(`/api/redteam/benchmark?seed=${seed}`),
  /** Proposed: audit registered assets. Returns the same shape as a scenario run. */
  auditAssets: async (registration_ids: string[]) =>
    source === 'fixture' ? (await delay(1600), fx.scenario(2)) : call<ScenarioResponse>('/api/audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ registration_ids }) }),
  embedders: async () => (source === 'fixture' ? fx.embedders() : call<EmbedderList>('/api/embedders')),
  ingest: async (file: File, kind: AssetKind, sha256: string) => {
    if (source === 'fixture') return (await delay(700), fx.ingest(kind, sha256))
    const fd = new FormData(); fd.append('file', file); fd.append('kind', kind); fd.append('sha256', sha256)
    return call<IngestResponse>('/api/ingest', { method: 'POST', body: fd })
  },
  provenance: async (auditId?: string) =>
    source === 'fixture' ? (await delay(500), fx.provenance) : call<ProvenanceChain>(`/api/provenance/chain${auditId ? `?audit_id=${encodeURIComponent(auditId)}` : ''}`),
  shift: async () => (source === 'fixture' ? (await delay(600), fx.shift) : call<ShiftMetrics>('/api/shift/metrics')),
  modelAudit: async () => (source === 'fixture' ? (await delay(600), fx.modelAudit) : call<ModelAudit>('/api/model/audit')),
}

export async function sha256Hex(buf: ArrayBuffer) {
  const h = await crypto.subtle.digest('SHA-256', buf)
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, '0')).join('')
}
