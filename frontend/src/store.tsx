import React, { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'
import { api, BASE, setSource, type Source } from './api/client'
import { scenarioById } from './api/scenarios'
import type { Asset, AuditRun, StatusResponse } from './api/types'

type Link = 'probing' | 'online' | 'offline'
interface Store {
  link: Link; linkError?: string; source: Source; status?: StatusResponse
  runs: AuditRun[]; active?: AuditRun; setActiveId: (id: string) => void
  run: (scenario: number) => Promise<void>; auditAssets: (ids: string[]) => Promise<void>
  toasts: Toast[]; toast: (t: Omit<Toast, 'id'>) => void; dismiss: (id: number) => void
  patchRun: (id: string, p: Partial<AuditRun>) => void
  assets: Asset[]; setAssets: React.Dispatch<React.SetStateAction<Asset[]>>; booted: boolean
  reprobe: () => void; refreshStatus: () => Promise<void>
}
export interface Toast { id: number; tone: string; title: string; body?: string }
// Kept on globalThis so hot-module reloads reuse one context instead of orphaning consumers.
const g = globalThis as unknown as { __vgStore?: React.Context<Store | null> }
const Ctx = (g.__vgStore ??= createContext<Store | null>(null))
export const useStore = () => {
  const s = useContext(Ctx)
  if (!s) throw new Error('useStore must be used inside <StoreProvider>')
  return s
}

export function StoreProvider({ children }: { children: ReactNode }) {
  const [link, setLink] = useState<Link>('probing')
  const [linkError, setLinkError] = useState<string>()
  const [source, setSrc] = useState<Source>('backend')
  const [status, setStatus] = useState<StatusResponse>()
  const [runs, setRuns] = useState<AuditRun[]>([])
  const [activeId, setActiveId] = useState<string>()
  const [assets, setAssets] = useState<Asset[]>([])
  const [booted, setBooted] = useState(false)
  const patchRun = useCallback((id: string, p: Partial<AuditRun>) => setRuns((x) => x.map((y) => (y.id === id ? { ...y, ...p } : y))), [])

  const reprobe = useCallback(async () => {
    setLink('probing')
    try {
      const s = await api.probe()
      setSource('backend'); setSrc('backend'); setStatus(s); setLink('online'); setLinkError(undefined)
    } catch (e) {
      setLinkError((e as Error).message); setLink('offline'); setStatus(undefined)
      // Fixtures only when no explicit backend is configured.
      if (!BASE) { setSource('fixture'); setSrc('fixture'); setStatus(await api.status()) }
    } finally { setBooted(true) }
  }, [])
  useEffect(() => { reprobe() }, [reprobe])

  const refreshStatus = useCallback(async () => { setStatus({ ...(await api.status()) }) }, [])

  const [toasts, setToasts] = useState<Toast[]>([])
  const dismiss = useCallback((id: number) => setToasts((x) => x.filter((t) => t.id !== id)), [])
  const toast = useCallback((t: Omit<Toast, 'id'>) => { const id = Date.now() + Math.random(); setToasts((x) => [...x.slice(-3), { ...t, id }]); setTimeout(() => dismiss(id), 5200) }, [dismiss])

  const exec = useCallback(async (scenario: number, label: string, fn: () => Promise<{ passport: AuditRun['passport']; report_url?: string }>) => {
    const id = `AUD-${new Date().toISOString().slice(2, 10).replace(/-/g, '')}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`
    const r: AuditRun = { id, scenario, label, startedAt: new Date().toISOString(), state: 'running', source }
    setRuns((x) => [r, ...x]); setActiveId(id)
    try {
      const res = await fn()
      if (!res?.passport) throw new Error('Backend response contained no passport')
      setRuns((x) => x.map((y) => (y.id === id ? { ...y, state: 'complete', completedAt: new Date().toISOString(), passport: res.passport, reportUrl: res.report_url } : y)))
      const d = res.passport.overall_disposition
      toast({ tone: d === 'QUARANTINE' ? 'crit' : d === 'REVIEW' ? 'warn' : 'ok', title: `Audit complete · ${d}`, body: `${label} · ${res.passport.top_findings?.length ?? 0} finding(s) · passport issued` })
    } catch (e) {
      setRuns((x) => x.map((y) => (y.id === id ? { ...y, state: 'failed', completedAt: new Date().toISOString(), error: (e as Error).message } : y)))
      toast({ tone: 'crit', title: 'Audit failed', body: (e as Error).message })
    }
  }, [source, toast])
  const run = useCallback((scenario: number) => exec(scenario, scenarioById(scenario)?.label ?? `Scenario ${scenario}`, () => api.runScenario(scenario)), [exec])
  const auditAssets = useCallback((ids: string[]) => exec(0, `Ingested assets (${ids.length})`, () => api.auditAssets(ids)), [exec])

  const active = runs.find((r) => r.id === activeId)
  return <Ctx.Provider value={{ auditAssets, toasts, toast, dismiss, patchRun, assets, setAssets, booted, link, linkError, source, status, runs, active, setActiveId, run, reprobe, refreshStatus }}>{children}</Ctx.Provider>
}
