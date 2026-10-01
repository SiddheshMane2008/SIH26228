import { useEffect, useRef, useState, type ReactNode } from 'react'

export const tone = (v?: string) => {
  const s = (v ?? '').toUpperCase()
  if (['CRITICAL', 'QUARANTINE', 'FAILED', 'INVALID', 'OFFLINE'].includes(s)) return 'crit'
  if (['HIGH', 'MEDIUM', 'REVIEW', 'WARN'].includes(s)) return 'warn'
  if (['LOW', 'CLEAR', 'PASS', 'VALID', 'ONLINE', 'OK', 'ACCEPT'].includes(s)) return 'ok'
  if (['RUNNING', 'INFO'].includes(s)) return 'info'
  return 'na'
}
const TXT: Record<string, string> = { ok: 'text-ok', warn: 'text-warn', crit: 'text-crit', info: 'text-info', na: 'text-na' }
const BG: Record<string, string> = { ok: 'bg-ok', warn: 'bg-warn', crit: 'bg-crit', info: 'bg-info', na: 'bg-na' }
const BD: Record<string, string> = { ok: 'border-ok/40', warn: 'border-warn/40', crit: 'border-crit/40', info: 'border-info/40', na: 'border-na/40' }

export function Dot({ t, pulse }: { t: string; pulse?: boolean }) {
  return <span className={`inline-block size-1.5 rounded-full ${BG[t]} ${pulse ? 'animate-breathe' : ''}`} />
}

export function Tag({ v, t }: { v: string; t?: string }) {
  const k = t ?? tone(v)
  return <span className={`inline-flex items-center gap-1.5 border ${BD[k]} ${TXT[k]} rounded-[3px] px-1.5 py-[3px] font-mono text-[10px] uppercase tracking-[0.12em] leading-none`}><Dot t={k} />{v}</span>
}

export function Label({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`font-mono text-[10px] uppercase tracking-[0.16em] text-mute ${className}`}>{children}</div>
}

export function Panel({ title, meta, children, className = '', pad = true }: { title?: ReactNode; meta?: ReactNode; children: ReactNode; className?: string; pad?: boolean }) {
  return (
    <section className={`sheen lift border border-line bg-panel/90 backdrop-blur-sm rounded-[4px] animate-rise shadow-[0_1px_0_rgb(255_255_255/0.03)_inset,0_20px_40px_-24px_rgb(0_0_0/0.8)] ${className}`}>
      {title && (
        <header className="flex items-center justify-between gap-4 border-b border-line px-4 h-10">
          <Label className="text-ink-2">{title}</Label>
          {meta && <div className="font-mono text-[10px] text-faint">{meta}</div>}
        </header>
      )}
      <div className={pad ? 'p-4' : 'stagger'}>{children}</div>
    </section>
  )
}

export function PageHead({ index, title, lede, right }: { index: string; title: string; lede: string; right?: ReactNode }) {
  return (
    <div className="relative flex items-end justify-between gap-8 pb-6 mb-6 border-b border-line animate-rise"><span className="absolute -bottom-px left-0 h-px w-24 bg-ink/60" />
      <div className="max-w-2xl">
        <Label className="mb-3 flex items-center gap-2"><span className="h-px w-6 bg-line-strong" />§ {index}</Label>
        <h1 className="text-[28px] font-semibold tracking-[-0.02em] leading-none">{title}</h1>
        <p className="mt-3 font-serif text-[17px] leading-snug text-ink-2 italic">{lede}</p>
      </div>
      {right}
    </div>
  )
}

export function Btn({ children, onClick, disabled, primary, className = '' }: { children: ReactNode; onClick?: () => void; disabled?: boolean; primary?: boolean; className?: string }) {
  return (
    <button onClick={onClick} disabled={disabled}
      className={`h-8 px-3 rounded-[3px] font-mono text-[11px] uppercase tracking-[0.12em] transition-colors disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer ${primary ? 'bg-ink text-ground hover:bg-white' : 'border border-line-strong text-ink-2 hover:text-ink hover:border-ink/40'} ${className}`}>
      {children}
    </button>
  )
}

export function Empty({ title, hint, action }: { title: string; hint: string; action?: ReactNode }) {
  return (
    <div className="hatch border border-dashed border-line-strong rounded-[4px] px-8 py-14 text-center">
      <div className="font-serif text-xl italic text-ink-2">{title}</div>
      <p className="mt-2 text-[13px] text-mute max-w-md mx-auto">{hint}</p>
      {action && <div className="mt-5 flex justify-center">{action}</div>}
    </div>
  )
}

export function Stat({ label, value, sub, t }: { label: string; value: ReactNode; sub?: ReactNode; t?: string }) {
  return (
    <div className="px-4 py-3.5">
      <Label>{label}</Label>
      <div className={`mt-2 font-mono text-[22px] leading-none ${t ? TXT[t] : 'text-ink'}`}>{typeof value === 'number' ? <Count to={value} /> : value}</div>
      {sub && <div className="mt-1.5 text-[11px] text-faint">{sub}</div>}
    </div>
  )
}

export function Meter({ v, t = 'info' }: { v: number; t?: string }) {
  return <div className="h-[3px] w-full bg-line rounded-full overflow-hidden"><div className={`h-full ${BG[t]} transition-[width] duration-700`} style={{ width: `${Math.max(0, Math.min(1, v)) * 100}%` }} /></div>
}

export const pct = (n?: number) => (n == null ? '—' : `${(n * 100).toFixed(1)}%`)
export const short = (h?: string, n = 10) => (!h ? '—' : h.length > n * 2 ? `${h.slice(0, n)}…${h.slice(-n)}` : h)
export const time = (iso?: string) => (iso ? new Date(iso).toLocaleTimeString([], { hour12: false }) : '—')

export function Count({ to, ms = 700 }: { to: number; ms?: number }) {
  const [v, setV] = useState(0); const from = useRef(0)
  useEffect(() => {
    if (matchMedia('(prefers-reduced-motion: reduce)').matches) { setV(to); from.current = to; return }
    const a = from.current, t0 = performance.now(); let id = 0
    const f = (t: number) => { const k = Math.min(1, (t - t0) / ms), e = 1 - (1 - k) ** 3; setV(a + (to - a) * e); if (k < 1) id = requestAnimationFrame(f); else from.current = to }
    id = requestAnimationFrame(f); return () => cancelAnimationFrame(id)
  }, [to, ms])
  return <>{Number.isInteger(to) ? Math.round(v) : v.toFixed(1)}</>
}

const STROKE: Record<string, string> = { ok: '#62b58f', warn: '#d8a547', crit: '#e05a50', info: '#86a9c8', na: '#6b7078' }
export function Gauge({ v, t = 'info', size = 132, children }: { v: number; t?: string; size?: number; children?: ReactNode }) {
  const [shown, setShown] = useState(0)
  useEffect(() => { const id = requestAnimationFrame(() => setShown(v)); return () => cancelAnimationFrame(id) }, [v])
  const r = size / 2 - 8, c = 2 * Math.PI * r, ticks = Array.from({ length: 48 })
  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg viewBox={`0 0 ${size} ${size}`} className="absolute inset-0 -rotate-90">
        {ticks.map((_, i) => { const a = (i / 48) * Math.PI * 2, R = size / 2; return <line key={i} x1={R + Math.cos(a) * (r + 5)} y1={R + Math.sin(a) * (r + 5)} x2={R + Math.cos(a) * (r + (i % 4 ? 6.5 : 8))} y2={R + Math.sin(a) * (r + (i % 4 ? 6.5 : 8))} stroke="rgb(255 255 255 / .12)" /> })}
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgb(255 255 255 / .06)" strokeWidth="3" />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={STROKE[t]} strokeWidth="3" strokeLinecap="round" strokeDasharray={c} strokeDashoffset={c * (1 - shown)} style={{ transition: 'stroke-dashoffset 1.1s cubic-bezier(.2,.7,.2,1)', filter: `drop-shadow(0 0 6px ${STROKE[t]}55)` }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">{children}</div>
    </div>
  )
}

// ── Extended primitives ──────────────────────────────────────────────
import Icon from './icons'
import { NotImplemented } from '../api/client'

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: readonly (readonly [T, string])[]; value: T; onChange: (v: T) => void }) {
  return (
    <div role="tablist" className="inline-flex gap-0.5 p-0.5 border border-line rounded-[4px] bg-ground/60">
      {tabs.map(([k, l]) => (
        <button key={k} role="tab" aria-selected={value === k} onClick={() => onChange(k)}
          className={`relative h-7 px-3 rounded-[3px] font-mono text-[10.5px] uppercase tracking-[0.12em] transition-colors cursor-pointer ${value === k ? 'bg-raised text-ink shadow-[inset_0_0_0_1px_var(--color-line-strong)]' : 'text-mute hover:text-ink-2'}`}>{l}</button>
      ))}
    </div>
  )
}

export function Copy({ v, className = '' }: { v?: string; className?: string }) {
  const [done, setDone] = useState(false)
  if (!v) return null
  return (
    <button aria-label="Copy to clipboard" onClick={async () => { await navigator.clipboard?.writeText(v).catch(() => {}); setDone(true); setTimeout(() => setDone(false), 1400) }}
      className={`inline-grid place-items-center size-5 rounded-[3px] transition-colors cursor-pointer ${done ? 'text-ok' : 'text-faint hover:text-ink'} ${className}`}>
      <Icon n={done ? 'check' : 'copy'} className="size-3" />
    </button>
  )
}

export function Hash({ v, n = 10, className = '' }: { v?: string; n?: number; className?: string }) {
  return <span className={`inline-flex items-center gap-1 font-mono text-[11px] ${className}`} title={v}>{short(v, n)}<Copy v={v} /></span>
}

export function KV({ k, v, mono = true }: { k: string; v: ReactNode; mono?: boolean }) {
  return <div className="flex items-baseline justify-between gap-4 py-2 border-b border-line last:border-0"><dt className="text-[12px] text-mute shrink-0">{k}</dt><dd className={`text-right min-w-0 truncate ${mono ? 'font-mono text-[11.5px]' : 'text-[13px]'} text-ink-2`}>{v ?? <span className="text-faint">—</span>}</dd></div>
}

/** Four epistemic states that must never be confused. */
export function Assess({ v }: { v?: string }) {
  const s = (v ?? 'NOT_EVALUATED').toUpperCase()
  const map: Record<string, [string, string]> = { VERIFIED: ['Verified', 'ok'], SUSPICIOUS: ['Suspicious', 'warn'], UNAVAILABLE: ['Unavailable', 'na'], NOT_EVALUATED: ['Not evaluated', 'na'] }
  const [l, t] = map[s] ?? [s, 'na']
  return <span className={s === 'NOT_EVALUATED' ? 'opacity-70' : ''}><Tag v={l} t={t} /></span>
}

export function Loading({ label }: { label: string }) {
  return (
    <div className="border border-line rounded-[4px] bg-panel/70 px-6 py-10" role="status" aria-live="polite">
      <div className="flex items-center gap-3"><Dot t="info" pulse /><span className="font-mono text-[11px] uppercase tracking-[0.14em] text-info">{label}</span></div>
      <div className="relative mt-5 h-px bg-line overflow-hidden"><div className="absolute inset-y-0 w-1/3 bg-info/70 animate-scan" /></div>
      <div className="mt-6 space-y-2.5">{[88, 72, 80].map((w, i) => <div key={i} className="h-2.5 rounded-sm bg-raised animate-breathe" style={{ width: `${w}%`, animationDelay: `${i * 0.2}s` }} />)}</div>
    </div>
  )
}

export function Failure({ what, error, affected, next, retry }: { what: string; error: unknown; affected?: string; next?: string; retry?: () => void }) {
  const ni = error instanceof NotImplemented
  return (
    <div role="alert" className={`animate-rise border rounded-[4px] px-6 py-5 ${ni ? 'border-line-strong bg-panel hatch' : 'border-crit/35 bg-crit/[0.04]'}`}>
      <div className={`flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.16em] ${ni ? 'text-ink-2' : 'text-crit'}`}><Icon n="alert" className="size-3.5" />{ni ? `${what} · unavailable` : `${what} · failed`}</div>
      <dl className="mt-4 grid grid-cols-[90px_1fr] gap-y-2 text-[12.5px]">
        <dt className="text-mute">Reason</dt><dd className="font-mono text-[11.5px] text-ink-2 break-all">{ni ? `Backend does not expose ${(error as NotImplemented).path} yet.` : (error as Error)?.message ?? String(error)}</dd>
        {affected && <><dt className="text-mute">Affected</dt><dd className="text-ink-2">{affected}</dd></>}
        <dt className="text-mute">Next</dt><dd className="text-ink-2">{ni ? 'Implement the endpoint using the contract in src/api/types.ts. Nothing is shown in its place.' : next ?? 'Check the backend log, then retry.'}</dd>
      </dl>
      {retry && !ni && <div className="mt-4"><Btn onClick={retry}>Retry</Btn></div>}
    </div>
  )
}

export function useLoad<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [s, set] = useState<{ data?: T; error?: unknown; loading: boolean }>({ loading: true })
  const seq = useRef(0)
  const run = () => { const n = ++seq.current; set({ loading: true }); fn().then((data) => { if (n === seq.current) set({ data, loading: false }) }, (error) => { if (n === seq.current) set({ error, loading: false }) }) }
  useEffect(() => { run(); return () => { seq.current++ } }, deps) // eslint-disable-line react-hooks/exhaustive-deps
  return { ...s, reload: run }
}

export function Drawer({ open, onClose, title, children }: { open: boolean; onClose: () => void; title: ReactNode; children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null)
  const close = useRef(onClose); close.current = onClose
  useEffect(() => {
    if (!open) return
    const prev = document.activeElement as HTMLElement | null
    ref.current?.focus()
    const k = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close.current()
      if (e.key === 'Tab' && ref.current) {
        const f = [...ref.current.querySelectorAll<HTMLElement>('a[href],button:not([disabled]),input:not([disabled]),select,textarea,[tabindex]:not([tabindex="-1"])')]
        if (!f.length) { e.preventDefault(); return }
        const a = document.activeElement
        if (e.shiftKey && (a === f[0] || a === ref.current)) { e.preventDefault(); f[f.length - 1].focus() }
        else if (!e.shiftKey && a === f[f.length - 1]) { e.preventDefault(); f[0].focus() }
        else if (!ref.current.contains(a)) { e.preventDefault(); f[0].focus() }
      }
    }
    addEventListener('keydown', k); return () => { removeEventListener('keydown', k); prev?.focus() }
  }, [open])
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-black/55 animate-fade" onClick={onClose} />
      <div ref={ref} tabIndex={-1} role="dialog" aria-modal="true" className="relative w-[min(640px,92vw)] h-full bg-panel border-l border-line-strong overflow-y-auto outline-none drawer-in">
        <header className="sticky top-0 z-10 flex items-center justify-between h-12 px-5 border-b border-line bg-panel/95 backdrop-blur-sm">
          <div className="min-w-0">{title}</div>
          <button onClick={onClose} aria-label="Close" className="size-7 grid place-items-center rounded-[3px] text-mute hover:text-ink hover:bg-raised cursor-pointer"><Icon n="close" /></button>
        </header>
        <div className="p-5">{children}</div>
      </div>
    </div>
  )
}
