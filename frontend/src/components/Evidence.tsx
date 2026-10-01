import { useEffect, type ReactNode } from 'react'
import { useStore } from '../store'
import type { Finding } from '../api/types'
import { Copy, Drawer, Label, Meter, Tag, pct, tone } from './ui'

const isImg = (v: unknown) => typeof v === 'string' && (/^data:image\//.test(v) || /\.(png|jpe?g|webp|gif)(\?|$)/i.test(v))
const PAIRS: [RegExp, RegExp, string, string][] = [
  [/^expected/i, /^observed/i, 'Expected', 'Observed'],
  [/^baseline/i, /^current/i, 'Baseline', 'Current'],
  [/(^|_)a$|image_a|^left/i, /(^|_)b$|image_b|^right/i, 'Sample A', 'Sample B'],
  [/^reference/i, /^model|^predicted/i, 'Reference', 'Model'],
]

function Val({ v }: { v: unknown }) {
  if (isImg(v)) return <img src={v as string} alt="Evidence sample" className="w-full aspect-square object-cover rounded-[3px] bg-raised border border-line" />
  if (typeof v === 'number') return <span className="font-mono text-[18px] text-ink">{Number.isInteger(v) ? v : v.toFixed(3)}</span>
  if (typeof v === 'string') return <span className="font-mono text-[12px] text-ink break-all">{v}</span>
  return <pre className="font-mono text-[11px] text-ink-2 whitespace-pre-wrap">{JSON.stringify(v, null, 2)}</pre>
}

/** Renders whatever evidence the backend attached — comparisons when paired keys exist, measures otherwise. */
export function EvidenceBody({ ev }: { ev: unknown }) {
  if (ev == null) return <p className="text-[12.5px] text-mute">No machine evidence attached to this finding by the backend.</p>
  if (typeof ev !== 'object' || Array.isArray(ev)) return <Val v={ev} />
  const o = ev as Record<string, unknown>
  const used = new Set<string>(); const blocks: ReactNode[] = []
  for (const [ra, rb, la, lb] of PAIRS) {
    const a = Object.keys(o).find((k) => ra.test(k) && !used.has(k)); const b = Object.keys(o).find((k) => rb.test(k) && !used.has(k) && k !== a)
    if (a && b) {
      used.add(a); used.add(b)
      blocks.push(
        <div key={a} className="grid grid-cols-[1fr_auto_1fr] items-stretch gap-3 animate-rise">
          <div className="border border-line rounded-[3px] p-3 bg-ground/50"><Label className="mb-2">{la} · {a}</Label><Val v={o[a]} /></div>
          <div className="grid place-items-center font-mono text-[10px] text-faint">vs</div>
          <div className="border border-warn/30 rounded-[3px] p-3 bg-warn/[0.03]"><Label className="mb-2">{lb} · {b}</Label><Val v={o[b]} /></div>
        </div>,
      )
    }
  }
  const thr = Object.keys(o).find((k) => /threshold/i.test(k))
  const rest = Object.keys(o).filter((k) => !used.has(k) && k !== thr)
  return (
    <div className="space-y-3">
      {blocks}
      {rest.length > 0 && (
        <div className="grid grid-cols-2 gap-px bg-line border border-line rounded-[3px] overflow-hidden stagger">
          {rest.map((k) => {
            const v = o[k]; const frac = typeof v === 'number' && v >= 0 && v <= 1
            const t = thr && typeof o[thr] === 'number' && typeof v === 'number' ? (v > (o[thr] as number) ? 'warn' : 'ok') : 'info'
            return (
              <div key={k} className="bg-panel p-3">
                <Label className="mb-2">{k.replace(/_/g, ' ')}</Label>
                <Val v={v} />
                {frac && <div className="mt-2 relative"><Meter v={v as number} t={t} />{thr && typeof o[thr] === 'number' && <span className="absolute -top-1 h-[11px] w-px bg-ink/70" style={{ left: `${(o[thr] as number) * 100}%` }} title={`threshold ${o[thr]}`} />}</div>}
                {thr && typeof o[thr] === 'number' && typeof v === 'number' && <div className="mt-1.5 font-mono text-[10px] text-faint">threshold {String(o[thr])}</div>}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

export function Inspector({ f, onClose }: { f?: Finding; onClose: () => void }) {
  const { active, patchRun } = useStore()
  useEffect(() => { if (f && active && !active.reviewed) patchRun(active.id, { reviewed: true }) }, [f]) // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <Drawer open={!!f} onClose={onClose} title={f && <div className="flex items-center gap-2 min-w-0"><Label className="text-ink-2">Finding</Label><span className="font-mono text-[12px] truncate">{f.finding_id}</span><Copy v={f.finding_id} /></div>}>
      {f && (
        <div className="space-y-6">
          <section className="animate-rise">
            <div className="flex items-center gap-2"><Tag v={f.disposition} /><span className="font-mono text-[10px] text-faint">{f.module} · {f.asset}</span></div>
            <h2 className="mt-3 text-[19px] font-medium leading-snug tracking-[-0.01em]">{f.reason}</h2>
          </section>

          <section className="grid grid-cols-2 gap-px bg-line border border-line rounded-[4px] overflow-hidden animate-rise" style={{ animationDelay: '.05s' }}>
            <div className="bg-panel p-4">
              <Label>Severity · impact if true</Label>
              <div className="mt-2"><Tag v={f.severity} /></div>
              <p className="mt-2 text-[11.5px] text-faint">How much harm this would cause.</p>
            </div>
            <div className="bg-panel p-4">
              <Label>Confidence · likelihood it is true</Label>
              {f.confidence != null ? <><div className="mt-2 font-mono text-[18px]">{pct(f.confidence)}</div><div className="mt-2"><Meter v={f.confidence} t="info" /></div></> : <div className="mt-2 text-[12px] text-faint">Not reported by backend</div>}
            </div>
          </section>

          <section className="animate-rise" style={{ animationDelay: '.1s' }}>
            <div className="flex items-center gap-2 mb-3"><span className="size-1.5 bg-ink rounded-[1px]" /><Label className="text-ink-2">Evidence · measured</Label></div>
            <EvidenceBody ev={f.evidence} />
          </section>

          <section className="animate-rise" style={{ animationDelay: '.15s' }}>
            <div className="flex items-center gap-2 mb-3"><span className="size-1.5 border border-ink rounded-full" /><Label className="text-ink-2">Interpretation · inferred</Label></div>
            <div className="border-l-2 border-line-strong pl-4 space-y-3">
              <p className="font-serif text-[16px] leading-snug text-ink-2 italic">{f.reason}</p>
              <div><Label>Recommended action</Label><p className="mt-1 text-[13px] text-ink">{f.recommended_action}</p></div>
            </div>
          </section>

          <section className="animate-rise" style={{ animationDelay: '.2s' }}>
            <details className="group border border-line rounded-[3px]">
              <summary className="cursor-pointer list-none px-3 h-9 flex items-center justify-between font-mono text-[10.5px] uppercase tracking-[0.14em] text-mute hover:text-ink-2">Raw record<span className="transition-transform group-open:rotate-90">›</span></summary>
              <pre className="px-3 pb-3 font-mono text-[11px] text-ink-2 overflow-x-auto">{JSON.stringify(f, null, 2)}</pre>
            </details>
          </section>
          <p className="text-[11px] text-faint">Severity is not confidence. A critical finding at low confidence still needs a person to review it.</p>
        </div>
      )}
    </Drawer>
  )
}

export function FindingRow({ f, onOpen, i = 0 }: { f: Finding; onOpen: () => void; i?: number }) {
  const t = tone(f.severity)
  return (
    <button onClick={onOpen} className="group w-full grid grid-cols-[4px_96px_1fr_130px_112px_18px] items-center gap-4 pr-4 py-3.5 text-left border-b border-line last:border-0 hover:bg-raised/60 focus-visible:bg-raised cursor-pointer transition-colors" style={{ animationDelay: `${i * 0.04}s` }}>
      <span className={`self-stretch ${t === 'crit' ? 'bg-crit' : t === 'warn' ? 'bg-warn/70' : 'bg-transparent'}`} />
      <Tag v={f.severity} />
      <div className="min-w-0"><div className="text-[13px] truncate text-ink">{f.reason}</div><div className="font-mono text-[10px] text-faint mt-1 truncate">{f.asset} · {f.finding_id}</div></div>
      <div>{f.confidence != null ? <><div className="font-mono text-[11px] mb-1.5 text-ink-2">{pct(f.confidence)} <span className="text-faint">conf.</span></div><Meter v={f.confidence} t="info" /></> : <span className="font-mono text-[10px] text-faint">conf. n/r</span>}</div>
      <Tag v={f.disposition} />
      <span className="text-faint group-hover:text-ink group-hover:translate-x-0.5 transition">›</span>
    </button>
  )
}
