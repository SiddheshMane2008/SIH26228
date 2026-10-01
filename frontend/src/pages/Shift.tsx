import { useState } from 'react'
import { api } from '../api/client'
import type { ShiftFeature } from '../api/types'
import { Failure, Label, Loading, PageHead, Panel, Tabs, Tag, useLoad } from '../components/ui'
import { useStore } from '../store'
import { ModuleFindings } from './Findings'

const psiTone = (p?: number) => (p == null ? 'na' : p >= 0.25 ? 'warn' : p >= 0.1 ? 'info' : 'ok')
const psiWord = (p?: number) => (p == null ? 'Not computed' : p >= 0.25 ? 'Significant shift' : p >= 0.1 ? 'Moderate shift' : 'Stable')

function Chart({ f, view }: { f: ShiftFeature; view: 'both' | 'baseline' | 'current' }) {
  const h = f.histogram
  if (!h) return <div className="h-[150px] grid place-items-center text-[12px] text-faint">Histogram not provided</div>
  const W = 420, H = 150, max = Math.max(...h.baseline, ...h.current) || 1
  const pts = (arr: number[]) => arr.map((v, i) => `${(arr.length > 1 ? i / (arr.length - 1) : 0) * W},${H - (v / max) * (H - 12)}`).join(' ')
  const area = (arr: number[]) => `M0,${H} L${pts(arr).split(' ').join(' L')} L${W},${H} Z`
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-[150px]" role="img" aria-label={`${f.name} baseline vs current distribution`}>
      {[0.25, 0.5, 0.75].map((y) => <line key={y} x1="0" x2={W} y1={H * y} y2={H * y} stroke="rgb(255 255 255 / .05)" />)}
      {view !== 'current' && <g className="grow"><path d={area(h.baseline)} fill="rgb(134 169 200 / .14)" /><polyline points={pts(h.baseline)} fill="none" stroke="#86a9c8" strokeWidth="1.3" /></g>}
      {view !== 'baseline' && <g className="grow" style={{ animationDelay: '.15s' }}><path d={area(h.current)} fill="rgb(216 165 71 / .10)" /><polyline points={pts(h.current)} fill="none" stroke="#d8a547" strokeWidth="1.3" strokeDasharray="4 3" /></g>}
    </svg>
  )
}

export default function Shift() {
  const { source } = useStore()
  const [view, setView] = useState<'both' | 'baseline' | 'current'>('both')
  const q = useLoad(() => api.shift(), [source])
  const d = q.data
  return (
    <>
      <PageHead index="05" title="Shift Diagnostician" lede="Measures how far live imagery has drifted from the training distribution. Drift shows that conditions changed. It does not prove anyone manipulated the data."
        right={<Tabs tabs={[['both', 'Baseline vs current'], ['baseline', 'Baseline'], ['current', 'Current']] as const} value={view} onChange={setView} />} />
      {q.loading ? <Loading label="Computing embeddings and distributions…" /> : q.error ? <Failure what="Shift metrics" error={q.error} affected="Distribution charts. Passport shift findings are shown below." retry={q.reload} /> : d && (
        <>
          <div className="grid grid-cols-[1fr_2fr] gap-5 mb-5 max-[1100px]:grid-cols-1">
            <Panel title="Embedding drift" meta={d.threshold != null ? `threshold ${d.threshold}` : undefined}>
              {d.embedding_drift == null ? <p className="text-[12.5px] text-mute">Not computed.</p> : <>
                <div className={`font-mono text-[40px] leading-none ${d.threshold != null && d.embedding_drift > d.threshold ? 'text-warn' : 'text-ok'}`}>{d.embedding_drift.toFixed(3)}</div>
                {d.threshold != null && <div className="mt-4 relative h-[3px] bg-line rounded-full"><div className="absolute inset-y-0 left-0 bg-warn rounded-full transition-[width] duration-1000" style={{ width: `${Math.min(1, d.embedding_drift / (d.threshold * 3)) * 100}%` }} /><span className="absolute -top-1.5 h-[15px] w-px bg-ink" style={{ left: '33.3%' }} /></div>}
              </>}
            </Panel>
            <Panel title="Reading this page">
              <div className="grid grid-cols-2 gap-6 text-[12.5px]">
                <div><Tag v="Observed shift" t="warn" /><p className="mt-2 text-ink-2">A statistical distance between baseline and current data. It is measured, and says nothing about intent.</p></div>
                <div><Tag v="Suspicious manipulation" t="crit" /><p className="mt-2 text-ink-2">Only raised by the Sentinel or Provenance modules, with their own evidence. Never inferred from drift alone.</p></div>
              </div>
              <div className="mt-4 flex items-center gap-5 font-mono text-[10px] text-mute"><span className="flex items-center gap-2"><span className="w-4 h-px bg-info" />baseline</span><span className="flex items-center gap-2"><span className="w-4 border-t border-dashed border-warn" />current</span></div>
            </Panel>
          </div>
          <div className="grid grid-cols-2 gap-5 max-[1100px]:grid-cols-1">
            {(d.features ?? []).map((f) => (
              <Panel key={f.name} title={f.name} meta={<Tag v={psiWord(f.psi)} t={psiTone(f.psi)} />}>
                <Chart key={view} f={f} view={view} />
                <div className="mt-3 grid grid-cols-2 gap-4 border-t border-line pt-3">
                  <div><Label>PSI</Label><div className="mt-1 font-mono text-[14px]">{f.psi?.toFixed(3) ?? '—'}</div></div>
                  <div><Label>Wasserstein</Label><div className="mt-1 font-mono text-[14px]">{f.wasserstein?.toFixed(3) ?? '—'}</div></div>
                </div>
              </Panel>
            ))}
          </div>
          {d.note && <p className="mt-3 font-mono text-[10.5px] text-faint">{d.note}</p>}
        </>
      )}
      <div className="mt-8"><Label className="mb-3">Passport findings attributed to Shift Diagnostician</Label><ModuleFindings mod="shift" /></div>
    </>
  )
}
