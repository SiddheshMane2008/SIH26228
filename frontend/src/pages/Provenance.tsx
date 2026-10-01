import { useEffect, useRef, useState } from 'react'
import { api } from '../api/client'
import type { ProvenanceRecord } from '../api/types'
import Icon from '../components/icons'
import { Btn, Failure, Hash, KV, Label, Loading, PageHead, Panel, Tag, time, useLoad } from '../components/ui'
import { useStore } from '../store'
import { ModuleFindings } from './Findings'

/** Link integrity is checked here, client-side, from the records the backend returned. */
const linkOk = (r: ProvenanceRecord[], i: number) => (i === 0 ? true : r[i].previous_hash === r[i - 1].hash)

export default function Provenance() {
  const { active, source } = useStore()
  const q = useLoad(() => api.provenance(active?.id), [active?.id, source])
  const recs = q.data?.records ?? []
  const [step, setStep] = useState(-1)
  const [sel, setSel] = useState(0)
  const firstBreak = recs.findIndex((_, i) => !linkOk(recs, i))
  const timer = useRef<ReturnType<typeof setInterval>>(undefined)
  const walk = () => { clearInterval(timer.current); setStep(-1); let i = 0; timer.current = setInterval(() => { setStep(i); if (i >= recs.length - 1 || (firstBreak !== -1 && i >= firstBreak)) clearInterval(timer.current); i++ }, 380) }
  useEffect(() => { setSel(0); if (recs.length) walk(); return () => clearInterval(timer.current) }, [q.data]) // eslint-disable-line react-hooks/exhaustive-deps
  const r = recs[sel]
  return (
    <>
      <PageHead index="04" title="Provenance chain" lede="Every artefact in the path from input to output is hash-linked to the one before it. We walk the chain and check each link against its predecessor."
        right={recs.length > 0 && <Btn onClick={walk}>Re-walk chain</Btn>} />
      {q.loading ? <Loading label="Checking provenance…" /> : q.error ? <Failure what="Provenance chain" error={q.error} affected="Chain visualisation. Provenance findings in the passport are shown below." retry={q.reload} /> : (
        <>
          <Panel title="Chain" meta={recs.length === 0 ? 'no records returned' : firstBreak === -1 ? `${recs.length} records · all links intact` : `broken at sequence ${recs[firstBreak].sequence}`} pad={false}>
            <div className="px-5 py-7 overflow-x-auto">
              <div className="flex items-center min-w-max">
                {recs.map((x, i) => {
                  const reached = step >= i, ok = linkOk(recs, i), broken = reached && !ok
                  return (
                    <div key={x.sequence} className="flex items-center">
                      {i > 0 && (
                        <div className="relative w-16 h-8 grid place-items-center">
                          <div className={`absolute inset-x-0 top-1/2 h-px transition-colors duration-500 ${broken ? 'bg-crit' : reached ? 'bg-ok/60' : 'bg-line-strong'}`} style={broken ? { backgroundImage: 'repeating-linear-gradient(90deg, var(--color-crit) 0 4px, transparent 4px 8px)', backgroundColor: 'transparent' } : undefined} />
                          {broken && <span className="relative z-[1] px-1 bg-panel font-mono text-[9px] tracking-[0.14em] text-crit animate-fade">BREAK</span>}
                        </div>
                      )}
                      <button onClick={() => setSel(i)} className={`relative w-[168px] text-left rounded-[4px] border px-3 py-3 transition-all duration-500 cursor-pointer ${sel === i ? 'bg-raised' : 'bg-ground/40 hover:bg-raised/60'} ${broken ? 'border-crit/60' : reached ? 'border-ok/35' : 'border-line'} ${reached ? 'opacity-100' : 'opacity-45'}`}>
                        <div className="flex items-center justify-between"><span className="font-mono text-[10px] text-faint">#{String(x.sequence).padStart(3, '0')}</span>
                          <span className={`transition-colors duration-500 ${broken ? 'text-crit' : reached && ok ? 'text-ok' : 'text-faint'}`}><Icon n={broken ? 'alert' : 'check'} className="size-3.5" /></span></div>
                        <div className="mt-2 text-[12px] font-medium uppercase tracking-[0.08em]">{x.kind}</div>
                        <div className="mt-0.5 font-mono text-[10px] text-mute truncate">{x.subject}</div>
                        <div className="mt-2 font-mono text-[10px] text-faint">{x.hash.slice(0, 8)}…</div>
                      </button>
                    </div>
                  )
                })}
              </div>
            </div>
            <div className="border-t border-line px-5 py-3 flex items-center gap-3">
              {recs.length === 0 ? <Tag v="No records" t="na" /> : step < 0 ? <Tag v="Walking" t="info" /> : firstBreak !== -1 && step >= firstBreak ? <Tag v="Tamper evidence" t="crit" /> : step >= recs.length - 1 ? <Tag v="Links verified" t="ok" /> : <Tag v={`Checking #${step + 1}`} t="info" />}
              <span className="text-[12px] text-mute">{q.data?.message ?? 'Checks that each record points to the hash of the record before it.'}</span>
              {q.data?.verified != null && <span className="ml-auto"><Tag v={q.data.verified ? 'Backend: signatures valid' : 'Backend: not verified'} t={q.data.verified ? 'ok' : 'warn'} /></span>}
            </div>
          </Panel>
          {r && (
            <div className="mt-5 grid grid-cols-2 gap-5 max-[1100px]:grid-cols-1">
              <Panel title={`Record #${r.sequence} · ${r.kind}`} meta={time(r.timestamp)}><dl key={sel} className="animate-fade">
                <KV k="Subject" v={r.subject} /><KV k="Hash" v={<Hash v={r.hash} n={14} />} /><KV k="Previous hash" v={<Hash v={r.previous_hash} n={14} className={linkOk(recs, sel) ? '' : 'text-crit'} />} />
                <KV k="Nonce" v={r.nonce} /><KV k="Timestamp" v={r.timestamp} /><KV k="Signature" v={r.signature_hex ? <Hash v={r.signature_hex} n={12} /> : <span className="text-faint">not provided</span>} />
              </dl></Panel>
              <Panel title="Link check">
                {sel === 0 ? <p className="text-[13px] text-ink-2">Genesis record. It has no predecessor to check against.</p> : (
                  <div key={sel} className="space-y-3 animate-fade">
                    <div><Label>#{recs[sel - 1].sequence} hash</Label><div className="mt-1 font-mono text-[11px] break-all text-ink-2">{recs[sel - 1].hash}</div></div>
                    <div><Label>#{r.sequence} previous_hash</Label><div className={`mt-1 font-mono text-[11px] break-all ${linkOk(recs, sel) ? 'text-ok' : 'text-crit'}`}>{r.previous_hash}</div></div>
                    <Tag v={linkOk(recs, sel) ? 'Link intact' : 'Mismatch · chain broken here'} t={linkOk(recs, sel) ? 'ok' : 'crit'} />
                  </div>
                )}
              </Panel>
            </div>
          )}
        </>
      )}
      <div className="mt-8"><Label className="mb-3">Passport findings attributed to Provenance</Label><ModuleFindings mod="provenance" /></div>
    </>
  )
}
