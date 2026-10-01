import { useMemo, useState } from 'react'
import type { Finding } from '../api/types'
import { FindingRow, Inspector } from '../components/Evidence'
import { Empty, Label, PageHead, Panel, Tabs, Tag, pct, tone } from '../components/ui'
import { useStore } from '../store'

export const MODULES = {
  sentinel: { title: 'Data Sentinel', match: /sentinel|data|poison|dup/i },
  auditor: { title: 'Model Auditor', match: /audit|model|backdoor|calib/i },
  provenance: { title: 'Provenance', match: /proven|lineage|digest|tamper/i },
  shift: { title: 'Shift Diagnostician', match: /shift|drift|ood/i },
} as const
export type ModuleKey = keyof typeof MODULES
export const findingsFor = (all: Finding[], k: ModuleKey) => all.filter((f) => MODULES[k].match.test(f.module))

const CATS = [['all', 'All'], ['dup', 'Duplicates'], ['label', 'Labels'], ['ood', 'OOD'], ['trigger', 'Triggers'], ['batch', 'Contributor/Batch']] as const
type Cat = (typeof CATS)[number][0]
const CAT_RX: Record<Exclude<Cat, 'all'>, RegExp> = { dup: /dup|near.?dup|phash|hash match/i, label: /label|relabel|annotat/i, ood: /ood|out.of.dist|distribution/i, trigger: /trigger|patch|backdoor/i, batch: /contributor|batch|shard/i }
const hay = (f: Finding) => `${f.reason} ${f.asset} ${JSON.stringify(f.evidence ?? '')}`

/** Findings list + inspector for a module, used on every analysis page. */
export function ModuleFindings({ mod, filter }: { mod: ModuleKey; filter?: (f: Finding) => boolean }) {
  const { active } = useStore()
  const [open, setOpen] = useState<Finding>()
  const all = active?.passport?.top_findings ?? []
  const list = findingsFor(all, mod).filter(filter ?? (() => true))
  if (!active?.passport) return <Empty title="No completed audit is active" hint="Findings appear here once an audit completes. Run one from Overview or reopen one from Audit History." />
  return (
    <>
      {list.length === 0 ? <Empty title="No findings in this view" hint={`The active passport has ${all.length} top finding(s). None of them match ${MODULES[mod].title} with the current filter. No finding here means nothing was flagged. It does not mean the check passed.`} />
        : <Panel title="Findings" meta={`${list.length} of ${all.length} in passport · click to inspect`} pad={false}>{list.map((f, i) => <FindingRow key={f.finding_id} f={f} i={i} onOpen={() => setOpen(f)} />)}</Panel>}
      <Inspector f={open} onClose={() => setOpen(undefined)} />
    </>
  )
}

const SEV = [['CRITICAL', 'bg-crit'], ['HIGH', 'bg-warn'], ['MEDIUM', 'bg-warn/50'], ['LOW', 'bg-ok/60']] as const

export default function Sentinel() {
  const { active } = useStore()
  const [cat, setCat] = useState<Cat>('all')
  const mine = findingsFor(active?.passport?.top_findings ?? [], 'sentinel')
  const counts = useMemo(() => Object.fromEntries(CATS.slice(1).map(([k]) => [k, mine.filter((f) => CAT_RX[k as Exclude<Cat, 'all'>].test(hay(f))).length])), [mine])
  const assets = [...new Set(mine.map((f) => f.asset))]
  const batches = Object.entries(mine.reduce<Record<string, Finding[]>>((m, f) => { const b = f.asset.split('/').slice(-1)[0] || f.asset; (m[b] ??= []).push(f); return m }, {})).sort((a, b) => b[1].length - a[1].length)
  return (
    <>
      <PageHead index="02" title="Data Sentinel" lede="Forensic screening of training data for duplicates, label corruption, out-of-distribution samples and trigger patterns before any training happens." right={active && <Label>{active.id}</Label>} />
      {active?.passport && (
        <div className="grid grid-cols-[1fr_1.4fr] gap-5 mb-5 max-[1100px]:grid-cols-1">
          <Panel title="Dataset summary" meta="from passport findings">
            {assets.length === 0 ? <p className="text-[12.5px] text-mute">Sentinel raised nothing against any dataset in this audit.</p> : assets.map((a) => (
              <div key={a} className="flex items-center justify-between py-2 border-b border-line last:border-0"><span className="font-mono text-[11.5px] text-ink-2 truncate">{a}</span><span className="font-mono text-[10px] text-faint">{mine.filter((f) => f.asset === a).length} finding(s)</span></div>
            ))}
            <p className="mt-3 text-[11px] text-faint">The backend doesn't report the total sample count yet. It will show here when it does.</p>
          </Panel>
          <Panel title="Evidence classes" meta="keyword-classified from backend findings">
            <div className="grid grid-cols-5 gap-3">
              {CATS.slice(1).map(([k, l]) => {
                const n = counts[k] ?? 0
                return (
                  <button key={k} onClick={() => setCat(k)} className={`text-left rounded-[3px] border p-3 transition-colors cursor-pointer ${cat === k ? 'border-info/50 bg-info/[0.05]' : 'border-line hover:border-line-strong'}`}>
                    <div className={`font-mono text-[22px] leading-none ${n ? 'text-ink' : 'text-faint'}`}>{n}</div>
                    <div className="mt-2 text-[11px] text-mute leading-tight">{l}</div>
                    <div className="mt-3 h-8 flex items-end gap-[2px]">{mine.map((f, i) => <span key={i} className={`grow flex-1 rounded-[1px] ${CAT_RX[k as Exclude<Cat, 'all'>].test(hay(f)) ? (tone(f.severity) === 'crit' ? 'bg-crit' : 'bg-warn/70') : 'bg-line'}`} style={{ height: `${30 + (f.confidence ?? 0.5) * 70}%`, animationDelay: `${i * 0.05}s` }} />)}</div>
                  </button>
                )
              })}
            </div>
          </Panel>
        </div>
      )}
      {active?.passport && mine.length > 0 && (
        <div className="grid grid-cols-2 gap-5 mb-5 max-[1100px]:grid-cols-1">
          <Panel title="Severity distribution" meta={`${mine.length} findings`}>
            <div className="flex h-3 rounded-full overflow-hidden bg-line">{SEV.map(([s, c]) => { const n = mine.filter((f) => f.severity === s).length; return n ? <span key={s} className={`${c} grow-x`} style={{ width: `${(n / mine.length) * 100}%` }} title={`${s}: ${n}`} /> : null })}</div>
            <div className="mt-3 flex gap-5">{SEV.map(([s, c]) => <span key={s} className="flex items-center gap-1.5 font-mono text-[10.5px] text-mute"><span className={`size-2 rounded-[2px] ${c}`} />{s.toLowerCase()} {mine.filter((f) => f.severity === s).length}</span>)}</div>
          </Panel>
          <Panel title="Contributor / batch analysis" meta="grouped by asset path">
            {batches.map(([b, fs], i) => (
              <div key={b} className="py-1.5">
                <div className="flex justify-between font-mono text-[11px]"><span className="text-ink-2 truncate">{b}</span><span className="text-faint">{fs.length} · max {pct(Math.max(...fs.map((f) => f.confidence ?? 0)))}</span></div>
                <div className="mt-1 h-[3px] bg-line rounded-full overflow-hidden"><span className="block h-full bar-grad grow-x" style={{ width: `${(fs.length / batches[0][1].length) * 100}%`, animationDelay: `${i * 0.08}s` }} /></div>
              </div>
            ))}
            <p className="mt-2 text-[10.5px] text-faint">Contributor IDs are not in the finding contract. Batches are grouped from the asset path (for example <span className="font-mono">dataset/shard</span>).</p>
          </Panel>
        </div>
      )}
      {active?.passport && <div className="mb-4 flex items-center justify-between"><Tabs tabs={CATS} value={cat} onChange={setCat} />{cat !== 'all' && <Tag v={`${counts[cat]} matching`} t="info" />}</div>}
      <ModuleFindings mod="sentinel" filter={cat === 'all' ? undefined : (f) => CAT_RX[cat].test(hay(f))} />
    </>
  )
}
