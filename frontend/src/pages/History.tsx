import { useState } from 'react'
import { Empty, Label, PageHead, Panel, Tabs, Tag } from '../components/ui'
import type { PageKey } from '../components/Shell'
import { useStore } from '../store'
import Icon from '../components/icons'

const F = [['all', 'All'], ['QUARANTINE', 'Quarantine'], ['REVIEW', 'Review'], ['CLEAR', 'Clear'], ['failed', 'Failed']] as const
const COLS = 'grid-cols-[150px_1.2fr_1fr_110px_70px_120px_110px]'

export default function History({ go }: { go: (p: PageKey) => void }) {
  const { runs, active, setActiveId } = useStore()
  const [q, setQ] = useState('')
  const [f, setF] = useState<(typeof F)[number][0]>('all')
  const list = runs.filter((r) => (f === 'all' || (f === 'failed' ? r.state === 'failed' : r.passport?.overall_disposition === f)) && `${r.id} ${r.label} ${(r.passport?.top_findings ?? []).map((x) => x.asset).join(' ')}`.toLowerCase().includes(q.toLowerCase()))
  return (
    <>
      <PageHead index="09" title="Audit history" lede="Every audit run in this session. Opening one makes it the active audit across the whole console." />
      {runs.length === 0 ? <Empty title="No audits recorded" hint="History is kept in memory for this session only." /> : (
        <>
          <div className="flex items-center gap-3 mb-4">
            <div className="relative flex-1 max-w-sm"><Icon n="search" className="size-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-faint" /><input aria-label="Search audits" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search ID, scenario, asset" className="w-full h-8 pl-8 pr-3 bg-panel border border-line-strong rounded-[3px] font-mono text-[12px] placeholder:text-faint focus:outline-none focus:border-info" /></div>
            <Tabs tabs={F} value={f} onChange={setF} />
          </div>
          <Panel title="Ledger" meta={`${list.length} of ${runs.length}`} pad={false}>
            <div className={`grid ${COLS} gap-4 px-4 h-9 items-center border-b border-line`}>{['Audit ID', 'Scenario', 'Assets', 'Modules', 'Findings', 'Disposition', 'Verification'].map((h) => <Label key={h}>{h}</Label>)}</div>
            {list.map((r) => {
              const fs = r.passport?.top_findings ?? []
              return (
                <button key={r.id} onClick={() => { setActiveId(r.id); if (r.passport) go('passport') }}
                  className={`w-full grid ${COLS} gap-4 px-4 py-3 items-center text-left border-b border-line last:border-0 hover:bg-raised/60 cursor-pointer transition-colors ${active?.id === r.id ? 'bg-raised shadow-[inset_2px_0_0_var(--color-info)]' : ''}`}>
                  <div><div className="font-mono text-[11px]">{r.id}</div><div className="font-mono text-[10px] text-faint">{r.startedAt ? new Date(r.startedAt).toLocaleString([], { hour12: false }) : '—'}{r.source === 'fixture' && <span className="text-warn"> · fixture</span>}</div></div>
                  <span className="text-[13px]">{r.label}</span>
                  <span className="font-mono text-[10.5px] text-mute truncate">{[...new Set(fs.map((x) => x.asset))].join(', ') || '—'}</span>
                  <span className="font-mono text-[10.5px] text-mute">{new Set(fs.map((x) => x.module)).size || '—'}</span>
                  <span className="font-mono text-[11px]">{r.passport ? fs.length : '—'}</span>
                  <span>{r.passport ? <Tag v={r.passport.overall_disposition} /> : <Tag v={r.state} />}</span>
                  <span>{r.verify === undefined ? <span className="font-mono text-[10px] text-faint">unchecked</span> : r.verify === null ? <Tag v="n/a" t="na" /> : !r.passport?.signature_hex && r.verify.is_valid ? <Tag v="n/a" t="na" /> : <Tag v={r.verify.is_valid === true ? 'Valid' : 'Invalid'} />}</span>
                </button>
              )
            })}
            {list.length === 0 && <div className="px-4 py-8 text-center text-[12.5px] text-mute">No audits match these filters.</div>}
          </Panel>
        </>
      )}
    </>
  )
}
