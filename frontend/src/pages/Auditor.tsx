import { useState } from 'react'
import { api } from '../api/client'
import type { ModelAudit } from '../api/types'
import Icon from '../components/icons'
import { Failure, Hash, KV, Label, Loading, Meter, PageHead, Panel, Tabs, Tag, useLoad } from '../components/ui'
import { useStore } from '../store'
import { ModuleFindings } from './Findings'

const TABS = [['overview', 'Overview'], ['black', 'Black-box'], ['white', 'White-box'], ['finger', 'Fingerprint'], ['behav', 'Behavioral tests']] as const
type T = (typeof TABS)[number][0]

function Unavailable({ title, why }: { title: string; why: string }) {
  return (
    <div className="hatch border border-dashed border-line-strong rounded-[4px] px-6 py-10 animate-rise">
      <div className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.18em] text-ink-2"><Icon n="alert" className="size-3.5 text-mute" />{title} · assessment unavailable</div>
      <p className="mt-3 text-[13px] text-mute max-w-xl">{why}</p>
      <p className="mt-2 text-[11px] text-faint">This check was not performed. It hasn't passed and it hasn't failed.</p>
    </div>
  )
}

function Body({ m, tab }: { m: ModelAudit; tab: T }) {
  if (tab === 'overview') return (
    <div className="grid grid-cols-[1fr_1fr] gap-5 max-[1100px]:grid-cols-1">
      <Panel title="Model identity"><dl>
        <KV k="Name" v={m.identity.name} /><KV k="Format" v={m.identity.format} /><KV k="SHA-256" v={<Hash v={m.identity.sha256} />} />
        <KV k="Access level" v={<Tag v={m.identity.access} t={m.identity.access === 'white-box' ? 'ok' : m.identity.access === 'black-box' ? 'info' : 'na'} />} />
      </dl></Panel>
      <Panel title="Limitations" meta="declared by backend">
        {m.limitations?.length ? <ul className="space-y-2.5">{m.limitations.map((l) => <li key={l} className="flex gap-2.5 text-[13px] text-ink-2"><span className="mt-2 size-1 rounded-full bg-warn shrink-0" />{l}</li>)}</ul> : <p className="text-[12.5px] text-mute">None declared.</p>}
      </Panel>
    </div>
  )
  if (tab === 'black') {
    const gb = m.blackbox?.golden_battery, ts = m.blackbox?.trigger_sweep
    if (!gb && !ts) return <Unavailable title="Black-box" why="The backend returned no black-box results for this model." />
    return (
      <div className="grid grid-cols-2 gap-5">
        <Panel title="Golden battery">{gb ? <><div className="font-mono text-[34px] leading-none">{gb.passed}<span className="text-faint text-[18px]">/{gb.total}</span></div><div className="mt-3"><Meter v={gb.total ? gb.passed / gb.total : 0} t={gb.passed === gb.total ? 'ok' : 'warn'} /></div><p className="mt-3 text-[12px] text-mute">Reference inputs with known correct outputs.</p></> : <p className="text-mute text-[12.5px]">Not reported.</p>}</Panel>
        <Panel title="Trigger sweep">{ts ? <><div className={`font-mono text-[34px] leading-none ${ts.flagged ? 'text-warn' : 'text-ok'}`}>{ts.flagged}<span className="text-faint text-[18px]"> flagged / {ts.triggers_tested}</span></div><div className="mt-4 flex gap-[3px] flex-wrap">{Array.from({ length: ts.triggers_tested }, (_, i) => <span key={i} className={`grow size-3 rounded-[2px] ${i < ts.flagged ? 'bg-warn' : 'bg-raised border border-line'}`} style={{ animationDelay: `${i * 0.02}s` }} />)}</div></> : <p className="text-mute text-[12.5px]">Not reported.</p>}</Panel>
      </div>
    )
  }
  if (tab === 'white') {
    if (!m.whitebox) return <Unavailable title="White-box" why={m.identity.access !== 'white-box' ? `This model is only reachable as ${m.identity.access}, so its parameter and activation statistics can't be inspected.` : 'The backend returned no white-box statistics.'} />
    return <div className="grid grid-cols-2 gap-5">{(['parameter_stats', 'activation_stats'] as const).map((k) => <Panel key={k} title={k.replace('_', ' ')}>{m.whitebox![k] ? <dl>{Object.entries(m.whitebox![k]!).map(([a, b]) => <KV key={a} k={a} v={b} />)}</dl> : <p className="text-mute text-[12.5px]">Not reported.</p>}</Panel>)}</div>
  }
  if (tab === 'finger') {
    if (!m.fingerprint) return <Unavailable title="Fingerprint" why="No fingerprint returned." />
    const ok = m.fingerprint.matches_registry
    return (
      <Panel title="Artefact fingerprint">
        <div className="flex items-center gap-6">
          <div className={`size-16 rounded-full grid place-items-center border ${ok === true ? 'border-ok/50 text-ok' : ok === false ? 'border-crit/50 text-crit' : 'border-line-strong text-faint'}`}><Icon n={ok ? 'check' : ok === false ? 'alert' : 'model'} className="size-6" /></div>
          <div className="min-w-0"><Label>Digest</Label><Hash v={m.fingerprint.digest} n={24} className="mt-1 text-ink" />
            <div className="mt-3">{ok === true ? <Tag v="Matches signed registry" t="ok" /> : ok === false ? <Tag v="Registry mismatch" t="crit" /> : <Tag v="Registry not checked" t="na" />}</div></div>
        </div>
      </Panel>
    )
  }
  if (!m.behavioral?.length) return <Unavailable title="Behavioral tests" why="No controlled behavioral tests were reported." />
  return <Panel title="Controlled tests" meta={`${m.behavioral.filter((b) => b.passed).length}/${m.behavioral.length} passed`} pad={false}>{m.behavioral.map((b) => (
    <div key={b.name} className="flex items-center gap-4 px-4 py-3 border-b border-line last:border-0"><Tag v={b.passed ? 'Pass' : 'Fail'} t={b.passed ? 'ok' : 'crit'} /><div className="flex-1"><div className="text-[13px]">{b.name}</div>{b.detail && <div className="font-mono text-[10.5px] text-faint mt-0.5">{b.detail}</div>}</div></div>
  ))}</Panel>
}

export default function Auditor() {
  const { source } = useStore()
  const [tab, setTab] = useState<T>('overview')
  const q = useLoad(() => api.modelAudit(), [source])
  return (
    <>
      <PageHead index="03" title="Model Auditor" lede="Tests the trained model for trigger-conditioned behaviour, miscalibration and substitution. Each check reports only what the access level actually allows." right={<Tabs tabs={TABS} value={tab} onChange={setTab} />} />
      <div key={tab} className="animate-fade">
        {q.loading ? <Loading label="Loading model assessment…" /> : q.error ? <Failure what="Model analysis" error={q.error} affected="Model Auditor tabs. Passport findings below are unaffected." retry={q.reload} /> : <Body m={q.data!} tab={tab} />}
      </div>
      <div className="mt-8"><Label className="mb-3">Passport findings attributed to Model Auditor</Label><ModuleFindings mod="auditor" /></div>
    </>
  )
}
