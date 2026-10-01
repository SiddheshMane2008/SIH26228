import { useEffect, useState } from 'react'
import { SCENARIOS } from '../api/scenarios'
import type { AuditRun, Finding } from '../api/types'
import { FindingRow, Inspector } from '../components/Evidence'
import Icon from '../components/icons'
import type { PageKey } from '../components/Shell'
import { Btn, Count, Dot, Gauge, Label, Panel, Tag, pct, short, time, tone } from '../components/ui'
import { useStore } from '../store'
import { MODULES, findingsFor, type ModuleKey } from './Findings'

type StageState = 'idle' | 'running' | 'clear' | 'flagged' | 'critical' | 'halted' | 'notrun' | 'signed' | 'unsigned'
const ST: Record<StageState, [string, string]> = {
  idle: ['Idle', 'na'], running: ['Executing', 'info'], clear: ['No findings', 'ok'], flagged: ['Review', 'warn'], critical: ['Critical', 'crit'],
  halted: ['Halted', 'crit'], notrun: ['Not run', 'na'], signed: ['Signed', 'ok'], unsigned: ['Unsigned', 'warn'],
}
const RING: Record<string, string> = { ok: 'border-ok/55 text-ok', warn: 'border-warn/55 text-warn', crit: 'border-crit/60 text-crit', info: 'border-info/55 text-info', na: 'border-line-strong text-faint' }

function modState(r: AuditRun | undefined, k: ModuleKey): [StageState, Finding[]] {
  if (!r) return ['idle', []]
  if (r.state === 'running') return ['running', []]
  if (r.state === 'failed') return ['halted', []]
  if (!r.passport) return ['notrun', []]
  const f = findingsFor(r.passport.top_findings, k)
  return [f.some((x) => x.severity === 'CRITICAL') ? 'critical' : f.some((x) => ['HIGH', 'MEDIUM'].includes(x.severity)) ? 'flagged' : 'clear', f]
}

function Pipeline({ go, onFinding }: { go: (p: PageKey) => void; onFinding: (f: Finding) => void }) {
  const { active: r } = useStore()
  const mods = (Object.keys(MODULES) as ModuleKey[]).map((k) => ({ k, title: MODULES[k].title, ...(([s, f]) => ({ s, f }))(modState(r, k)) }))
  const stages: { key: string; title: string; icon: string; s: StageState; f: Finding[]; page: PageKey }[] = [
    { key: 'ingest', title: 'Ingest', icon: 'ingestion', s: !r ? 'idle' : r.state === 'running' ? 'running' : r.state === 'failed' ? 'halted' : 'clear', f: [], page: 'ingestion' },
    ...mods.map((m) => ({ key: m.k, title: m.k === 'shift' ? 'Shift' : m.title, icon: m.k, s: m.s, f: m.f, page: m.k as PageKey })),
    { key: 'blast', title: 'Blast Radius', icon: 'blast', s: !r || r.state !== 'complete' ? (r?.state === 'running' ? 'idle' : r?.state === 'failed' ? 'halted' : 'idle') : r.blast ? (r.blast.trace.affected_models.length ? 'flagged' : 'clear') : 'notrun', f: [], page: 'blast' },
    { key: 'passport', title: 'Trust Passport', icon: 'passport', s: !r || r.state === 'running' ? 'idle' : r.state === 'failed' ? 'halted' : r.passport?.signature_hex ? 'signed' : 'unsigned', f: [], page: 'passport' },
  ]
  const running = r?.state === 'running'
  return (
    <Panel title="Audit pipeline" meta={running ? 'backend executes as one call · per-stage progress not streamed' : r ? `${r.id} · ${r.label}` : 'awaiting audit'} pad={false}>
      <div className="relative px-5 pt-6 pb-5">
        <div className="absolute left-[calc(1.25rem+18px)] right-[calc(1.25rem+18px)] top-[calc(1.5rem+18px)] h-px bg-line overflow-hidden">
          {running && <div className="absolute inset-y-0 w-1/4 bg-gradient-to-r from-transparent via-info to-transparent animate-scan" />}
          {r?.state === 'complete' && <div className="absolute inset-0 bg-line-strong origin-left grow" style={{ transformOrigin: 'left', animationName: 'none' }} />}
        </div>
        <ol className="relative grid grid-cols-7 gap-2">
          {stages.map((st, i) => {
            const [label, t] = ST[st.s]
            return (
              <li key={st.key} className="flex flex-col items-center text-center min-w-0">
                <button onClick={() => go(st.page)} aria-label={`${st.title}: ${label}`} className={`relative grid place-items-center size-9 rounded-full border bg-panel transition-all duration-500 cursor-pointer hover:scale-105 ${RING[t]} ${st.s === 'running' ? 'glow' : ''}`} style={{ transitionDelay: `${i * 70}ms` }}>
                  <Icon n={st.icon} className="size-[15px]" />
                  {st.f.length > 0 && <span className={`absolute -top-1 -right-1 min-w-4 h-4 px-1 rounded-full grid place-items-center font-mono text-[9px] text-ground animate-fade ${t === 'crit' ? 'bg-crit' : 'bg-warn'}`} style={{ animationDelay: `${0.3 + i * 0.08}s` }}>{st.f.length}</span>}
                </button>
                <div className="mt-2.5 text-[12px] text-ink truncate max-w-full">{st.title}</div>
                <div className={`mt-1 font-mono text-[9.5px] uppercase tracking-[0.14em] ${st.s === 'running' ? 'text-info animate-breathe' : `text-${t === 'na' ? 'faint' : t}`}`}>{label}</div>
                <div className="mt-2 w-full space-y-1">
                  {st.f.slice(0, 2).map((f, j) => (
                    <button key={f.finding_id} onClick={() => onFinding(f)} className="w-full text-left rounded-[3px] border border-line bg-ground/50 px-2 py-1.5 hover:border-line-strong cursor-pointer animate-rise" style={{ animationDelay: `${0.35 + i * 0.08 + j * 0.05}s` }}>
                      <div className="flex items-center gap-1.5"><Dot t={tone(f.severity)} /><span className="font-mono text-[9px] text-faint truncate">{f.finding_id}</span></div>
                      <div className="mt-0.5 text-[10.5px] text-ink-2 leading-tight line-clamp-2">{f.reason}</div>
                    </button>
                  ))}
                  {st.s === 'notrun' && <button onClick={() => go('blast')} className="font-mono text-[10px] text-info hover:underline cursor-pointer">Trace →</button>}
                </div>
              </li>
            )
          })}
        </ol>
        {r?.state === 'failed' && <div className="mt-4 rounded-[3px] border border-crit/35 bg-crit/[0.04] px-3 py-2 font-mono text-[11px] text-crit animate-rise">Pipeline halted · {r.error} · the backend didn't report which stage failed.</div>}
      </div>
    </Panel>
  )
}

function Elapsed({ from }: { from: string }) {
  const [n, setN] = useState(0)
  useEffect(() => { const id = setInterval(() => setN(Date.now() - +new Date(from)), 250); return () => clearInterval(id) }, [from])
  return <span className="font-mono tabular-nums">{(n / 1000).toFixed(1)}s</span>
}

/** Guided journey — every step's state is derived from real session state. */
function Journey({ go }: { go: (p: PageKey) => void }) {
  const { link, source, assets, active: r } = useStore()
  const steps: [string, boolean, PageKey, string][] = [
    ['System linked', link === 'online' || source === 'fixture', 'settings', 'Check backend'],
    ['Assets registered', assets.some((a) => a.stage === 'registered'), 'ingestion', 'Upload'],
    ['Audit complete', r?.state === 'complete', 'overview', 'Run audit'],
    ['Evidence reviewed', !!r?.passport && (r.passport.top_findings.length === 0 || !!r.reviewed), 'sentinel', 'Open evidence'],
    ['Blast radius traced', !!r?.blast, 'blast', 'Trace'],
    ['Passport verified', r?.verify?.is_valid === true, 'passport', 'Verify'],
  ]
  const next = steps.findIndex((s) => !s[1])
  return (
    <nav aria-label="Assurance journey" className="mb-5 flex items-stretch rounded-[4px] border border-line bg-panel/70 overflow-hidden animate-rise">
      {steps.map(([l, done, page, cta], i) => (
        <button key={l} onClick={() => go(page)} className={`group relative flex-1 min-w-0 px-3.5 py-2.5 text-left border-r border-line last:border-0 transition-colors cursor-pointer hover:bg-raised/60 ${i === next ? 'bg-accent/[0.06]' : ''}`}>
          {i === next && <span className="absolute inset-x-0 top-0 h-px bar-grad" />}
          <div className="flex items-center gap-2">
            <span className={`size-4 rounded-full grid place-items-center border text-[9px] font-mono transition-colors ${done ? 'border-ok/50 text-ok bg-ok/10' : i === next ? 'border-accent text-accent' : 'border-line-strong text-faint'}`}>{done ? '✓' : i + 1}</span>
            <span className={`text-[12px] truncate ${done ? 'text-ink-2' : i === next ? 'text-ink' : 'text-mute'}`}>{l}</span>
          </div>
          <div className={`mt-1 pl-6 font-mono text-[9.5px] uppercase tracking-[0.12em] ${i === next ? 'text-accent' : 'text-faint'}`}>{done ? 'done' : i === next ? `next · ${cta} →` : 'pending'}</div>
        </button>
      ))}
    </nav>
  )
}

function AssuranceState() {
  const { active: r, runs } = useStore()
  const p = r?.passport
  const f = p?.top_findings ?? []
  const title = !r ? 'No audit on record' : r.state === 'running' ? 'Audit in progress' : r.state === 'failed' ? 'Audit could not complete' : !p ? 'Audit returned no passport' : p.overall_disposition === 'CLEAR' ? 'No findings requiring action' : p.overall_disposition === 'QUARANTINE' ? 'Quarantine recommended' : 'Assurance review required'
  const t = !r ? 'na' : r.state === 'running' ? 'info' : r.state === 'failed' ? 'crit' : !p ? 'na' : tone(p.overall_disposition)
  const models = [...new Set(f.map((x) => x.asset).filter((a) => /model/i.test(a)))]
  const datasets = [...new Set(f.map((x) => x.asset).filter((a) => /dataset|stream|shard/i.test(a)))]
  return (
    <section className="edge relative border border-line rounded-[4px] bg-panel animate-rise" style={{ ['--edge' as string]: `var(--color-${t === 'na' ? 'accent' : t})` }}>
      <div className={`absolute left-0 top-0 bottom-0 w-[3px] rounded-l-[4px] ${t === 'crit' ? 'bg-crit' : t === 'warn' ? 'bg-warn' : t === 'ok' ? 'bg-ok' : t === 'info' ? 'bg-info' : 'bg-line-strong'} transition-colors duration-700`} />
      <div className="grid grid-cols-[1fr_auto] gap-8 p-7 pl-8 max-[1100px]:grid-cols-1">
        <div className="min-w-0">
          <div className="flex items-center gap-3"><Label>Primary assurance state</Label>{r?.state === 'running' && <span className="text-[11px] text-accent">elapsed <Elapsed from={r.startedAt} /></span>}</div>
          <h2 key={title} className={`mt-3 text-[34px] font-semibold tracking-[-0.025em] leading-[1.02] stamp text-${t === 'na' ? 'ink-2' : t}`}>{title}</h2>
          <p className="mt-3 font-serif text-[16px] leading-snug text-ink-2 max-w-xl">{p?.executive_summary ?? (r?.state === 'running' ? 'The backend is running Sentinel, Auditor, Provenance and Shift checks. Results appear once it returns the signed passport.' : r?.state === 'failed' ? r.error : 'Pick a scenario below or register assets under Ingestion. Nothing is shown until the backend has produced it.')}</p>
          <dl className="mt-6 grid grid-cols-6 gap-px bg-line border border-line rounded-[3px] overflow-hidden max-[1300px]:grid-cols-3">
            {[
              ['Assets audited', p ? new Set(f.map((x) => x.asset)).size : '—'], ['Findings', p ? p.findings_summary?.total ?? f.length : '—'],
              ['Critical', p ? f.filter((x) => x.severity === 'CRITICAL').length : '—'], ['Open reviews', p ? f.filter((x) => x.disposition !== 'CLEAR').length : '—'],
              ['Last audit', r?.completedAt ? time(r.completedAt) : '—'], ['Audits in session', runs.length],
            ].map(([k, v]) => (
              <div key={k as string} className="bg-panel px-3 py-3"><dt className="font-mono text-[9.5px] uppercase tracking-[0.14em] text-faint">{k}</dt><dd className="mt-1.5 font-mono text-[18px] leading-none text-ink">{typeof v === 'number' ? <Count to={v} /> : v}</dd></div>
            ))}
          </dl>
          <div className="mt-3 flex gap-6 font-mono text-[10.5px] text-mute">
            <span>Model <span className="text-ink-2">{models[0] ?? '—'}</span></span><span>Dataset <span className="text-ink-2">{datasets[0] ?? '—'}</span></span>
          </div>
        </div>
        <div className="flex flex-col items-center justify-center">
          {p ? <Gauge v={p.overall_confidence} t={t} size={150}><span className="font-mono text-[22px]">{pct(p.overall_confidence)}</span><Label className="mt-1">confidence</Label></Gauge>
            : <div className={`size-[150px] rounded-full border border-dashed grid place-items-center ${r?.state === 'running' ? 'border-info/40' : 'border-line-strong'}`}>{r?.state === 'running' ? <span className="relative size-[120px] rounded-full border-t border-info spin-slow" style={{ animationDuration: '2.4s' }} /> : <Label>no data</Label>}</div>}
          {p && <div className="mt-3"><Tag v={p.overall_disposition} /></div>}
        </div>
      </div>
    </section>
  )
}

const CARD: { k: ModuleKey | 'blast' | 'passport'; title: string; desc: string }[] = [
  { k: 'sentinel', title: 'Data Sentinel', desc: 'Duplicates, labels, OOD, triggers' },
  { k: 'auditor', title: 'Model Auditor', desc: 'Black-box, white-box, fingerprint' },
  { k: 'provenance', title: 'Provenance', desc: 'Hash-linked lineage records' },
  { k: 'shift', title: 'Shift Diagnostician', desc: 'Distribution and embedding drift' },
  { k: 'blast', title: 'Blast Radius', desc: 'Downstream contamination' },
  { k: 'passport', title: 'Trust Passport', desc: 'Signed attestation, offline verify' },
]

function Modules({ go }: { go: (p: PageKey) => void }) {
  const { active: r } = useStore()
  return (
    <div className="grid grid-cols-6 gap-3 max-[1300px]:grid-cols-3">
      {CARD.map((c, i) => {
        const [s, f] = c.k === 'passport' ? [r?.verify ? (r.verify.is_valid ? 'clear' : 'flagged') : r?.passport ? 'notrun' : r?.state === 'running' ? 'running' : 'idle', [] as Finding[]] as const : c.k === 'blast' ? [r?.blast ? (r.blast.trace.affected_models.length ? 'flagged' : 'clear') : r?.state === 'complete' ? 'notrun' : 'idle', [] as Finding[]] as const : modState(r, c.k)
        const [label, t] = ST[s as StageState]
        const top = f.reduce<number | undefined>((m, x) => (x.confidence != null ? Math.max(m ?? 0, x.confidence) : m), undefined)
        return (
          <button key={c.k} onClick={() => go(c.k as PageKey)} className="group relative flex flex-col text-left rounded-[4px] border border-line bg-panel p-4 lift sheen cursor-pointer animate-rise" style={{ animationDelay: `${i * 0.05}s` }}>
            <div className="flex h-6 items-center justify-between"><span className="flex h-5 w-5 items-center text-mute group-hover:text-ink-2 transition-colors"><Icon n={c.k} /></span><Tag v={label} t={t} /></div>
            <div className="mt-4 text-[14px] font-medium">{c.title}</div>
            <div className="mt-0.5 min-h-[34px] text-[11.5px] leading-snug text-faint">{c.desc}</div>
            <div className="mt-auto pt-3 border-t border-line grid grid-cols-2 gap-2 font-mono text-[10.5px]">
              <div><div className="text-faint">findings</div><div className="text-ink-2 mt-0.5">{c.k === 'passport' ? (r?.passport ? (r.passport.signature_hex ? 'signed' : 'unsigned') : '—') : c.k === 'blast' ? (r?.blast ? `${r.blast.trace.affected_models.length} models` : '—') : r?.passport ? f.length : '—'}</div></div>
              <div><div className="text-faint">{c.k === 'passport' ? 'verified' : c.k === 'blast' ? 'status' : 'max conf.'}</div><div className="text-ink-2 mt-0.5">{c.k === 'passport' ? (r?.verify ? (r.verify.is_valid ? 'valid' : 'invalid') : '—') : c.k === 'blast' ? (r?.blast ? 'traced' : '—') : pct(top)}</div></div>
            </div>
            <div className="pointer-events-none absolute inset-x-3 bottom-full mb-2 rounded-[3px] border border-line-strong bg-raised px-3 py-2 text-[11px] text-ink-2 opacity-0 translate-y-1 group-hover:opacity-100 group-hover:translate-y-0 group-focus-visible:opacity-100 transition-all duration-200 z-10">
              {f[0] ? <><span className="font-mono text-[10px] text-faint">{f[0].finding_id}</span><div className="mt-0.5 line-clamp-2">{f[0].reason}</div></> : r?.passport ? 'Nothing raised in the active audit.' : 'No audit has run yet.'}
            </div>
          </button>
        )
      })}
    </div>
  )
}

export default function Overview({ go }: { go: (p: PageKey) => void }) {
  const { runs, active, run, link, source } = useStore()
  const [open, setOpen] = useState<Finding>()
  const busy = runs.some((r) => r.state === 'running')
  const ready = link === 'online' || source === 'fixture'
  const all = active?.passport?.top_findings ?? []
  return (
    <>
      <header className="flex items-end justify-between gap-8 mb-6 animate-rise">
        <div>
          <Label className="flex items-center gap-2"><span className="h-px w-6 bg-line-strong" />§ 00 · Overview</Label>
          <h1 className="mt-3 text-[30px] font-semibold tracking-[-0.025em] leading-none"><span className="text-grad">VisionGuard</span> <span className="text-mute font-normal">AI Assurance Console</span></h1>
          <p className="mt-2.5 font-serif italic text-[16.5px] text-ink-2 max-w-2xl">What is happening to your computer-vision assets, what was found, and the evidence behind it.</p>
        </div>
        {active && <div className="text-right"><Label>Active audit</Label><div className="mt-1 font-mono text-[12px] text-ink-2">{short(active.id, 14)}</div></div>}
      </header>

      <Journey go={go} />
      <AssuranceState />
      <div className="mt-5"><Pipeline go={go} onFinding={setOpen} /></div>
      <div className="mt-5"><Modules go={go} /></div>

      <div className="mt-5 grid grid-cols-[1fr_1.35fr] gap-5 max-[1100px]:grid-cols-1">
        <Panel title="Scenario bench" meta={ready ? `${SCENARIOS.length} reproducible scenarios` : 'backend required'} pad={false}>
          {SCENARIOS.map((s) => (
            <div key={s.id} className="group flex items-center gap-4 px-4 py-3.5 border-b border-line last:border-0 hover:bg-raised/50 transition-colors">
              <span className="font-mono text-[10.5px] text-faint w-9 group-hover:text-info transition-colors">{s.code}</span>
              <div className="flex-1 min-w-0"><div className="text-[13px] font-medium">{s.label}</div><div className="text-[11.5px] text-mute mt-0.5 line-clamp-1">{s.brief}</div></div>
              <Btn disabled={!ready || busy} onClick={() => run(s.id)}>{busy && active?.scenario === s.id ? 'Running' : 'Run'}</Btn>
            </div>
          ))}
        </Panel>
        <Panel title="Latest findings" meta={all.length ? 'click to open evidence' : undefined} pad={false}>
          {all.length ? all.slice(0, 5).map((f, i) => <FindingRow key={f.finding_id} f={f} i={i} onOpen={() => setOpen(f)} />)
            : <div className="px-5 py-10 text-center"><div className="font-serif italic text-[17px] text-ink-2">{active?.state === 'running' ? 'Waiting for backend…' : 'No findings yet'}</div><p className="mt-1 text-[12px] text-mute">Findings appear here once an audit returns.</p></div>}
          {active?.passport && <div className="px-4 py-3 border-t border-line flex gap-2"><Btn primary onClick={() => go('passport')}>Open Trust Passport</Btn><Btn onClick={() => go('sentinel')}>All findings</Btn></div>}
        </Panel>
      </div>
      <Inspector f={open} onClose={() => setOpen(undefined)} />
    </>
  )
}
