import { useState } from 'react'
import { api } from '../api/client'
import type { RedTeamResponse } from '../api/types'
import { Btn, Empty, Failure, Label, Loading, Meter, PageHead, Panel, Stat, Tag, pct } from '../components/ui'

const CATALOG: [string, RegExp][] = [['Label Flip', /label.?flip/], ['Duplicate Flood', /duplicate|flood/], ['OOD Insertion', /\bood\b|out.?of.?distribution/], ['Trigger Poisoning', /trigger|badnets|backdoor/], ['Model Substitution', /substitut|model.?swap/], ['Inference Tampering', /inference.?tamper/], ['Replay', /replay/], ['Distribution Shift', /distribution.?shift|\bshift\b|drift/]]
const t = (v?: number) => (v == null || Number.isNaN(v) ? 'na' : v >= 0.9 ? 'ok' : v >= 0.8 ? 'warn' : 'crit')
const COLS = 'grid-cols-[1.3fr_90px_90px_90px_1fr_1fr_1fr_80px]'

export default function RedTeam() {
  const [seed, setSeed] = useState(42)
  const [d, setD] = useState<RedTeamResponse>()
  const [ranSeed, setRanSeed] = useState<number>()
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<unknown>()
  const go = async () => { if (busy) return; const sd = Number.isFinite(seed) ? Math.trunc(seed) : 42; setBusy(true); setErr(undefined); try { setD(await api.redteam(sd)); setRanSeed(sd) } catch (e) { setErr(e) } finally { setBusy(false) } }
  const scen = d?.scenarios_evaluated ?? []
  const evaluated = (re: RegExp) => scen.some((s) => re.test(`${s.attack_name ?? ''} ${s.attack_family ?? ''}`.toLowerCase()))
  return (
    <>
      <PageHead index="07" title="Red-team laboratory" lede="Controlled, reproducible attacks with known ground truth, replayed against VisionGuard's detectors. Only attacks that were actually evaluated get a score." />
      <div className="grid grid-cols-[300px_1fr] gap-5 max-[1100px]:grid-cols-1">
        <div className="space-y-5">
          <Panel title="Attack configuration">
            <label className="block"><Label>Seed · deterministic</Label>
              <input type="number" value={seed} onChange={(e) => setSeed(+e.target.value)} className="mt-2 w-full h-8 bg-ground border border-line-strong rounded-[3px] px-3 font-mono text-[12px] focus:outline-none focus:border-info" /></label>
            <p className="mt-3 text-[11.5px] text-faint">The benchmark endpoint runs its full built-in suite. Choosing individual attacks isn't exposed by the API yet.</p>
            <Btn primary disabled={busy} onClick={go} className="mt-4 w-full">{busy ? 'Running suite…' : 'Run benchmark'}</Btn>
          </Panel>
          <Panel title="Attack catalogue" meta={d ? 'after run' : 'before run'} pad={false}>
            {CATALOG.map(([c, re]) => { const e = evaluated(re); return (
              <div key={c} className="flex items-center justify-between px-4 py-2.5 border-b border-line last:border-0"><span className="text-[12.5px] text-ink-2">{c}</span>{d ? <Tag v={e ? 'Evaluated' : 'Not in suite'} t={e ? 'ok' : 'na'} /> : <span className="font-mono text-[10px] text-faint">—</span>}</div>
            ) })}
          </Panel>
        </div>
        <div>
          {busy ? <Loading label="Replaying attacks against detectors…" /> : err ? <Failure what="Red-team benchmark" error={err} retry={go} /> : !d ? <Empty title="Benchmark not yet run" hint="Results are deterministic for a given seed, so evaluators can reproduce every number." /> : (
            <div className="space-y-5">
              <div className="grid grid-cols-3 divide-x divide-line border border-line bg-panel rounded-[4px] animate-rise">
                <Stat label="Macro precision" value={pct(d.macro_precision)} t={t(d.macro_precision)} />
                <Stat label="Macro recall" value={pct(d.macro_recall)} t={t(d.macro_recall)} />
                <Stat label="Macro F1" value={pct(d.macro_f1)} t={t(d.macro_f1)} />
              </div>
              <Panel title="Ground truth vs VisionGuard result" meta={`${scen.length} evaluated · seed ${ranSeed ?? '—'}`} pad={false}>
                <div className={`grid ${COLS} gap-3 px-4 h-9 items-center border-b border-line`}>{['Attack', 'Injected', 'Detected', 'Det. rate', 'Precision', 'Recall', 'F1', 'FP'].map((h) => <Label key={h}>{h}</Label>)}</div>
                {scen.map((s, i) => {
                  const fp = (s as unknown as Record<string, unknown>).false_positives
                  return (
                    <div key={`${s.attack_name}-${i}`} className={`grid ${COLS} gap-3 px-4 py-3 items-center border-b border-line last:border-0 hover:bg-raised/40 transition-colors`}>
                      <div><div className="text-[13px]">{s.attack_name}</div><div className="font-mono text-[10px] text-faint">{s.attack_family}</div></div>
                      <div className="font-mono text-[11.5px]">{s.sample_count}</div>
                      <div className="font-mono text-[11.5px]">{s.detected_count}</div>
                      <div className="font-mono text-[11.5px]">{s.sample_count > 0 ? pct(s.detected_count / s.sample_count) : '—'}</div>
                      {[s.precision, s.recall, s.f1_score].map((v, i) => <div key={i}><div className="font-mono text-[11px] mb-1.5">{pct(v)}</div>{v != null && <Meter v={v} t={t(v)} />}</div>)}
                      <div className="font-mono text-[11px] text-faint">{typeof fp === 'number' ? <span className="text-ink-2">{fp}</span> : 'n/r'}</div>
                    </div>
                  )
                })}
              </Panel>
              <Panel title="Limitations">
                <ul className="space-y-2 text-[12.5px] text-ink-2">
                  <li>· These are synthetic attacks from a fixed generator. Real adversaries may adapt to the detectors.</li>
                  <li>· False-positive counts show "n/r" when the backend doesn't report them.</li>
                  <li>· Attacks marked "Not in suite" were never evaluated, so they have no score. That isn't a failed test.</li>
                </ul>
              </Panel>
            </div>
          )}
        </div>
      </div>
    </>
  )
}
