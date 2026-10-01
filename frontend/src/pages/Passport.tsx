import { api } from '../api/client'
import { useState } from 'react'
import { Mark, type PageKey } from '../components/Shell'
import { Btn, Copy, Empty, Label, Meter, PageHead, Tag, pct, time, tone } from '../components/ui'
import { useStore } from '../store'

function Seal({ signed, valid }: { signed: boolean; valid?: boolean }) {
  const text = signed ? 'ED25519 · SIGNED · VISIONGUARD · OFFLINE VERIFIABLE · ' : 'UNSIGNED · FIXTURE · NOT EVIDENCE · UNSIGNED · FIXTURE · '
  return (
    <div className={`relative size-[104px] shrink-0 ${valid === true ? 'text-ok' : valid === false ? 'text-crit' : signed ? 'text-ink-2' : 'text-warn'} transition-colors duration-700`}>
      <svg viewBox="0 0 100 100" className="absolute inset-0 spin-slow"><defs><path id="sealp" d="M50 50 m-38 0 a38 38 0 1 1 76 0 a38 38 0 1 1 -76 0" /></defs>
        <text fontSize="7.2" letterSpacing="1.6" fill="currentColor" className="font-mono"><textPath href="#sealp">{text}</textPath></text></svg>
      <svg viewBox="0 0 100 100" className="absolute inset-0" fill="none" stroke="currentColor">
        <circle cx="50" cy="50" r="28" strokeOpacity=".5" /><circle cx="50" cy="50" r="24" strokeDasharray="2 3" strokeOpacity=".4" />
        {valid === true ? <path d="M40 50l7 7 13-14" strokeWidth="2" pathLength={1} className="draw" /> : valid === false ? <path d="M42 42l16 16M58 42 42 58" strokeWidth="2" /> : <path d="M50 38 60 42v7c0 6-4 10-10 12-6-2-10-6-10-12v-7l10-4Z" strokeWidth="1.3" />}
      </svg>
    </div>
  )
}

function Row({ k, children, d = 0 }: { k: string; children: React.ReactNode; d?: number }) {
  return <div className="grid grid-cols-[150px_1fr] gap-4 py-3 border-b border-line animate-rise" style={{ animationDelay: `${d}s` }}><dt className="font-mono text-[10px] uppercase tracking-[0.16em] text-faint pt-0.5">{k}</dt><dd className="text-[13px] text-ink-2 min-w-0">{children}</dd></div>
}
function Sig({ k, v }: { k: string; v?: string }) {
  return <div className="py-2.5 border-b border-line last:border-0"><div className="flex items-center justify-between"><Label>{k}</Label><Copy v={v} /></div><div className="mt-1 font-mono text-[10.5px] text-ink-2 break-all leading-relaxed">{v || <span className="text-warn">absent · unsigned</span>}</div></div>
}

export default function Passport({ go }: { go: (p: PageKey) => void }) {
  const { active, patchRun, status, toast } = useStore()
  const p = active?.passport
  const [err, setErr] = useState<string>()
  const [busy, setBusy] = useState(false)
  if (!p || !active) return <><PageHead index="08" title="Trust passport" lede="A signed, portable record of what the assurance pipeline found." /><Empty title="No passport issued" hint="A passport is issued when an audit completes." action={<Btn primary onClick={() => go('overview')}>Go to Overview</Btn>} /></>
  const v = active.verify
  const t = tone(p.overall_disposition)
  const verify = async () => { if (busy) return; setBusy(true); setErr(undefined); try { const r = p.signature_hex && p.signer_public_key_hex ? await api.verifyPassport(p) : null; patchRun(active.id, { verify: r }); toast(r === null ? { tone: 'warn', title: 'Not verifiable', body: 'This passport carries no signature.' } : { tone: r.is_valid === true ? 'ok' : 'crit', title: r.is_valid === true ? 'Signature valid' : 'Signature invalid', body: r.message }) } catch (e) { patchRun(active.id, { verify: undefined }); setErr((e as Error).message); toast({ tone: 'crit', title: 'Verification failed', body: (e as Error).message }) } finally { setBusy(false) } }
  const download = () => { const a = document.createElement('a'); const u = URL.createObjectURL(new Blob([JSON.stringify(p, null, 2)], { type: 'application/json' })); a.href = u; a.download = `${p.passport_id || 'passport'}.json`; a.click(); setTimeout(() => URL.revokeObjectURL(u), 0) }
  const f = p.top_findings ?? []
  const assets = [...new Set(f.map((x) => x.asset))]
  const sev = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => [s, f.filter((x) => x.severity === s).length] as const)
  const unsigned = !p.signature_hex
  const integrity = v === undefined ? ['Not yet verified', 'na'] : v === null || (unsigned && v.is_valid) ? [active.source === 'fixture' ? 'Unverifiable · fixture' : 'Unverifiable · unsigned', 'warn'] : v.is_valid === true ? ['Signature valid', 'ok'] : ['Signature invalid', 'crit']
  return (
    <>
      <PageHead index="08" title="Trust passport" lede="A signed record of what the assurance pipeline found. It is evidence, not a guarantee that the system is safe."
        right={<div className="flex gap-2">{active.reportUrl && <a href={active.reportUrl} target="_blank" rel="noreferrer" className="h-8 px-3 grid place-items-center rounded-[3px] border border-line-strong font-mono text-[11px] uppercase tracking-[0.12em] text-ink-2 hover:text-ink">Report</a>}<Btn onClick={download}>Export JSON</Btn></div>} />

      <article key={p.passport_id} style={{ ['--edge' as string]: `var(--color-${t})` }} className="edge relative border border-line rounded-[6px] bg-panel shadow-[0_40px_80px_-40px_rgb(0_0_0/0.9)]" aria-label="Trust passport">
        <div className="absolute inset-0 pointer-events-none opacity-[0.35]" style={{ backgroundImage: 'repeating-linear-gradient(0deg, rgb(255 255 255 / .018) 0 1px, transparent 1px 4px)' }} />
        <div className={`h-[3px] ${t === 'crit' ? 'bg-crit' : t === 'warn' ? 'bg-warn' : 'bg-ok'} origin-left grow`} style={{ transformOrigin: 'left', animationName: 'none' }} />
        <header className="relative flex items-center justify-between px-8 py-5 border-b border-line animate-fade">
          <div className="flex items-center gap-3"><span className="text-accent"><Mark className="size-7" /></span><div><div className="font-mono text-[11px] tracking-[0.32em] text-grad">VISIONGUARD</div><div className="font-serif italic text-[15px] text-ink-2 -mt-0.5">Trust Passport</div></div></div>
          <div className="text-right"><Label>Passport ID</Label><div className="mt-1 flex items-center gap-1 font-mono text-[11.5px]">{p.passport_id}<Copy v={p.passport_id} /></div></div>
        </header>

        <div className="relative grid grid-cols-[1fr_340px] max-[1100px]:grid-cols-1">
          <div className="px-8 py-7 border-r border-line">
            <div className="flex items-center gap-8 animate-rise">
              <div>
                <Label>Disposition</Label>
                <div className={`mt-2 stamp text-[56px] font-semibold tracking-[-0.035em] leading-[0.9] text-${t}`}>{p.overall_disposition}</div>
                <div className="mt-4 w-72"><div className="flex justify-between mb-1.5"><Label>Confidence</Label><span className="font-mono text-[12px]">{pct(p.overall_confidence)}</span></div><Meter v={p.overall_confidence} t="info" /></div>
              </div>
              <div className="ml-auto"><Seal signed={!!p.signature_hex} valid={v && !unsigned ? v.is_valid === true : undefined} /></div>
            </div>
            <p className="mt-6 font-serif text-[18px] leading-[1.45] text-ink max-w-2xl animate-rise" style={{ animationDelay: '.1s' }}>{p.executive_summary}</p>
            <dl className="mt-6 border-t border-line">
              <Row k="Audit" d={0.14}><span className="font-mono text-[11.5px]">{active.id}</span> · {active.label} · {time(active.completedAt)}</Row>
              <Row k="Assets" d={0.18}>{assets.length ? <div className="flex flex-wrap gap-1.5">{assets.map((a) => <span key={a} className="font-mono text-[10.5px] border border-line rounded-[3px] px-1.5 py-0.5">{a}</span>)}</div> : '—'}</Row>
              <Row k="Runtime" d={0.22}><span className="font-mono text-[11.5px]">{active.source === 'fixture' ? 'dev fixture' : 'local backend'} · embedder {status?.active_embedder ?? '—'}</span></Row>
              <Row k="Severity profile" d={0.26}><div className="flex gap-4">{sev.map(([s, n]) => <span key={s} className={`font-mono text-[11px] ${n ? `text-${tone(s)}` : 'text-faint'}`}>{n} {s.toLowerCase()}</span>)}</div></Row>
              <Row k={`Findings · ${p.findings_summary?.total ?? f.length}`} d={0.3}>
                <ul className="space-y-2">{f.map((x) => <li key={x.finding_id} className="flex items-start gap-3"><Tag v={x.severity} /><div className="min-w-0"><div className="text-ink-2">{x.reason}</div><div className="font-mono text-[10px] text-faint mt-0.5">{x.finding_id} · {x.module} · evidence {x.evidence ? 'attached' : 'none'}</div></div></li>)}</ul>
              </Row>
              <Row k="Limitations" d={0.34}>This passport records what the enabled modules detected with the evidence they had. Checks not run, or unavailable for this model's access level, are not covered. It certifies the evidence, not that the system is safe.</Row>
            </dl>
          </div>

          <aside className="px-6 py-7 bg-raised/30">
            <Label className="text-ink-2 mb-2">Integrity</Label>
            <div className="animate-rise" style={{ animationDelay: '.2s' }}>
              <Sig k="Signer public key · Ed25519" v={p.signer_public_key_hex} />
              <Sig k="Passport digest" v={p.passport_digest} />
              <Sig k="Signature" v={p.signature_hex} />
            </div>
            <div className={`mt-5 rounded-[4px] border p-4 transition-colors duration-500 ${v?.is_valid === true && !unsigned ? 'border-ok/40 bg-ok/[0.04]' : v?.is_valid === false ? 'border-crit/40 bg-crit/[0.04]' : 'border-line'}`}>
              <div className="flex items-center justify-between"><Label>Verification</Label><Tag v={integrity[0]} t={integrity[1]} /></div>
              <p className="mt-3 text-[12px] text-ink-2 min-h-8" aria-live="polite">{err ? <span className="font-mono text-crit">{err}</span> : v === undefined ? 'Send this passport to the backend verifier to check its Ed25519 signature against the digest.' : v === null || (unsigned && v.is_valid) ? 'This passport carries no signature, so it cannot be verified.' : v.message}</p>
              <Btn primary disabled={busy} onClick={verify} className="mt-4 w-full h-10 text-[12px]">{busy ? 'Verifying signature…' : v ? 'Verify again' : 'Verify passport'}</Btn>
            </div>
          </aside>
        </div>
      </article>
    </>
  )
}
