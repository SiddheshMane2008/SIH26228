import { useRef, useState } from 'react'
import { api, sha256Hex } from '../api/client'
import type { Asset, AssetKind } from '../api/types'
import { FindingRow, Inspector } from '../components/Evidence'
import Icon from '../components/icons'
import { Assess, Btn, Empty, Hash, KV, Label, PageHead, Panel, Tabs, Tag, time } from '../components/ui'
import { useStore } from '../store'
import type { Finding } from '../api/types'

const KINDS = [['image', 'Image'], ['dataset', 'Dataset'], ['model', 'Model'], ['inference', 'Inference record']] as const
const ACCEPT: Record<AssetKind, RegExp> = { image: /\.(png|jpe?g|webp|bmp|tiff?)$/i, dataset: /\.(zip|tar|gz|tgz|csv|parquet|json|jsonl)$/i, model: /\.(onnx|pt|pth|safetensors|h5|tflite|pb)$/i, inference: /\.(json|jsonl|csv)$/i }
const MAX = 2 * 1024 ** 3
const STEPS = ['Drop', 'Validate', 'Hash', 'Register', 'Audit'] as const
const stepIdx = (a: Asset) => ({ validating: 1, hashing: 2, registering: 3, registered: 4, unregistered: 3, rejected: 1 })[a.stage]
const fmt = (n: number) => (n > 1024 ** 2 ? `${(n / 1024 ** 2).toFixed(2)} MB` : `${(n / 1024).toFixed(1)} KB`)

function Steps({ a }: { a: Asset }) {
  const cur = stepIdx(a), bad = a.stage === 'rejected' || a.stage === 'unregistered'
  return (
    <ol className="flex items-center gap-1.5">
      {STEPS.map((s, i) => {
        const done = i < cur || (i === cur && a.stage === 'registered'), now = i === cur && !done
        const c = now && bad ? (a.stage === 'rejected' ? 'text-crit border-crit/50' : 'text-warn border-warn/50') : done ? 'text-ok border-ok/40' : now ? 'text-info border-info/50' : 'text-faint border-line'
        return <li key={s} className="flex items-center gap-1.5"><span className={`h-5 px-1.5 rounded-[3px] border font-mono text-[9px] uppercase tracking-[0.12em] grid place-items-center transition-colors duration-300 ${c} ${now && !bad ? 'animate-breathe' : ''}`}>{s}</span>{i < STEPS.length - 1 && <span className={`w-2 h-px ${done ? 'bg-ok/50' : 'bg-line'}`} />}</li>
      })}
    </ol>
  )
}

function Workspace({ a }: { a: Asset }) {
  const [open, setOpen] = useState<Finding>()
  const an = a.registration?.analysis
  return (
    <div className="grid grid-cols-[1.1fr_1fr] gap-5 animate-rise max-[1100px]:grid-cols-1">
      <div className="relative rounded-[4px] border border-line bg-ground overflow-hidden">
        {a.preview ? <img src={a.preview} alt={`Uploaded image ${a.name}`} className="w-full max-h-[520px] object-contain bg-[#07080a]" /> : <div className="aspect-[4/3] grid place-items-center text-faint"><Icon n="image" className="size-8" /></div>}
        <div className="absolute left-3 top-3 flex gap-2"><Tag v="Evidence · input" t="info" /></div>
        <div className="absolute inset-x-0 bottom-0 bg-gradient-to-t from-black/80 to-transparent px-4 pt-8 pb-3 font-mono text-[10.5px] text-ink-2 flex justify-between"><span>{a.name}</span><span>{fmt(a.size)}</span></div>
      </div>
      <div className="space-y-4">
        <Panel title="Input identity"><dl>
          <KV k="SHA-256" v={<Hash v={a.sha256} n={14} />} /><KV k="Registration" v={a.registration?.registration_id ?? <span className="text-warn">not registered</span>} />
          <KV k="Expected label" v={an?.expected_label ?? <span className="text-faint">not supplied</span>} /><KV k="Observed / reference" v={an?.observed_label ?? <span className="text-faint">not reported</span>} />
        </dl></Panel>
        <Panel title="Analysis" meta="as reported by backend"><dl>
          <KV k="Embedding" v={<Assess v={an?.embedding} />} /><KV k="Duplicate check" v={<Assess v={an?.duplicate} />} />
          <KV k="OOD check" v={<Assess v={an?.ood} />} /><KV k="Trigger analysis" v={<Assess v={an?.trigger} />} />
        </dl>
          {!an && <p className="mt-3 text-[11.5px] text-faint">The backend has not returned an analysis for this asset, so every check reads Not evaluated.</p>}
        </Panel>
        {an?.findings && (an.findings.length ? <Panel title="Findings" pad={false}>{an.findings.map((f, i) => <FindingRow key={f.finding_id} f={f} i={i} onOpen={() => setOpen(f)} />)}</Panel> : <p className="text-[12px] text-mute px-1">The backend raised no findings for this input.</p>)}
      </div>
      <Inspector f={open} onClose={() => setOpen(undefined)} />
    </div>
  )
}

export default function Ingestion() {
  const { assets, setAssets, auditAssets, runs } = useStore()
  const reg = assets.filter((a) => a.stage === 'registered' && a.registration)
  const busy = runs.some((r) => r.state === 'running')
  const [kind, setKind] = useState<AssetKind>('image')
  const [over, setOver] = useState(false)
  const [sel, setSel] = useState<string>()
  const input = useRef<HTMLInputElement>(null)
  const patch = (key: string, p: Partial<Asset>) => setAssets((x) => x.map((y) => (y.key === key ? { ...y, ...p } : y)))

  const add = async (files: FileList | null) => {
    for (const file of Array.from(files ?? [])) {
      const key = `${file.name}-${file.size}-${performance.now()}`
      const a: Asset = { key, name: file.name, size: file.size, format: file.name.split('.').pop()?.toUpperCase() ?? '—', kind, addedAt: new Date().toISOString(), stage: 'validating', preview: kind === 'image' && file.type.startsWith('image/') ? URL.createObjectURL(file) : undefined }
      setAssets((x) => [a, ...x]); setSel(key)
      if (!ACCEPT[kind].test(file.name) || file.size === 0 || file.size > MAX) { patch(key, { stage: 'rejected', error: file.size === 0 ? 'Empty file' : file.size > MAX ? 'Exceeds 2 GB limit' : `.${a.format.toLowerCase()} is not an accepted ${kind} format` }); continue }
      patch(key, { stage: 'hashing' })
      let sha: string
      try { sha = await sha256Hex(await file.arrayBuffer()) }
      catch (e) { patch(key, { stage: 'rejected', error: `Hashing failed: ${(e as Error).message}` }); continue }
      patch(key, { stage: 'registering', sha256: sha })
      try { patch(key, { stage: 'registered', registration: await api.ingest(file, kind, sha) }) }
      catch (e) { patch(key, { stage: 'unregistered', error: (e as Error).message }) }
    }
  }
  const s = assets.find((a) => a.key === sel)
  return (
    <>
      <PageHead index="01" title="Ingestion & custody" lede="Each file is checked and SHA-256 hashed in the browser, then registered with the local backend. It never leaves this machine." right={<Tabs tabs={KINDS} value={kind} onChange={setKind} />} />
      <div onDragOver={(e) => { e.preventDefault(); setOver(true) }} onDragLeave={() => setOver(false)} onDrop={(e) => { e.preventDefault(); setOver(false); add(e.dataTransfer.files) }}
        className={`relative rounded-[4px] border border-dashed transition-all duration-300 overflow-hidden ${over ? 'border-info bg-info/[0.05] scale-[1.004]' : 'border-line-strong bg-panel/60'}`}>
        <div className="absolute inset-0 hatch opacity-60" />
        {over && <div className="absolute inset-x-0 top-0 h-px bg-info animate-scan" />}
        <button onClick={() => input.current?.click()} className="relative w-full py-12 flex flex-col items-center cursor-pointer" aria-label={`Select ${kind} files to ingest`}>
          <span className={`size-12 grid place-items-center rounded-full border transition-all duration-300 ${over ? 'border-info text-info -translate-y-1' : 'border-line-strong text-mute'}`}><Icon n={kind} className="size-5" /></span>
          <div className="mt-4 font-serif italic text-[20px] text-ink-2">{over ? 'Release to ingest' : `Drop ${KINDS.find((k) => k[0] === kind)![1].toLowerCase()} files here`}</div>
          <Label className="mt-2">or click to browse · {ACCEPT[kind].source.replace(/\\\.|\(|\)|\$|\/i/g, '').split('|').slice(0, 5).join(' · ')}</Label>
        </button>
        <input ref={input} type="file" multiple className="sr-only" onChange={(e) => { add(e.target.files); e.target.value = '' }} />
      </div>

      <div className="mt-5">
        {assets.length === 0 ? <Empty title="Custody ledger is empty" hint="Every file you ingest gets a SHA-256 digest and a registration ID from the backend." /> : (
          <>
          {reg.length > 0 && (
            <div className="mb-4 flex items-center gap-4 rounded-[4px] border border-accent/30 bg-accent/[0.05] px-4 py-3 animate-rise">
              <span className="size-2 rounded-full bg-accent animate-breathe" />
              <div className="flex-1"><div className="text-[13px]">{reg.length} registered asset{reg.length > 1 ? 's' : ''} ready to audit</div><div className="font-mono text-[10.5px] text-faint mt-0.5">{reg.map((a) => a.registration!.registration_id).join(' · ')}</div></div>
              <Btn primary disabled={busy} onClick={() => auditAssets(reg.map((a) => a.registration!.registration_id))}>{busy ? 'Audit running…' : 'Start audit →'}</Btn>
            </div>
          )}
          <Panel title="Custody ledger" meta={`${assets.length} artefact(s)`} pad={false}>
            {assets.map((a) => (
              <details key={a.key} open={a.key === sel} className="group border-b border-line last:border-0">
                <summary onClick={(e) => { e.preventDefault(); setSel(a.key === sel ? undefined : a.key) }} className={`list-none cursor-pointer grid grid-cols-[20px_1.2fr_80px_1fr_auto] items-center gap-4 px-4 py-3 hover:bg-raised/50 transition-colors ${a.key === sel ? 'bg-raised/60' : ''}`}>
                  <span className="text-mute"><Icon n={a.kind} className="size-3.5" /></span>
                  <div className="min-w-0"><div className="text-[13px] truncate">{a.name}</div><div className="font-mono text-[10px] text-faint">{a.format} · {fmt(a.size)} · {time(a.addedAt)}</div></div>
                  <span className="font-mono text-[10px] uppercase text-mute">{a.kind}</span>
                  <div className="font-mono text-[11px] truncate">{a.sha256 ? <span className="text-ink-2">{a.sha256.slice(0, 16)}…</span> : a.stage === 'hashing' ? <span className="text-info animate-breathe">hashing…</span> : <span className="text-faint">—</span>}</div>
                  <Steps a={a} />
                </summary>
                <div className="px-4 pb-4 pl-12 grid grid-cols-2 gap-6 animate-fade">
                  <dl><KV k="Filename" v={a.name} /><KV k="Size" v={`${a.size.toLocaleString()} bytes`} /><KV k="Format" v={a.format} /><KV k="SHA-256" v={<Hash v={a.sha256} n={16} />} /></dl>
                  <dl><KV k="Registration ID" v={a.registration?.registration_id} /><KV k="Registered at" v={a.registration?.registered_at} /><KV k="Status" v={<Tag v={a.stage} t={a.stage === 'registered' ? 'ok' : a.stage === 'rejected' ? 'crit' : a.stage === 'unregistered' ? 'warn' : 'info'} />} />
                    {a.error && <p className="mt-2 font-mono text-[10.5px] text-warn break-all">{a.error}</p>}</dl>
                </div>
              </details>
            ))}
          </Panel>
          </>
        )}
      </div>
      {s?.kind === 'image' && s.sha256 && <div className="mt-6"><Label className="mb-3">Image evidence workspace</Label><Workspace a={s} /></div>}
    </>
  )
}
