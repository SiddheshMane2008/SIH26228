import { useMemo, useState } from 'react'
import { api } from '../api/client'
import { Btn, Copy, Empty, Failure, Label, Loading, PageHead, Panel, Tag, tone } from '../components/ui'
import { useStore } from '../store'

type Kind = 'root' | 'dataset' | 'model' | 'inference'
interface N { id: string; kind: Kind; col: number; row: number }
const COLS: [Kind, string][] = [['root', 'Root'], ['dataset', 'Datasets'], ['model', 'Models'], ['inference', 'Inference']]
const kindOf = (id: string): Kind => (/^model/i.test(id) ? 'model' : /^inf/i.test(id) ? 'inference' : 'dataset')

/** Edges come from the backend's Mermaid source when parseable; otherwise columns are connected layer-to-layer and labelled as inferred. */
function parseEdges(m: string) {
  const out: (readonly [string, string | undefined, string, string | undefined])[] = []
  const node = (seg: string) => { const x = /^([^\s[({>"&]+)\s*(?:[[({>]+\s*"?(.*?)"?\s*[\])}]+)?\s*$/.exec(seg.trim()); return x ? { id: x[1], label: x[2]?.trim() || undefined } : undefined }
  for (const raw of (m ?? '').split(/\n|;/)) {
    const line = raw.replace(/%%.*$/, '').trim()
    if (!line || /^(graph|flowchart|subgraph|end|classDef|class|style|linkStyle|click|direction)\b/.test(line)) continue
    const segs = line.split(/\s*(?:--\s[^-]*?\s-->|==\s[^=]*?\s==>|<?[-.=]{2,}[->ox]?)(?:\|[^|]*\|)?\s*/).map((sg) => sg.split(/\s*&\s*/).map(node).filter((n): n is { id: string; label: string | undefined } => !!n))
    for (let i = 0; i + 1 < segs.length; i++) for (const a of segs[i]) for (const b of segs[i + 1]) out.push([a.id, a.label, b.id, b.label] as const)
  }
  return out
}

export default function Blast() {
  const { active, patchRun } = useStore()
  const guess = active?.passport?.top_findings?.find((f) => f.disposition === 'QUARANTINE')?.asset ?? ''
  const [root, setRoot] = useState(guess)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<unknown>()
  const [pick, setPick] = useState<string>()
  const [hide, setHide] = useState<Set<Kind>>(new Set())
  const [traced, setTraced] = useState<{ run: string; root: string }>()
  const d = active?.blast
  const tracedRoot = traced && traced.run === active?.id ? traced.root : undefined
  const go = async () => { const r = root.trim(); if (!active || busy || !r) return; setBusy(true); setErr(undefined); setPick(undefined); try { patchRun(active.id, { blast: await api.blastRadius(r) }); setTraced({ run: active.id, root: r }) } catch (e) { setErr(e) } finally { setBusy(false) } }

  const g = useMemo(() => {
    if (!d) return undefined
    const t = d.trace
    const ds = t?.affected_datasets ?? [], rootId = (typeof t?.root_id === 'string' && t.root_id) || tracedRoot || ds[0] || ''
    const seen = new Set<string>(); const uniq = (xs: string[] | undefined) => (xs ?? []).filter((x) => typeof x === 'string' && !seen.has(x) && !!seen.add(x))
    const lists: Record<Kind, string[]> = { root: uniq(rootId ? [rootId] : []), dataset: uniq(ds), model: uniq(t?.affected_models), inference: uniq(t?.affected_inference_records) }
    const nodes: N[] = COLS.flatMap(([k], c) => lists[k].map((id, row) => ({ id, kind: k, col: c, row })))
    const alias = new Map<string, string>(); const parsed = parseEdges(d.mermaid)
    parsed.forEach(([a, al, b, bl]) => { if (al) alias.set(a, al); if (bl) alias.set(b, bl) })
    const resolve = (k: string) => { const lbl = alias.get(k) ?? k; return (nodes.find((n) => n.id === lbl) ?? (lbl.includes(':') ? nodes.find((n) => n.id.startsWith(lbl) || lbl.startsWith(n.id)) : undefined))?.id }
    const ek = new Set<string>()
    let edges = parsed.map(([a, , b]) => [resolve(a), resolve(b)] as const).filter((e): e is readonly [string, string] => !!e[0] && !!e[1] && e[0] !== e[1] && !ek.has(e.join('\u0000')) && !!ek.add(e.join('\u0000')))
    const inferred = edges.length === 0
    if (inferred) edges = nodes.flatMap((n) => nodes.filter((m) => m.col === n.col + 1).map((m) => [n.id, m.id] as const))
    return { nodes, edges, inferred }
  }, [d, tracedRoot])

  const W = 1120, colW = 240, gap = (W - colW * 4) / 3, rowH = 52
  const rows = g ? Math.max(...COLS.map((_, c) => g.nodes.filter((n) => n.col === c).length), 1) : 1
  const H = rows * rowH + 44
  const pos = (n: N) => ({ x: n.col * (colW + gap), y: 44 + n.row * rowH })
  const byId = (id: string) => g?.nodes.find((n) => n.id === id)
  const down = (id: string, acc = new Set<string>()): Set<string> => { g?.edges.filter((e) => e[0] === id).forEach(([, b]) => { if (!acc.has(b)) { acc.add(b); down(b, acc) } }); return acc }
  const up = (id: string, acc = new Set<string>()): Set<string> => { g?.edges.filter((e) => e[1] === id).forEach(([a]) => { if (!acc.has(a)) { acc.add(a); up(a, acc) } }); return acc }
  const pickN = pick ? g?.nodes.find((n) => n.id === pick) : undefined
  const lit = pickN && pick ? new Set([pick, ...down(pick), ...up(pick)]) : undefined
  const related = (pick ? active?.passport?.top_findings?.filter((f) => !!f.asset && (f.asset === pick || pick.startsWith(f.asset) || f.asset.startsWith(pick))) : undefined) ?? []
  const vis = (n: N) => !hide.has(n.kind)

  return (
    <>
      <PageHead index="06" title="Blast radius" lede="Start from a compromised artefact and follow the lineage graph to every dataset, model and inference record that inherited from it." />
      <div className="flex gap-2 mb-5">
        <label className="sr-only" htmlFor="root">Root artefact id</label>
        <input id="root" value={root} onChange={(e) => setRoot(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && go()} placeholder="root artefact id, e.g. dataset:traffic-v3/shard-07"
          className="flex-1 h-8 bg-panel border border-line-strong rounded-[3px] px-3 font-mono text-[12px] placeholder:text-faint focus:outline-none focus:border-info transition-colors" />
        <Btn primary disabled={busy || !root.trim() || !active} onClick={go}>{busy ? 'Tracing…' : 'Trace'}</Btn>
      </div>
      {!active ? <Empty title="No active audit" hint="A blast-radius trace is attached to an audit. Run or select one first." />
        : busy ? <Loading label="Walking lineage graph…" />
        : err ? <Failure what="Blast radius trace" error={err} affected="Downstream impact for this root" retry={go} />
        : !d || !g ? <Empty title="No trace computed for this audit" hint={guess ? 'Pre-filled with the quarantined asset from the active passport.' : 'Enter a root artefact id to walk its lineage.'} />
        : (
          <div className="grid grid-cols-[1fr_300px] gap-5 max-[1200px]:grid-cols-1">
            <Panel title="Contamination graph" meta={<div className="flex items-center gap-3">{COLS.slice(1).map(([k, l]) => <button key={k} onClick={() => setHide((h) => { const s = new Set(h); s.has(k) ? s.delete(k) : s.add(k); return s })} className={`font-mono text-[10px] uppercase tracking-[0.12em] cursor-pointer transition-colors ${hide.has(k) ? 'text-faint line-through' : 'text-ink-2'}`}>{l}</button>)}<Tag v={d.trace?.severity} /></div>}>
              <p className="font-serif text-[15px] text-ink-2 mb-3">{d.trace?.description}</p>
              <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label="Blast radius graph">
                {COLS.map(([, l], c) => <text key={l} x={c * (colW + gap)} y={14} fill="#5a5f67" fontSize="10" letterSpacing="1.6" className="font-mono">{l.toUpperCase()} · {g.nodes.filter((n) => n.col === c).length}</text>)}
                {g.edges.map(([a, b], i) => {
                  const A = byId(a), B = byId(b); if (!A || !B || !vis(A) || !vis(B)) return null
                  const p = pos(A), q = pos(B), on = !lit || (lit.has(a) && lit.has(b))
                  return <path key={i} pathLength={1} className="draw" style={{ animationDelay: `${A.col * 0.25}s`, transition: 'opacity .3s' }} opacity={on ? 1 : 0.12} fill="none" stroke={on && lit ? '#e05a50' : 'rgb(224 90 80 / .35)'} strokeWidth={on && lit ? 1.4 : 1}
                    d={`M${p.x + colW} ${p.y + 16} C${p.x + colW + gap / 2} ${p.y + 16}, ${q.x - gap / 2} ${q.y + 16}, ${q.x} ${q.y + 16}`} />
                })}
                {g.nodes.filter(vis).map((n) => {
                  const p = pos(n), on = !lit || lit.has(n.id), sel = pick === n.id
                  return (
                    <g key={n.id} tabIndex={0} role="button" aria-label={n.id} onClick={() => setPick(sel ? undefined : n.id)} onKeyDown={(e) => e.key === 'Enter' && setPick(sel ? undefined : n.id)} className="cursor-pointer outline-none animate-fade" style={{ animationDelay: `${n.col * 0.22}s`, opacity: on ? 1 : 0.3, transition: 'opacity .3s' }}>
                      <rect x={p.x} y={p.y} width={colW} height={32} rx={4} fill={sel ? '#1b1f24' : '#15181c'} stroke={n.kind === 'root' ? '#e05a50' : sel ? '#e8e6e1' : 'rgb(255 255 255 / .13)'} />
                      <rect x={p.x} y={p.y} width={3} height={32} rx={1} fill={n.kind === 'root' ? '#e05a50' : n.kind === 'model' ? '#d8a547' : n.kind === 'inference' ? '#86a9c8' : '#858a92'} />
                      <text x={p.x + 12} y={p.y + 20} fill="#e8e6e1" fontSize="11" className="font-mono">{n.id.length > 32 ? n.id.slice(0, 31) + '…' : n.id}</text>
                    </g>
                  )
                })}
              </svg>
              {g.inferred && <p className="mt-2 font-mono text-[10px] text-warn">Edges inferred layer-to-layer. The backend's Mermaid output had no parseable edges.</p>}
            </Panel>
            <div className="space-y-5">
              <Panel title="Node inspector">
                {!pick || !pickN ? <p className="text-[12.5px] text-mute">Select a node to see what it depends on and what depends on it.</p> : (
                  <div key={pick} className="animate-fade space-y-4">
                    <div><Label>Identity</Label><div className="mt-1 flex items-center gap-1 font-mono text-[12px] break-all">{pick}<Copy v={pick} /></div><div className="mt-2"><Tag v={pickN.kind} t="info" /></div></div>
                    <div><Label>Downstream impact · {down(pick).size}</Label><ul className="mt-1.5 space-y-1">{[...down(pick)].map((x) => <li key={x} className="font-mono text-[10.5px] text-ink-2 truncate">→ {x}</li>)}{down(pick).size === 0 && <li className="text-[11.5px] text-faint">Terminal node</li>}</ul></div>
                    <div><Label>Upstream · {up(pick).size}</Label><ul className="mt-1.5 space-y-1">{[...up(pick)].map((x) => <li key={x} className="font-mono text-[10.5px] text-mute truncate">← {x}</li>)}</ul></div>
                    <div><Label>Findings on this asset</Label>{related.length ? related.map((f) => <div key={f.finding_id} className="mt-1.5 flex items-center gap-2"><Tag v={f.severity} t={tone(f.severity)} /><span className="text-[11.5px] text-ink-2 truncate">{f.reason}</span></div>) : <p className="mt-1 text-[11.5px] text-faint">None in active passport.</p>}</div>
                  </div>
                )}
              </Panel>
              <Panel title="Totals"><dl className="grid grid-cols-3 gap-3 font-mono">{[['datasets', d.trace?.affected_datasets?.length ?? 0], ['models', d.trace?.affected_models?.length ?? 0], ['inference', d.trace?.affected_inference_records?.length ?? 0]].map(([k, v]) => <div key={k}><div className="text-[20px]">{v}</div><div className="text-[10px] text-faint">{k}</div></div>)}</dl></Panel>
              <details className="border border-line rounded-[4px] bg-panel"><summary className="list-none cursor-pointer px-4 h-10 flex items-center font-mono text-[10px] uppercase tracking-[0.14em] text-mute">Mermaid source ›</summary><pre className="px-4 pb-4 font-mono text-[10.5px] text-ink-2 overflow-x-auto">{d.mermaid}</pre></details>
            </div>
          </div>
        )}
    </>
  )
}
