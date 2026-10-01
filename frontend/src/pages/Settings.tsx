import { useState } from 'react'
import { api, BASE } from '../api/client'
import type { EmbedderInfo } from '../api/types'
import { Btn, Failure, KV, Label, Loading, PageHead, Panel, Tag, useLoad } from '../components/ui'
import { useStore } from '../store'
import { THEMES, useTheme } from '../theme'
import { Swatch } from '../components/ThemeMenu'

export default function Settings() {
  const { status, link, linkError, source, reprobe, refreshStatus } = useStore()
  const q = useLoad(() => api.embedders(), [source, status?.active_embedder])
  const th = useTheme()
  const [switching, setSwitching] = useState<string>()
  const [msg, setMsg] = useState<{ ok: boolean; text: string }>()
  const apply = async (n: string) => {
    setSwitching(n); setMsg(undefined)
    try { const r = await api.selectEmbedder(n); setMsg({ ok: true, text: `${r.selected_embedder} active · dimension ${r.dimension}. Run the audit again so results use this embedder.` }); await refreshStatus(); q.reload() }
    catch (e) { setMsg({ ok: false, text: (e as Error).message }) } finally { setSwitching(undefined) }
  }
  const state = (e: EmbedderInfo) => (!e.available ? ['Unavailable', 'na'] : e.name === status?.active_embedder ? ['Configured', 'ok'] : e.loaded ? ['Loaded', 'info'] : ['Not loaded', 'na'])
  return (
    <>
      <PageHead index="10" title="Settings" lede="Runtime configuration. Changes are applied on the local backend and show up in the system bar." />
      <div className="grid grid-cols-[1.3fr_1fr] gap-5 max-[1100px]:grid-cols-1">
        <Panel title="Default embedder" meta={status ? `active · ${status.active_embedder} · d${status.embedder_dimension}` : undefined} pad={false}>
          {q.loading ? <div className="p-4"><Loading label="Reading embedder inventory…" /></div> : q.error ? <div className="p-4"><Failure what="Embedder inventory" error={q.error} affected="Embedder list only. The active embedder from /api/status is still shown above." /></div> : (q.data?.embedders ?? []).map((e) => {
            const [l, t] = state(e)
            return (
              <div key={e.name} className={`flex items-center gap-4 px-4 py-3.5 border-b border-line last:border-0 transition-colors ${e.name === status?.active_embedder ? 'bg-raised/60' : ''} ${!e.available ? 'opacity-60' : ''}`}>
                <span className={`size-2 rounded-full ${e.name === status?.active_embedder ? 'bg-ok' : 'border border-line-strong'}`} />
                <div className="flex-1 min-w-0"><div className="font-mono text-[12.5px]">{e.name}</div><div className="text-[11px] text-faint">{e.dimension ? `dimension ${e.dimension}` : 'dimension unknown'}{e.note ? ` · ${e.note}` : ''}</div></div>
                <Tag v={l} t={t} />
                <Btn disabled={!e.available || e.name === status?.active_embedder || !!switching} onClick={() => apply(e.name)}>{switching === e.name ? 'Loading…' : 'Use'}</Btn>
              </div>
            )
          })}
          {msg && <p className={`px-4 py-3 border-t border-line font-mono text-[11px] animate-fade ${msg.ok ? 'text-ok' : 'text-crit'}`}>{msg.text}</p>}
        </Panel>
        <div className="space-y-5">
          <Panel title="Offline runtime" meta={<Btn onClick={reprobe}>Re-probe</Btn>}>
            <dl><KV k="Endpoint" v={BASE || 'same-origin'} /><KV k="Link" v={<Tag v={link} t={link === 'online' ? 'ok' : link === 'probing' ? 'info' : 'crit'} />} /><KV k="Data source" v={<span className={source === 'fixture' ? 'text-warn' : ''}>{source}</span>} />
              {Object.entries(status ?? {}).filter(([k, v]) => !['active_embedder', 'embedder_dimension', 'available_embedders'].includes(k) && typeof v !== 'object').map(([k, v]) => <KV key={k} k={k.replace(/_/g, ' ')} v={String(v)} />)}</dl>
            {linkError && <p className="mt-3 font-mono text-[10.5px] text-crit break-all">{linkError}</p>}
          </Panel>
          <Panel title="Appearance" meta="saved on this machine">
            <div className="grid grid-cols-5 gap-2">
              {THEMES.map(([k, l, a, b, g]) => (
                <button key={k} onClick={() => th.setTheme(k)} aria-pressed={th.theme === k} className={`group flex flex-col items-center gap-2 rounded-[4px] border p-2.5 transition-all cursor-pointer ${th.theme === k ? 'border-accent/60 bg-raised' : 'border-line hover:border-line-strong'}`}>
                  <Swatch a={a} b={b} g={g} size="size-7" /><span className="text-[10.5px] text-ink-2">{l}</span>
                </button>
              ))}
            </div>
            <label className="mt-4 flex items-center justify-between text-[12.5px] text-ink-2 cursor-pointer">Ambient gradient motion
              <input type="checkbox" checked={th.ambient} onChange={(e) => th.setAmbient(e.target.checked)} className="accent-[var(--color-accent)] size-4" /></label>
          </Panel>
          <Panel title="Verification & reports">
            <dl><KV k="Signature scheme" v="Ed25519 (backend)" /><KV k="Verifier" v="POST /api/passport/verify" /><KV k="Export format" v="Passport JSON" /></dl>
            <Label className="mt-3">Paths and report templates are set on the backend host.</Label>
          </Panel>
        </div>
      </div>
    </>
  )
}
