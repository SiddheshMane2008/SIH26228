import { useEffect, useMemo, useRef, useState } from 'react'
import { SCENARIOS } from '../api/scenarios'
import { useStore } from '../store'
import { THEMES, useTheme } from '../theme'
import Icon from './icons'
import { NAV, type PageKey } from './Shell'

interface Cmd { id: string; label: string; hint: string; icon: string; run: () => void }

export default function Palette({ go }: { go: (p: PageKey) => void }) {
  const [open, setOpen] = useState(false)
  const [q, setQ] = useState('')
  const [i, setI] = useState(0)
  const inp = useRef<HTMLInputElement>(null)
  const { run, runs, link, source } = useStore()
  const { setTheme } = useTheme()
  const busy = runs.some((r) => r.state === 'running')
  const ready = (link === 'online' || source === 'fixture') && !busy

  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setOpen((o) => !o); setQ(''); setI(0) }
      const el = e.target as HTMLElement
      const typing = /INPUT|TEXTAREA|SELECT/.test(el.tagName) || el.isContentEditable
      if (!typing && !e.metaKey && !e.ctrlKey && e.key === '/') { e.preventDefault(); setOpen(true); setQ(''); setI(0) }
    }
    const o = () => { setOpen(true); setQ(''); setI(0) }
    addEventListener('keydown', k); addEventListener('vg-palette', o); return () => { removeEventListener('keydown', k); removeEventListener('vg-palette', o) }
  }, [])
  useEffect(() => {
    if (!open) return
    const prev = document.activeElement as HTMLElement | null
    const t = setTimeout(() => inp.current?.focus(), 0)
    return () => { clearTimeout(t); prev?.focus?.() }
  }, [open])

  const cmds = useMemo<Cmd[]>(() => [
    ...NAV.map(([k, l], n) => ({ id: `nav-${k}`, label: `Go to ${l}`, hint: n < 9 ? `G ${n + 1}` : '', icon: k === 'shift' ? 'shift' : k, run: () => go(k) })),
    ...(ready ? SCENARIOS.map((s) => ({ id: `run-${s.id}`, label: `Run ${s.code} · ${s.label}`, hint: 'audit', icon: 'overview', run: () => { run(s.id); go('overview') } })) : []),
    ...THEMES.map(([k, l]) => ({ id: `theme-${k}`, label: `Colour mode · ${l}`, hint: 'theme', icon: 'settings', run: () => setTheme(k) })),
  ], [go, ready, run, setTheme])
  const list = cmds.filter((c) => c.label.toLowerCase().includes(q.toLowerCase()))
  const pick = (c?: Cmd) => { if (!c) return; c.run(); setOpen(false) }

  if (!open) return null
  return (
    <div className="fixed inset-0 z-[80] flex items-start justify-center pt-[14vh]" onKeyDown={(e) => {
      if (e.key === 'Escape') { e.stopPropagation(); setOpen(false) }
      if (e.key === 'ArrowDown') { e.preventDefault(); setI((x) => Math.min(list.length - 1, x + 1)) }
      if (e.key === 'ArrowUp') { e.preventDefault(); setI((x) => Math.max(0, x - 1)) }
      if (e.key === 'Enter') { e.preventDefault(); pick(list[Math.min(i, list.length - 1)]) }
      if (e.key === 'Tab') { e.preventDefault(); inp.current?.focus() }
    }}>
      <div className="absolute inset-0 bg-black/55 animate-fade" onClick={() => setOpen(false)} />
      <div role="dialog" aria-modal="true" aria-label="Command palette" className="edge relative w-[560px] rounded-[6px] border border-line bg-panel/95 backdrop-blur-md shadow-[0_40px_80px_-24px_rgb(0_0_0/0.9)] animate-rise">
        <div className="flex items-center gap-3 px-4 h-12 border-b border-line">
          <Icon n="search" className="size-4 text-mute" />
          <input ref={inp} value={q} onChange={(e) => { setQ(e.target.value); setI(0) }} placeholder="Jump to a module, run a scenario, change colour mode…" aria-label="Command"
            className="flex-1 bg-transparent text-[14px] placeholder:text-faint focus:outline-none" />
          <kbd className="font-mono text-[10px] text-faint border border-line rounded px-1.5 py-0.5">ESC</kbd>
        </div>
        <ul role="listbox" className="max-h-[360px] overflow-y-auto p-1.5">
          {list.map((c, n) => (
            <li key={c.id} role="option" aria-selected={n === i}>
              <button onMouseEnter={() => setI(n)} onClick={() => pick(c)} className={`w-full flex items-center gap-3 px-3 h-9 rounded-[3px] text-left text-[13px] cursor-pointer transition-colors ${n === i ? 'bg-raised text-ink' : 'text-ink-2'}`}>
                <span className={n === i ? 'text-accent' : 'text-faint'}><Icon n={c.icon} className="size-[15px]" /></span>
                <span className="flex-1 truncate">{c.label}</span>
                {c.hint && <span className="font-mono text-[10px] text-faint">{c.hint}</span>}
              </button>
            </li>
          ))}
          {list.length === 0 && <li className="px-3 py-6 text-center text-[12.5px] text-mute">No command matches “{q}”.</li>}
        </ul>
        <div className="flex items-center gap-4 px-4 h-9 border-t border-line font-mono text-[10px] text-faint">
          <span>↑↓ navigate</span><span>↵ select</span><span className="ml-auto">⌘K / Ctrl K · G then 1–9 to jump</span>
        </div>
      </div>
    </div>
  )
}
