import { useEffect, useState, type ReactNode } from 'react'
import { useStore } from '../store'
import Icon from './icons'
import ThemeMenu from './ThemeMenu'
import Toasts from './Toasts'
import Palette from './Palette'
import { Dot, Label, short } from './ui'

export const NAV = [
  ['overview', 'Overview', 'Assure'], ['ingestion', 'Ingestion', 'Assure'],
  ['sentinel', 'Data Sentinel', 'Analyse'], ['auditor', 'Model Auditor', 'Analyse'], ['provenance', 'Provenance', 'Analyse'], ['shift', 'Shift Diagnostician', 'Analyse'], ['blast', 'Blast Radius', 'Analyse'], ['redteam', 'Red-Team', 'Analyse'],
  ['passport', 'Trust Passport', 'Attest'], ['history', 'Audit History', 'Attest'], ['settings', 'Settings', 'System'],
] as const
export type PageKey = (typeof NAV)[number][0]
const ICON: Record<PageKey, string> = { overview: 'overview', ingestion: 'ingestion', sentinel: 'sentinel', auditor: 'auditor', provenance: 'provenance', shift: 'shift', blast: 'blast', redteam: 'redteam', passport: 'passport', history: 'history', settings: 'settings' }

export function Mark({ className = 'size-6' }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="none" stroke="currentColor" strokeWidth="1.3">
      <path d="M12 2.5 20 6v6c0 4.6-3.3 8.3-8 9.5C7.3 20.3 4 16.6 4 12V6l8-3.5Z" />
      <circle cx="12" cy="11.5" r="3" /><circle cx="12" cy="11.5" r=".8" fill="currentColor" />
    </svg>
  )
}

function Clock() {
  const [t, setT] = useState(() => new Date())
  useEffect(() => { const id = setInterval(() => setT(new Date()), 1000); return () => clearInterval(id) }, [])
  return <>{t.toISOString().slice(11, 19)}Z</>
}

function Cell({ k, children, t }: { k: string; children: ReactNode; t?: string }) {
  return (
    <div className="flex flex-col justify-center gap-[3px] px-4 border-l border-line h-full min-w-0">
      <span className="font-mono text-[9px] uppercase tracking-[0.18em] text-faint leading-none">{k}</span>
      <span className={`font-mono text-[11px] leading-none truncate ${t ?? 'text-ink-2'}`}>{children}</span>
    </div>
  )
}

function Boot() {
  const { link } = useStore()
  const lines = ['Loading assurance console', 'Probing local backend', link === 'probing' ? 'Awaiting response' : link === 'online' ? 'Backend linked' : 'Backend unreachable']
  return (
    <div className="fixed inset-0 z-[60] grid place-items-center bg-ground animate-fade" role="status" aria-live="polite">
      <div className="w-72">
        <div className="flex items-center gap-3 text-ink boot"><span className="text-accent"><Mark className="size-8" /></span><div><div className="text-[17px] font-semibold tracking-[-0.01em]">VisionGuard</div><Label className="mt-0.5">Assurance console</Label></div></div>
        <div className="mt-6 space-y-1.5">{lines.map((l, i) => <div key={l} className="boot font-mono text-[11px] text-mute flex items-center gap-2" style={{ animationDelay: `${0.15 + i * 0.18}s` }}><span className="text-faint">{String(i + 1).padStart(2, '0')}</span>{l}</div>)}</div>
        <div className="relative mt-5 h-px bg-line overflow-hidden"><div className="absolute inset-y-0 w-1/3 bg-info animate-scan" /></div>
      </div>
    </div>
  )
}

export default function Shell({ page, go, children }: { page: PageKey; go: (p: PageKey) => void; children: ReactNode }) {
  const { link, source, status, active, runs, booted } = useStore()
  const [collapsed, setCollapsed] = useState(() => { const s = localStorage.getItem('vg-nav'); return s ? s === 'min' : innerWidth < 1300 })
  useEffect(() => { localStorage.setItem('vg-nav', collapsed ? 'min' : 'full') }, [collapsed])
  // "G" then 1–9: jump to section.
  useEffect(() => {
    let armed = 0
    const k = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement
      if (/INPUT|TEXTAREA|SELECT/.test(el.tagName) || el.isContentEditable || e.metaKey || e.ctrlKey || e.altKey || e.repeat) return
      if (document.querySelector('[aria-modal="true"]')) return
      if (e.key.toLowerCase() === 'g') { armed = Date.now(); return }
      if (Date.now() - armed < 900 && /^[1-9]$/.test(e.key)) { go(NAV[+e.key - 1][0]); armed = 0 }
      if (e.key === '[') setCollapsed((c) => !c)
    }
    addEventListener('keydown', k); return () => removeEventListener('keydown', k)
  }, [go])
  const flagged = runs.filter((r) => r.passport && r.passport.overall_disposition !== 'CLEAR').length
  const groups = [...new Set(NAV.map((n) => n[2]))]
  const sys = link === 'online' ? ['Nominal', 'text-ok'] : link === 'probing' ? ['Probing', 'text-info'] : source === 'fixture' ? ['Dev fixture', 'text-warn'] : ['Unreachable', 'text-crit']
  return (
    <>
      {!booted && <Boot />}
      <Toasts />
      <Palette go={go} />
      <div className={`h-full grid grid-rows-[48px_1fr] transition-[grid-template-columns] duration-300 ${collapsed ? 'grid-cols-[56px_1fr]' : 'grid-cols-[220px_1fr]'}`}>
        <aside className="row-span-2 border-r border-line bg-panel flex flex-col boot overflow-hidden" style={{ animationDelay: '.05s' }}>
          <div className="h-12 flex items-center gap-2.5 px-4 border-b border-line text-ink">
            <span className="text-accent"><Mark /></span>
            {!collapsed && <div className="whitespace-nowrap"><div className="text-[14px] font-semibold tracking-[-0.01em] leading-none text-grad">VisionGuard</div><div className="font-mono text-[9px] tracking-[0.18em] text-faint mt-1">AI ASSURANCE CONSOLE</div></div>}
          </div>
          <nav aria-label="Primary" className="flex-1 overflow-y-auto py-2">
            {groups.map((g) => (
              <div key={g} className="py-1.5">
                {collapsed ? <div className="mx-4 my-1.5 h-px bg-line" /> : <div className="px-4 pb-1 pt-1 font-mono text-[9px] uppercase tracking-[0.2em] text-faint">{g}</div>}
                {NAV.filter((n) => n[2] === g).map(([k, label]) => (
                  <button key={k} onClick={() => go(k)} aria-current={page === k ? 'page' : undefined} title={collapsed ? label : undefined} aria-label={label}
                    className={`group relative w-full flex items-center gap-2.5 px-4 h-8 text-left text-[13px] transition-colors cursor-pointer ${page === k ? 'text-ink bg-raised' : 'text-mute hover:text-ink-2 hover:bg-raised/40'}`}>
                    <span className={`absolute left-0 top-1.5 bottom-1.5 w-[2px] bar-grad transition-transform duration-300 ${page === k ? 'scale-y-100' : 'scale-y-0'}`} />
                    <span className={`transition-colors ${page === k ? 'text-accent' : 'text-faint group-hover:text-mute'}`}><Icon n={ICON[k]} className="size-[15px]" /></span>
                    {!collapsed && <span className="truncate whitespace-nowrap">{label}</span>}
                    {!collapsed && k === 'history' && flagged > 0 && <span className="ml-auto font-mono text-[10px] text-warn">{flagged}</span>}
                    {k === 'overview' && active?.state === 'running' && <span className={collapsed ? 'absolute right-2 top-2' : 'ml-auto'}><Dot t="info" pulse /></span>}
                  </button>
                ))}
              </div>
            ))}
          </nav>
          {!collapsed && <div className="border-t border-line p-4">
            <div className="flex items-center gap-2"><Icon n="sentinel" className="size-3.5 text-mute" /><Label>Custody</Label></div>
            <p className="mt-2 text-[11px] leading-relaxed text-faint">Computation stays on this host. Passports are signed by the backend and verifiable offline.</p>
          </div>}
          <div className="border-t border-line flex">
            <button onClick={() => dispatchEvent(new Event('vg-palette'))} title="Command palette (⌘K)" className="flex-1 flex items-center gap-2 px-4 h-10 text-mute hover:text-ink cursor-pointer"><Icon n="search" className="size-3.5" />{!collapsed && <><span className="text-[12px]">Search</span><kbd className="ml-auto font-mono text-[9.5px] text-faint border border-line rounded px-1">⌘K</kbd></>}</button>
            <button onClick={() => setCollapsed(!collapsed)} aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'} title="Toggle sidebar ( [ )" className="w-10 grid place-items-center border-l border-line text-mute hover:text-ink cursor-pointer"><span className={`transition-transform duration-300 ${collapsed ? '' : 'rotate-180'}`}><Icon n="arrow" className="size-3.5" /></span></button>
          </div>
        </aside>

        <header className="relative flex items-stretch border-b border-line bg-ground overflow-hidden boot" style={{ animationDelay: '.12s' }}>
          {active?.state === 'running' && <span className="absolute bottom-0 left-0 h-px w-1/3 bar-grad animate-scan" />}
          <span className="absolute bottom-0 inset-x-0 h-px opacity-40 bar-grad" />
          <div className="flex items-center gap-2.5 px-4">
            <Dot t={link === 'online' ? 'ok' : link === 'probing' ? 'info' : source === 'fixture' ? 'warn' : 'crit'} pulse={link !== 'offline'} />
            <span className="font-mono text-[10.5px] uppercase tracking-[0.16em] text-ink">{link === 'online' ? 'Air-gapped' : 'Link'}</span>
          </div>
          <Cell k="System" t={sys[1]}>{sys[0]}</Cell>
          <Cell k="Runtime" t={source === 'fixture' ? 'text-warn' : undefined}>{source === 'fixture' ? 'Fixture · no backend' : link === 'online' ? 'Local' : '—'}</Cell>
          <Cell k="Model">{status ? `${status.active_embedder}` : '—'}</Cell>
          <Cell k="Active audit" t={active?.state === 'running' ? 'text-info' : undefined}>{active ? `${active.state === 'running' ? 'Running · ' : ''}${active.label}` : 'None'}</Cell>
          <div className="ml-auto" />
          <Cell k="Audit ID">{active ? short(active.id, 14) : '—'}</Cell>
          <Cell k="UTC"><Clock /></Cell>
          <ThemeMenu />
        </header>

        <main className="overflow-y-auto grain relative" id="main">
          <div className="pointer-events-none absolute inset-x-0 top-0 h-[560px] aurora" />
          {source === 'fixture' && (
            <div className="sticky top-0 z-20 hatch bg-[#1b1710]/95 border-b border-warn/30 px-8 py-1.5 font-mono text-[10px] uppercase tracking-[0.14em] text-warn flex items-center gap-2">
              <Icon n="alert" className="size-3" />Dev fixtures active — VITE_VISIONGUARD_API unset and backend unreachable. Nothing shown is evidence.
            </div>
          )}
          <div className="relative max-w-[1240px] mx-auto px-8 py-7 max-[1300px]:px-6">{children}</div>
        </main>
      </div>
    </>
  )
}
