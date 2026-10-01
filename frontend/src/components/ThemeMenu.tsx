import { useEffect, useRef, useState } from 'react'
import { THEMES, useTheme } from '../theme'
import { Label } from './ui'

export function Swatch({ a, b, g, size = 'size-5' }: { a: string; b: string; g: string; size?: string }) {
  return <span className={`${size} rounded-full border border-white/15 shrink-0`} style={{ background: `conic-gradient(from 210deg, ${a}, ${b}, ${g} 70%, ${a})` }} />
}

export default function ThemeMenu() {
  const { theme, setTheme, ambient, setAmbient } = useTheme()
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const c = (e: MouseEvent) => !ref.current?.contains(e.target as Node) && setOpen(false)
    const k = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false)
    addEventListener('mousedown', c); addEventListener('keydown', k)
    return () => { removeEventListener('mousedown', c); removeEventListener('keydown', k) }
  }, [open])
  const cur = THEMES.find((t) => t[0] === theme) ?? THEMES[0]
  return (
    <div ref={ref} className="relative flex items-center px-3 border-l border-line">
      <button onClick={() => setOpen(!open)} aria-haspopup="menu" aria-expanded={open} aria-label="Colour mode"
        className="flex items-center gap-2 h-8 px-2 rounded-[3px] hover:bg-raised transition-colors cursor-pointer">
        <Swatch a={cur[2]} b={cur[3]} g={cur[4]} size="size-4" /><span className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-2">{cur[1]}</span>
      </button>
      {open && (
        <div role="menu" className="absolute right-2 top-[calc(100%+6px)] z-50 w-60 rounded-[5px] border border-line-strong bg-panel/95 backdrop-blur-md p-2 shadow-[0_24px_48px_-16px_rgb(0_0_0/0.8)] animate-rise">
          <Label className="px-2 pt-1 pb-2">Colour mode</Label>
          {THEMES.map(([k, l, a, b, g]) => (
            <button key={k} role="menuitemradio" aria-checked={theme === k} onClick={() => setTheme(k)}
              className={`w-full flex items-center gap-3 px-2 h-9 rounded-[3px] text-left text-[12.5px] transition-colors cursor-pointer ${theme === k ? 'bg-raised text-ink' : 'text-ink-2 hover:bg-raised/60'}`}>
              <Swatch a={a} b={b} g={g} /><span className="flex-1">{l}</span>
              <span className="h-1 w-10 rounded-full" style={{ background: `linear-gradient(90deg, ${a}, ${b})` }} />
            </button>
          ))}
          <div className="mt-2 pt-2 border-t border-line">
            <button role="menuitemcheckbox" aria-checked={ambient} onClick={() => setAmbient(!ambient)} className="w-full flex items-center justify-between px-2 h-9 rounded-[3px] text-[12.5px] text-ink-2 hover:bg-raised/60 cursor-pointer">
              Ambient motion
              <span className={`relative w-8 h-[18px] rounded-full transition-colors ${ambient ? 'bg-accent/70' : 'bg-line-strong'}`}><span className={`absolute top-[3px] size-3 rounded-full bg-ink transition-transform duration-300 ${ambient ? 'translate-x-[17px]' : 'translate-x-[3px]'}`} /></span>
            </button>
            <p className="px-2 pt-1 pb-1 text-[10.5px] text-faint leading-snug">Status colours (verified, review, critical) are the same in every mode.</p>
          </div>
        </div>
      )}
    </div>
  )
}
