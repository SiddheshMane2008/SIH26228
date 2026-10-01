import { useEffect, useState } from 'react'

export const THEMES = [
  ['obsidian', 'Obsidian', '#86a9c8', '#9d8fd6', '#0a0b0d'],
  ['midnight', 'Midnight', '#7fa8ff', '#5ee0d0', '#070a12'],
  ['phosphor', 'Phosphor', '#7bd8a8', '#c6e36b', '#070b09'],
  ['ember', 'Ember', '#e8a36b', '#d86b8c', '#0d0a08'],
  ['ultraviolet', 'Ultraviolet', '#b39cff', '#ff8fc7', '#0a0810'],
] as const
export type ThemeKey = (typeof THEMES)[number][0]

const VALID: Record<string, readonly string[]> = { 'vg-theme': THEMES.map((t) => t[0]), 'vg-ambient': ['on', 'off'] }
const read = <T extends string>(k: string, d: T): T => {
  let v: string | null = null
  try { v = localStorage.getItem(k) } catch { /* storage unavailable */ }
  return v != null && (VALID[k]?.includes(v) ?? true) ? (v as T) : d
}
const save = (k: string, v: string) => { try { localStorage.setItem(k, v) } catch { /* storage unavailable */ } }
let listeners: (() => void)[] = []
const apply = () => {
  const el = document.documentElement
  el.dataset.theme = read('vg-theme', 'obsidian'); el.dataset.ambient = read('vg-ambient', 'on')
  listeners.forEach((l) => l())
}
apply()

export function useTheme() {
  const [, force] = useState(0)
  useEffect(() => { const l = () => force((n) => n + 1); listeners.push(l); return () => { listeners = listeners.filter((x) => x !== l) } }, [])
  return {
    theme: read<ThemeKey>('vg-theme', 'obsidian'), ambient: read('vg-ambient', 'on') === 'on',
    setTheme: (t: ThemeKey) => { save('vg-theme', t); apply() },
    setAmbient: (on: boolean) => { save('vg-ambient', on ? 'on' : 'off'); apply() },
  }
}
