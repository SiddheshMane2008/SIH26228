import { useStore } from '../store'
import Icon from './icons'

const C: Record<string, string> = { ok: 'border-ok/40 text-ok', warn: 'border-warn/40 text-warn', crit: 'border-crit/45 text-crit', info: 'border-accent/40 text-accent' }
export default function Toasts() {
  const { toasts, dismiss } = useStore()
  return (
    <div className="fixed bottom-5 right-5 z-[70] flex flex-col gap-2 w-[340px]" aria-live="polite">
      {toasts.map((t) => (
        <div key={t.id} role="status" className={`relative overflow-hidden rounded-[4px] border bg-panel/95 backdrop-blur-md px-4 py-3 shadow-[0_20px_40px_-16px_rgb(0_0_0/0.8)] drawer-in ${C[t.tone] ?? C.info}`}>
          <div className="flex items-start gap-3">
            <Icon n={t.tone === 'ok' ? 'check' : t.tone === 'info' ? 'check' : 'alert'} className="size-4 mt-0.5 shrink-0" />
            <div className="flex-1 min-w-0"><div className="font-mono text-[10.5px] uppercase tracking-[0.14em]">{t.title}</div>{t.body && <div className="mt-1 text-[12px] text-ink-2 break-words">{t.body}</div>}</div>
            <button onClick={() => dismiss(t.id)} aria-label="Dismiss" className="text-faint hover:text-ink cursor-pointer"><Icon n="close" className="size-3.5" /></button>
          </div>
          <span className="absolute bottom-0 left-0 h-px w-full bg-current opacity-50 origin-left" style={{ animation: 'toastbar 5.2s linear forwards' }} />
        </div>
      ))}
    </div>
  )
}
