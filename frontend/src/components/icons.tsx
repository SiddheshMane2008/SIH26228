// Compact 16px line icons, 1.3 stroke, drawn for this console.
const P: Record<string, string> = {
  overview: 'M2.5 2.5h4.5v4.5h-4.5zM9 2.5h4.5v7H9zM2.5 9h4.5v4.5h-4.5zM9 11.5h4.5v2H9z',
  ingestion: 'M8 2v8M5 7l3 3 3-3M2.5 11v2.5h11V11',
  sentinel: 'M8 1.8 13.5 4v4c0 3.2-2.3 5.6-5.5 6.4C4.8 13.6 2.5 11.2 2.5 8V4L8 1.8ZM5.6 8l1.7 1.7L10.5 6.4',
  auditor: 'M6.8 11.6a4.8 4.8 0 1 0 0-9.6 4.8 4.8 0 0 0 0 9.6ZM10.3 10.3 14 14M4.8 6.8h4M6.8 4.8v4',
  provenance: 'M5 5.5 3.4 7.1a2.3 2.3 0 0 0 3.3 3.3L8.3 8.8M11 10.5l1.6-1.6a2.3 2.3 0 0 0-3.3-3.3L7.7 7.2M6 10l4-4',
  shift: 'M1.5 12.5c2-.1 2.6-6 4.3-6s2 3.6 3.5 3.6 1.9-6.6 5.2-7.6M1.5 14.5h13',
  blast: 'M8 8m-1.4 0a1.4 1.4 0 1 0 2.8 0 1.4 1.4 0 1 0-2.8 0M8 8m-4 0a4 4 0 1 0 8 0 4 4 0 1 0-8 0M8 8m-6.3 0a6.3 6.3 0 1 0 12.6 0 6.3 6.3 0 1 0-12.6 0',
  redteam: 'M8 1.5v3M8 11.5v3M1.5 8h3M11.5 8h3M8 8m-3.5 0a3.5 3.5 0 1 0 7 0 3.5 3.5 0 1 0-7 0',
  passport: 'M3.5 1.8h9v12.4h-9zM6 5.2h4M6 7.4h4M8 12a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3Z',
  history: 'M2.2 8a5.8 5.8 0 1 0 1.7-4.1M2.2 2.2v2.7h2.7M8 4.8V8l2.2 1.4',
  settings: 'M2 4.5h7M12 4.5h2M2 11.5h2M7 11.5h7M10.5 4.5m-1.5 0a1.5 1.5 0 1 0 3 0 1.5 1.5 0 1 0-3 0M5.5 11.5m-1.5 0a1.5 1.5 0 1 0 3 0 1.5 1.5 0 1 0-3 0',
  copy: 'M5.5 5.5h8v8h-8zM10.5 5.5v-3h-8v8h3',
  check: 'M3 8.5l3 3 7-7',
  close: 'M4 4l8 8M12 4l-8 8',
  arrow: 'M3 8h10M9 4l4 4-4 4',
  image: 'M2 3h12v10H2zM2 11l3.5-3.5 3 3 2-2L14 12M10.5 6a1 1 0 1 0 0-.01',
  dataset: 'M8 2c3.3 0 5.5.9 5.5 2S11.3 6 8 6 2.5 5.1 2.5 4 4.7 2 8 2ZM2.5 4v8c0 1.1 2.2 2 5.5 2s5.5-.9 5.5-2V4M2.5 8c0 1.1 2.2 2 5.5 2s5.5-.9 5.5-2',
  model: 'M8 1.8 14 5v6l-6 3.2L2 11V5l6-3.2ZM2 5l6 3.2L14 5M8 8.2v6',
  inference: 'M2 8h3l1.5-4 3 8L11 8h3',
  alert: 'M8 2 14.5 13.5h-13L8 2ZM8 6.5v3.2M8 11.6v.1',
  search: 'M7 12a5 5 0 1 0 0-10 5 5 0 0 0 0 10ZM10.7 10.7 14 14',
}
export default function Icon({ n, className = 'size-4' }: { n: string; className?: string }) {
  return <svg viewBox="0 0 16 16" className={className} fill="none" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d={P[n]} /></svg>
}
