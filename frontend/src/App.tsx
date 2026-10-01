import { useState } from 'react'
import Shell, { type PageKey } from './components/Shell'
import Auditor from './pages/Auditor'
import Blast from './pages/Blast'
import Sentinel from './pages/Findings'
import History from './pages/History'
import Ingestion from './pages/Ingestion'
import Overview from './pages/Overview'
import Passport from './pages/Passport'
import Provenance from './pages/Provenance'
import RedTeam from './pages/RedTeam'
import Settings from './pages/Settings'
import Shift from './pages/Shift'
import { StoreProvider } from './store'

export default function App() {
  const [page, setPage] = useState<PageKey>('overview')
  const go = (p: PageKey) => { setPage(p); document.getElementById('main')?.scrollTo({ top: 0 }) }
  const view = {
    overview: <Overview go={go} />, ingestion: <Ingestion />, sentinel: <Sentinel />, auditor: <Auditor />, provenance: <Provenance />, shift: <Shift />,
    blast: <Blast />, redteam: <RedTeam />, passport: <Passport go={go} />, history: <History go={go} />, settings: <Settings />,
  }[page]
  return <StoreProvider><Shell page={page} go={go}><div key={page} className="animate-fade">{view}</div></Shell></StoreProvider>
}
