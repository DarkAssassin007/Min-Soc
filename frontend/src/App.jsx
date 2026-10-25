import { Navigate, Route, Routes } from 'react-router-dom'
import Sidebar from './components/layout/Sidebar.jsx'
import TopBar from './components/layout/TopBar.jsx'
import { Loading } from './components/common/States.jsx'
import { useAuth } from './hooks/useAuth.jsx'
import Login from './pages/Login.jsx'
import Dashboard from './pages/Dashboard/index.jsx'
import LiveMonitor from './pages/LiveMonitor/index.jsx'
import Alerts from './pages/Alerts/index.jsx'
import Incidents from './pages/Incidents/index.jsx'
import Network from './pages/Network/index.jsx'
import Threats from './pages/Threats/index.jsx'
import Analytics from './pages/Analytics/index.jsx'
import Investigation from './pages/Investigation/index.jsx'
import Reports from './pages/Reports/index.jsx'

export default function App() {
  const { user, status } = useAuth()

  if (!user && status === 'checking') {
    return (
      <div className="login-shell">
        <Loading label="Checking session…" />
      </div>
    )
  }

  if (!user) {
    return (
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    )
  }

  return (
    <div className="app-shell">
      <Sidebar />
      <div className="main">
        <Routes>
          <Route
            path="/"
            element={
              <Page title="Security Overview" subtitle="Current posture: events, alerts, incidents, risk">
                <Dashboard />
              </Page>
            }
          />
          <Route
            path="/live"
            element={
              <Page title="Live Network Monitor" subtitle="Streaming normalised events (WebSocket)">
                <LiveMonitor />
              </Page>
            }
          />
          <Route
            path="/alerts"
            element={
              <Page title="Alerts" subtitle="Detection results with triage and investigation actions">
                <Alerts />
              </Page>
            }
          />
          <Route
            path="/incidents"
            element={
              <Page title="Incidents" subtitle="Correlated alerts treated as one investigation">
                <Incidents />
              </Page>
            }
          />
          <Route
            path="/network"
            element={
              <Page title="Network Activity" subtitle="Traffic volume, talkers and targeted services">
                <Network />
              </Page>
            }
          />
          <Route
            path="/threats"
            element={
              <Page title="Threat Activity" subtitle="Who is attacking, how, and what they target">
                <Threats />
              </Page>
            }
          />
          <Route
            path="/analytics"
            element={
              <Page title="Analytics" subtitle="Historical trends across events, detections and alerts">
                <Analytics />
              </Page>
            }
          />
          <Route
            path="/investigation"
            element={
              <Page title="Investigation" subtitle="Event → detection → alert → incident trace">
                <Investigation />
              </Page>
            }
          />
          <Route
            path="/reports"
            element={
              <Page title="Reports" subtitle="Generated summaries for hand-off and review">
                <Reports />
              </Page>
            }
          />
          <Route path="/login" element={<Navigate to="/" replace />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>
    </div>
  )
}

function Page({ title, subtitle, children }) {
  return (
    <>
      <TopBar title={title} subtitle={subtitle} />
      <main className="content">{children}</main>
    </>
  )
}
