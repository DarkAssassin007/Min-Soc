import { useApi } from '../../hooks/useApi.js'
import { useAuth } from '../../hooks/useAuth.jsx'
import { formatDuration, formatNumber } from '../../utils/format.js'
import { LiveDot } from '../common/States.jsx'

export function TopBar({ title, subtitle, actions }) {
  const { user, logout } = useAuth()
  const { data: metrics } = useApi('/system/metrics', { pollMs: 10000, params: { history: 0 } })
  const { data: health } = useApi('/system/health', { pollMs: 30000 })
  const { data: ws } = useApi('/system/metrics', { pollMs: 30000, params: { history: 0 } })

  const pipelineRunning = metrics?.pipeline?.running
  const collectors = metrics?.pipeline?.collectors || {}
  const liveCollectors = Object.entries(collectors)
    .filter(([, entry]) => entry.running)
    .map(([name]) => name)
  const labData = liveCollectors.includes('synthetic')

  return (
    <header className="topbar">
      <div>
        <h2>{title}</h2>
        {subtitle ? <div className="subtitle">{subtitle}</div> : null}
      </div>
      <div className="topbar-actions">
        <div style={{ textAlign: 'right' }}>
          <LiveDot
            active={Boolean(pipelineRunning)}
            label={pipelineRunning ? 'Pipeline running' : 'Pipeline stopped'}
          />
          <div className="text-dim" style={{ fontSize: 11.5, marginTop: 2 }}>
            {formatNumber(metrics?.events_per_second || 0, 1)} eps · queue {formatNumber(metrics?.queue_depth || 0)} ·{' '}
            {liveCollectors.length ? liveCollectors.join(' + ') : 'no live collectors'} · uptime{' '}
            {formatDuration(metrics?.uptime_seconds || 0)}
          </div>
        </div>
        <span className={`badge ${health?.status === 'ok' ? 'ok' : health?.status === 'degraded' ? 'warn' : 'danger'}`}>
          {health?.status || 'unknown'}
        </span>
        {labData ? (
          <span
            className="badge danger"
            title="Synthetic lab traffic is feeding the pipeline — these events are not from your network"
          >
            LAB DATA
          </span>
        ) : null}
        {ws?.websocket?.connections !== undefined ? (
          <span className="badge" title="Dashboard connections">
            {ws.websocket.connections} client{ws.websocket.connections === 1 ? '' : 's'}
          </span>
        ) : null}
        {actions}
        <div style={{ textAlign: 'right' }}>
          <div className="mono" style={{ fontSize: 12.5 }}>
            {user?.username}
          </div>
          <div className="text-dim" style={{ fontSize: 11.5 }}>
            {user?.role}
          </div>
        </div>
        <button className="sm ghost" onClick={logout} title="End the session">
          Sign out
        </button>
      </div>
    </header>
  )
}

export default TopBar
