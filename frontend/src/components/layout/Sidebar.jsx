import { NavLink } from 'react-router-dom'
import { useApi } from '../../hooks/useApi.js'
import { formatNumber } from '../../utils/format.js'

const NAV = [
  { to: '/', label: 'Overview', end: true },
  { to: '/live', label: 'Live Monitor' },
  { to: '/alerts', label: 'Alerts', badge: 'activeAlerts' },
  { to: '/incidents', label: 'Incidents', badge: 'openIncidents' },
  { to: '/network', label: 'Network' },
  { to: '/threats', label: 'Threats' },
  { to: '/analytics', label: 'Analytics' },
  { to: '/investigation', label: 'Investigation' },
  { to: '/reports', label: 'Reports' },
]

export function Sidebar() {
  const { data } = useApi('/dashboard/summary', { pollMs: 20000 })
  const counts = {
    activeAlerts: data?.alerts?.active_total ?? data?.alerts?.open_total ?? data?.alerts?.active,
    openIncidents: data?.incidents?.open,
  }

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <h1>Mini SOC</h1>
        <span>Real-time monitoring</span>
      </div>
      <div className="sidebar-status">
        <span className={`pulse ${data ? '' : 'stale'}`} />
        <span>{data ? `${formatNumber(data?.events?.per_second || 0, 1)} events/s` : 'connecting…'}</span>
      </div>
      <nav>
        {NAV.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
          >
            <span>{item.label}</span>
            {item.badge && counts[item.badge] ? (
              <span className="nav-count">{formatNumber(counts[item.badge])}</span>
            ) : null}
          </NavLink>
        ))}
      </nav>
      <div className="sidebar-footer">
        <div>Detection: rules + ML</div>
        <div>Collection: live sources only</div>
      </div>
    </aside>
  )
}

export default Sidebar
