import { Link } from 'react-router-dom'
import { BarList, SeverityPie, TimeSeriesChart } from '../../components/charts/Charts.jsx'
import { AlertTable } from '../../components/tables/Tables.jsx'
import { Empty, ErrorBox, Loading, Severity } from '../../components/common/States.jsx'
import StatCard from '../../components/cards/StatCard.jsx'
import { useApi } from '../../hooks/useApi.js'
import { formatNumber, formatTime, relativeTime } from '../../utils/format.js'

export default function Dashboard() {
  const { data, error, loading, reload } = useApi('/dashboard/summary', { pollMs: 15000 })

  if (loading && !data) return <Loading label="Loading security overview…" />
  if (error) return <ErrorBox error={error} onRetry={reload} />
  if (!data) return <Empty label="No summary available yet" />

  const alerts = data.alerts || {}
  const incidents = data.incidents || {}
  const events = data.events || {}

  return (
    <>
      <div className="grid cols-6">
        <StatCard
          label="Events (24h)"
          value={formatNumber(events.last_24h)}
          foot={`${formatNumber(events.total)} stored in total`}
        />
        <StatCard
          label="Throughput"
          value={`${formatNumber(events.per_second, 1)}/s`}
          foot="events per second (60s window)"
        />
        <StatCard
          label="Active alerts"
          value={formatNumber(alerts.active ?? alerts.open_total)}
          foot={`${formatNumber(alerts.total)} raised in window`}
          accent={alerts.active > 0 ? 'high' : undefined}
        />
        <StatCard
          label="Critical alerts"
          value={formatNumber(alerts.critical)}
          foot="severity CRITICAL, still open"
          accent={alerts.critical > 0 ? 'critical' : undefined}
        />
        <StatCard
          label="Open incidents"
          value={formatNumber(incidents.open)}
          foot={`${formatNumber(incidents.total)} recorded in total`}
        />
        <StatCard
          label="Detections"
          value={formatNumber((data.detection_types || []).reduce((sum, item) => sum + item.count, 0))}
          foot={`${(data.detection_types || []).length} distinct detection types`}
        />
      </div>

      <div className="grid cols-2">
        <div className="panel">
          <div className="panel-header">
            <h3>Network activity</h3>
            <span className="hint">events per bucket, last {(data.window_minutes || 1440) / 60}h</span>
          </div>
          <TimeSeriesChart buckets={data.network_activity} color="#22d3ee" label="events" />
        </div>
        <div className="panel">
          <div className="panel-header">
            <h3>Threat activity</h3>
            <span className="hint">alerts last seen</span>
          </div>
          <TimeSeriesChart buckets={data.threat_activity} color="#fb923c" label="alerts" />
        </div>
      </div>

      <div className="grid cols-3">
        <div className="panel">
          <div className="panel-header">
            <h3>Alert severity mix</h3>
            <span className="hint">triage priority</span>
          </div>
          <SeverityPie items={data.severity_distribution} />
        </div>
        <div className="panel">
          <div className="panel-header">
            <h3>Detection types</h3>
            <span className="hint">what is firing</span>
          </div>
          <BarList items={data.detection_types} labelKey="value" valueKey="count" color="#fbbf24" />
        </div>
        <div className="panel">
          <div className="panel-header">
            <h3>High-risk sources</h3>
            <span className="hint">ranked by peak event risk</span>
          </div>
          <BarList
            items={data.high_risk_sources}
            labelKey="source_ip"
            valueKey="max_risk"
            color="#ef4444"
            formatter={(item) => `${item.source_ip} · ${formatNumber(item.events)} events`}
          />
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h3>Recent alerts</h3>
          <Link to="/alerts" className="hint">
            open the alert queue →
          </Link>
        </div>
        {data.recent_alerts?.length ? (
          <AlertTable alerts={data.recent_alerts} />
        ) : (
          <Empty label="No alerts in the selected window" hint="Detection runs continuously; this stays empty while traffic is normal." />
        )}
      </div>

      <div className="panel">
        <div className="panel-header">
          <h3>Latest events</h3>
          <Link to="/live" className="hint">
            real-time view →
          </Link>
        </div>
        {data.recent_events?.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th style={{ width: 96 }}>Time</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th style={{ width: 68 }}>Proto</th>
                  <th style={{ width: 150 }}>Type</th>
                  <th style={{ width: 140 }}>Risk</th>
                </tr>
              </thead>
              <tbody>
                {data.recent_events.map((event) => (
                  <tr key={event.event_id}>
                    <td className="mono nowrap" title={relativeTime(event.timestamp)}>
                      {formatTime(event.timestamp)}
                    </td>
                    <td className="mono">{event.source_ip}</td>
                    <td className="mono">
                      {event.destination_ip}
                      {event.destination_port ? <span className="text-dim">:{event.destination_port}</span> : null}
                    </td>
                    <td className="mono">{event.protocol}</td>
                    <td className="text-muted">{String(event.event_type).replace(/_/g, ' ')}</td>
                    <td>
                      <Severity value={event} showScore />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty
            label="No events stored yet"
            hint="This dashboard only shows genuinely collected traffic. Events appear as soon as packet capture or the syslog receiver sees activity."
          />
        )}
      </div>
    </>
  )
}
