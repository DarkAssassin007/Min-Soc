import { RiskScore, Severity, StatusBadge } from '../common/States.jsx'
import { ProvenanceTag } from '../common/Provenance.jsx'
import { formatBytes, formatTime, relativeTime, truncate } from '../../utils/format.js'

export function EventTable({ events = [], onSelect, selectedId, compact = false }) {
  if (!events.length) return null
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th style={{ width: 92 }}>Time</th>
            <th>Source</th>
            <th>Destination</th>
            <th style={{ width: 68 }}>Proto</th>
            {compact ? null : <th style={{ width: 72 }}>Port</th>}
            <th style={{ width: 96 }}>Type</th>
            {compact ? null : <th style={{ width: 128 }}>State</th>}
            {compact ? null : <th style={{ width: 86 }}>Bytes</th>}
            <th style={{ width: 108 }}>Risk</th>
            <th style={{ width: 172 }}>Source feed</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr
              key={event.event_id}
              className={onSelect ? 'clickable' : undefined}
              onClick={onSelect ? () => onSelect(event) : undefined}
              style={selectedId === event.event_id ? { background: 'rgba(34,211,238,0.08)' } : undefined}
            >
              <td className="mono nowrap">{formatTime(event.timestamp)}</td>
              <td className="mono">{event.source_ip || '—'}</td>
              <td className="mono">
                {event.destination_ip || '—'}
                {event.destination_port ? <span className="text-dim">:{event.destination_port}</span> : null}
              </td>
              <td className="mono">{event.protocol}</td>
              {compact ? null : <td className="mono">{event.destination_port || '—'}</td>}
              <td className="text-muted nowrap">{String(event.event_type).replace(/_/g, ' ')}</td>
              {compact ? null : <td className="mono text-dim">{event.connection_state}</td>}
              {compact ? null : <td className="mono text-dim">{formatBytes(event.bytes)}</td>}
              <td>
                <Severity value={event} showScore />
              </td>
              <td>
                <ProvenanceTag record={event} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function AlertTable({ alerts = [], onSelect, selectedId, showIncident = true }) {
  if (!alerts.length) return null
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th style={{ width: 92 }}>Time</th>
            <th style={{ width: 108 }}>Alert</th>
            <th style={{ width: 168 }}>Detection</th>
            <th>Source</th>
            <th>Target</th>
            <th style={{ width: 150 }}>Severity</th>
            <th style={{ width: 78 }}>Occur.</th>
            <th style={{ width: 130 }}>Status</th>
            <th style={{ width: 172 }}>Source feed</th>
            {showIncident ? <th style={{ width: 104 }}>Incident</th> : null}
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr
              key={alert.alert_id}
              className={onSelect ? 'clickable' : undefined}
              onClick={onSelect ? () => onSelect(alert) : undefined}
              style={selectedId === alert.alert_id ? { background: 'rgba(34,211,238,0.08)' } : undefined}
            >
              <td className="mono nowrap" title={alert.first_seen}>
                {formatTime(alert.last_seen)}
              </td>
              <td className="mono nowrap">{alert.alert_id}</td>
              <td>
                <div className="nowrap">{String(alert.detection_type).replace(/_/g, ' ')}</div>
                <div className="text-dim" style={{ fontSize: 11.5 }}>
                  {alert.engine}
                  {alert.rule_key ? ` · ${alert.rule_key}` : ''}
                </div>
              </td>
              <td className="mono">{alert.source_ip || '—'}</td>
              <td className="mono">{alert.destination_ip || '—'}</td>
              <td>
                <Severity value={alert} showScore />
                <div className="text-dim" style={{ fontSize: 11.5 }} title="Risk score">
                  risk <RiskScore score={alert.risk_score} /> · conf {(Number(alert.confidence) || 0).toFixed(2)}
                </div>
              </td>
              <td className="mono">{alert.event_count}</td>
              <td>
                <StatusBadge status={alert.status} />
              </td>
              <td>
                <ProvenanceTag record={alert} />
              </td>
              {showIncident ? (
                <td className="mono">{alert.incident_id || <span className="text-dim">—</span>}</td>
              ) : null}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function IncidentTable({ incidents = [], onSelect, selectedId }) {
  if (!incidents.length) return null
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th style={{ width: 92 }}>Updated</th>
            <th style={{ width: 96 }}>Incident</th>
            <th>Title</th>
            <th style={{ width: 340 }}>Detection types</th>
            <th style={{ width: 150 }}>Severity</th>
            <th style={{ width: 78 }}>Alerts</th>
            <th style={{ width: 130 }}>Status</th>
          </tr>
        </thead>
        <tbody>
          {incidents.map((incident) => (
            <tr
              key={incident.incident_id}
              className={onSelect ? 'clickable' : undefined}
              onClick={onSelect ? () => onSelect(incident) : undefined}
              style={selectedId === incident.incident_id ? { background: 'rgba(34,211,238,0.08)' } : undefined}
            >
              <td className="mono nowrap">{relativeTime(incident.updated_at)}</td>
              <td className="mono nowrap">{incident.incident_id}</td>
              <td>
                <div className="truncate" title={incident.title}>
                  {incident.title}
                </div>
                <div className="text-dim" style={{ fontSize: 11.5 }}>
                  {truncate((incident.source_entities || []).join(', '), 70)}
                </div>
              </td>
              <td className="text-muted">
                {(incident.detection_types || []).map((type) => (
                  <span key={type} className="badge" style={{ marginRight: 6 }}>
                    {String(type).replace(/_/g, ' ')}
                  </span>
                ))}
              </td>
              <td>
                <Severity value={incident} showScore />
              </td>
              <td className="mono">{incident.alert_count}</td>
              <td>
                <StatusBadge status={incident.status} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default { EventTable, AlertTable, IncidentTable }
