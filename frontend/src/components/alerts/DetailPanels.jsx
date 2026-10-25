import { RiskScore, Severity, StatusBadge } from '../common/States.jsx'
import { ProvenanceTag } from '../common/Provenance.jsx'
import { formatBytes, formatDateTime, formatTime } from '../../utils/format.js'

/** Normalised event detail (used by the live monitor and investigation page). */
export function EventDetail({ event }) {
  if (!event) return null
  const metadata = event.metadata || {}
  const network = event.network || {}
  return (
    <div className="grid cols-2">
      <div>
        <dl className="detail-grid">
          <dt>Event id</dt>
          <dd className="mono">{event.event_id}</dd>
          <dt>Timestamp</dt>
          <dd>{formatDateTime(event.timestamp)}</dd>
          <dt>Type</dt>
          <dd>{String(event.event_type || '').replace(/_/g, ' ')}</dd>
          <dt>Source</dt>
          <dd className="mono">
            {event.source_ip || '—'}
            {event.source_port ? `:${event.source_port}` : ''}
          </dd>
          <dt>Destination</dt>
          <dd className="mono">
            {event.destination_ip || '—'}
            {event.destination_port ? `:${event.destination_port}` : ''}
          </dd>
          <dt>Protocol</dt>
          <dd className="mono">
            {event.protocol} {network.tcp_flags ? `· flags ${network.tcp_flags}` : ''}
          </dd>
          <dt>State</dt>
          <dd className="mono">{event.connection_state}</dd>
          <dt>Direction</dt>
          <dd>{event.direction || '—'}</dd>
          <dt>Volume</dt>
          <dd className="mono">
            {formatBytes(event.bytes)} · {event.packet_count} pkts
          </dd>
          <dt>Risk</dt>
          <dd>
            <Severity value={event} showScore /> · confidence {(Number(event.confidence) || 0).toFixed(2)}
          </dd>
          <dt>Anomaly</dt>
          <dd className="mono">{event.anomaly_score === null || event.anomaly_score === undefined ? '—' : Number(event.anomaly_score).toFixed(4)}</dd>
          <dt>Source feed</dt>
          <dd>
            <ProvenanceTag record={event} />
          </dd>
        </dl>
      </div>
      <div>
        <div className="panel-header" style={{ marginBottom: 8 }}>
          <h3 style={{ fontSize: 12.5 }}>Protocol metadata</h3>
          <span className="hint">no payload content is stored</span>
        </div>
        <pre className="evidence">
          {JSON.stringify({ network_detail: network, metadata }, null, 2)}
        </pre>
      </div>
    </div>
  )
}

/** Alert detail with evidence, detection trace and investigation context. */
export function AlertDetail({ alert, onAction, pending, permissions }) {
  if (!alert) return null
  const evidence = alert.evidence || {}
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div className="grid cols-2">
        <div>
          <dl className="detail-grid">
            <dt>Alert</dt>
            <dd className="mono">{alert.alert_id}</dd>
            <dt>Status</dt>
            <dd>
              <StatusBadge status={alert.status} />
            </dd>
            <dt>Detection</dt>
            <dd>
              {String(alert.detection_type || '').replace(/_/g, ' ')}{' '}
              <span className="text-dim">
                ({alert.engine}
                {alert.rule_key ? ` · ${alert.rule_key}` : ''})
              </span>
            </dd>
            <dt>Severity</dt>
            <dd>
              <Severity value={alert} showScore /> · confidence {(Number(alert.confidence) || 0).toFixed(2)}
            </dd>
            <dt>Source</dt>
            <dd className="mono">{alert.source_ip || '—'}</dd>
            <dt>Destination</dt>
            <dd className="mono">{alert.destination_ip || '—'}</dd>
            <dt>First seen</dt>
            <dd>{formatDateTime(alert.first_seen)}</dd>
            <dt>Last seen</dt>
            <dd>{formatDateTime(alert.last_seen)}</dd>
            <dt>Occurrences</dt>
            <dd className="mono">{alert.event_count}</dd>
            <dt>Incident</dt>
            <dd className="mono">{alert.incident_id || '—'}</dd>
            <dt>Classification</dt>
            <dd>{evidence.classification || '—'}</dd>
            <dt>Source feed</dt>
            <dd>
              <ProvenanceTag record={alert} />
            </dd>
            <dt>First event</dt>
            <dd className="mono">{evidence.first_event_id || '—'}</dd>
          </dl>
          <div style={{ marginTop: 12 }}>
            <div className="text-dim" style={{ fontSize: 11.5, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Description
            </div>
            <div style={{ marginTop: 4 }}>{alert.description}</div>
          </div>
          <div style={{ marginTop: 12 }}>
            <div className="text-dim" style={{ fontSize: 11.5, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Recommended action
            </div>
            <div style={{ marginTop: 4 }}>{alert.recommended_action || '—'}</div>
          </div>
        </div>
        <div>
          <div className="panel-header" style={{ marginBottom: 8 }}>
            <h3 style={{ fontSize: 12.5 }}>Why this fired</h3>
            <span className="hint">risk {Number(alert.risk_score).toFixed(1)}</span>
          </div>
          <ul style={{ margin: '0 0 12px 16px', padding: 0, fontSize: 13 }}>
            {(evidence.reasons || []).map((reason) => (
              <li key={reason} style={{ marginBottom: 4 }}>
                {reason}
              </li>
            ))}
            {!(evidence.reasons || []).length ? <li className="text-dim">No explanation recorded</li> : null}
          </ul>
          <div className="text-dim" style={{ fontSize: 11.5, marginBottom: 6 }}>
            Risk components:{' '}
            {Object.entries(evidence.components || {})
              .map(([key, value]) => `${key} ${Number(value).toFixed(1)}`)
              .join(' · ') || '—'}
          </div>
          <pre className="evidence">{JSON.stringify(evidence, null, 2)}</pre>
        </div>
      </div>

      {(alert.detections || []).length ? (
        <div>
          <div className="panel-header" style={{ marginBottom: 8 }}>
            <h3 style={{ fontSize: 12.5 }}>Detection trace</h3>
            <span className="hint">event → detection → alert</span>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th style={{ width: 108 }}>Detection</th>
                  <th style={{ width: 132 }}>Event</th>
                  <th style={{ width: 78 }}>Engine</th>
                  <th style={{ width: 92 }}>Score</th>
                  <th style={{ width: 96 }}>Confidence</th>
                  <th>Description</th>
                </tr>
              </thead>
              <tbody>
                {alert.detections.map((detection) => (
                  <tr key={detection.detection_id}>
                    <td className="mono">{detection.detection_id}</td>
                    <td className="mono">{detection.event_id}</td>
                    <td>{detection.engine}</td>
                    <td className="mono">{Number(detection.rule_score).toFixed(1)}</td>
                    <td className="mono">{Number(detection.confidence).toFixed(2)}</td>
                    <td className="text-muted">{detection.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}

      {(alert.events || []).length ? (
        <div>
          <div className="panel-header" style={{ marginBottom: 8 }}>
            <h3 style={{ fontSize: 12.5 }}>Related events</h3>
            <span className="hint">bounded sample</span>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th style={{ width: 96 }}>Time</th>
                  <th style={{ width: 120 }}>Event</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th style={{ width: 66 }}>Proto</th>
                  <th style={{ width: 96 }}>State</th>
                  <th style={{ width: 96 }}>Risk</th>
                </tr>
              </thead>
              <tbody>
                {alert.events.map((event) => (
                  <tr key={event.event_id}>
                    <td className="mono">{formatTime(event.timestamp)}</td>
                    <td className="mono">{event.event_id}</td>
                    <td className="mono">{event.source_ip}</td>
                    <td className="mono">
                      {event.destination_ip}
                      {event.destination_port ? `:${event.destination_port}` : ''}
                    </td>
                    <td className="mono">{event.protocol}</td>
                    <td className="text-dim mono">{event.connection_state}</td>
                    <td>
                      <RiskScore score={event.risk_score} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}

      {(alert.related_alerts || []).length ? (
        <div>
          <div className="panel-header" style={{ marginBottom: 8 }}>
            <h3 style={{ fontSize: 12.5 }}>Other alerts from the same source</h3>
            <span className="hint">correlation context</span>
          </div>
          <div className="kv">
            {alert.related_alerts.map((related) => (
              <span key={related.alert_id} className="badge">
                {related.alert_id} · {related.detection_type} · {related.severity}
              </span>
            ))}
          </div>
        </div>
      ) : null}

      {(alert.notes || []).length ? (
        <div>
          <div className="panel-header" style={{ marginBottom: 8 }}>
            <h3 style={{ fontSize: 12.5 }}>Investigation notes</h3>
          </div>
          <ul className="timeline">
            {alert.notes.map((note) => (
              <li key={note.id}>
                <div className="when">
                  {formatDateTime(note.created_at)} · {note.author || 'unknown'}
                  {note.action_taken ? ` · ${note.action_taken}` : ''}
                </div>
                <div className="what">{note.note}</div>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {permissions?.investigate ? (
        <div className="panel" style={{ background: '#0e1729' }}>
          <div className="panel-header" style={{ marginBottom: 10 }}>
            <h3 style={{ fontSize: 12.5 }}>Actions</h3>
            <span className="hint">RBAC: analyst or administrator</span>
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button className="sm" disabled={pending} onClick={() => onAction('ACKNOWLEDGED')}>
              Acknowledge
            </button>
            <button className="sm" disabled={pending} onClick={() => onAction('INVESTIGATING')}>
              Start investigation
            </button>
            <button className="sm primary" disabled={pending} onClick={() => onAction('RESOLVED')}>
              Resolve
            </button>
            <button className="sm danger" disabled={pending} onClick={() => onAction('FALSE_POSITIVE')}>
              Mark false positive
            </button>
          </div>
        </div>
      ) : null}
    </div>
  )
}

export default { EventDetail, AlertDetail }
