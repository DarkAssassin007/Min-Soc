import { useState } from 'react'
import { Empty, ErrorBox, Loading, Severity, StatusBadge } from '../../components/common/States.jsx'
import { AlertDetail, EventDetail } from '../../components/alerts/DetailPanels.jsx'
import { ProvenanceTag } from '../../components/common/Provenance.jsx'
import { useApi } from '../../hooks/useApi.js'
import { useAuth } from '../../hooks/useAuth.jsx'
import api from '../../services/api.js'
import { formatBytes, formatDateTime, formatNumber } from '../../utils/format.js'

/**
 * The investigation workspace answers one question well:
 * "why did the platform consider this suspicious?"
 *
 * An analyst can pivot from an IP, an event id or an alert id and get the
 * historical activity, related alerts, a merged timeline and the recommended
 * action - the chain the specification asks for.
 */
export default function Investigation() {
  const { permissions } = useAuth()
  const [query, setQuery] = useState('')
  const [subject, setSubject] = useState(null) // { type: 'ip'|'event'|'alert', value }
  const [note, setNote] = useState('')
  const [saveState, setSaveState] = useState(null)

  const { data: events, loading: loadingEvents, error: eventsError } = useApi(
    subject?.type === 'ip' ? '/events' : subject?.type === 'event' ? `/events/${subject.value}` : null,
    { params: subject?.type === 'ip' ? { source_ip: subject.value, limit: 50 } : undefined },
  )
  const { data: alerts, loading: loadingAlerts } = useApi(
    subject?.type === 'ip' ? '/alerts' : subject?.type === 'alert' ? `/alerts/${subject.value}` : null,
    { params: subject?.type === 'ip' ? { source_ip: subject.value, limit: 50 } : undefined },
  )
  const { data: relatedEvents } = useApi(
    subject?.type === 'event' ? `/events/${subject.value}/related` : null,
    { params: { minutes: 120, limit: 50 } },
  )
  const { data: detections } = useApi(
    subject?.type === 'event' ? `/events/${subject.value}/detections` : null,
  )

  const submit = (event) => {
    event.preventDefault()
    const value = query.trim()
    if (!value) return
    if (/^ALT-/i.test(value)) setSubject({ type: 'alert', value: value.toUpperCase() })
    else if (/^EVT-/i.test(value)) setSubject({ type: 'event', value: value.toUpperCase() })
    else setSubject({ type: 'ip', value })
    setSaveState(null)
  }

  const saveNote = async () => {
    if (subject?.type !== 'alert' || !note.trim()) return
    try {
      await api.post(`/alerts/${subject.value}/notes`, { note: note.trim(), action_taken: 'INVESTIGATION' })
      setNote('')
      setSaveState('Note saved to the alert record.')
    } catch (error) {
      setSaveState(error.message)
    }
  }

  const timeline = buildTimeline(subject, events, alerts)

  return (
    <>
      <div className="panel">
        <div className="panel-header">
          <h3>Investigate</h3>
          <span className="hint">IP address, event id (EVT-…) or alert id (ALT-…)</span>
        </div>
        <form className="filters" onSubmit={submit}>
          <div className="field" style={{ flex: 1, minWidth: 260 }}>
            <label htmlFor="subject">Subject</label>
            <input
              id="subject"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="192.168.50.201 · EVT-000123 · ALT-000004"
            />
          </div>
          <button className="primary" type="submit">
            Investigate
          </button>
          {['192.168.50.201', '192.168.50.101'].map((sample) => (
            <button
              key={sample}
              type="button"
              className="sm ghost"
              onClick={() => {
                setQuery(sample)
                setSubject({ type: 'ip', value: sample })
              }}
            >
              {sample}
            </button>
          ))}
        </form>
      </div>

      {!subject ? (
        <Empty
          label="Choose a subject to investigate"
          hint="Type an IP to see everything that host did, or open an alert id for the full detection explanation."
        />
      ) : null}

      {subject?.type === 'alert' ? (
        <div className="panel">
          <div className="panel-header">
            <h3>
              Alert {subject.value} <StatusBadge status={alerts?.status} />
            </h3>
          </div>
          {loadingAlerts ? (
            <Loading label="Loading alert…" />
          ) : alerts && alerts.alert_id ? (
            <>
              <AlertDetail alert={alerts} permissions={permissions} pending={false} onAction={() => {}} />
              {permissions.investigate ? (
                <div style={{ marginTop: 16 }}>
                  <div className="field">
                    <label htmlFor="note">Investigation note</label>
                    <textarea
                      id="note"
                      value={note}
                      onChange={(event) => setNote(event.target.value)}
                      placeholder="What did you verify? What is the conclusion?"
                    />
                  </div>
                  <div style={{ display: 'flex', gap: 8, marginTop: 8, alignItems: 'center' }}>
                    <button className="sm primary" disabled={!note.trim()} onClick={saveNote}>
                      Save to alert
                    </button>
                    {saveState ? <span className="form-note">{saveState}</span> : null}
                  </div>
                </div>
              ) : null}
            </>
          ) : (
            <ErrorBox error={{ message: 'Alert not found' }} />
          )}
        </div>
      ) : null}

      {subject?.type === 'event' ? (
        <div className="panel">
          <div className="panel-header">
            <h3>Event {subject.value}</h3>
          </div>
          {loadingEvents ? (
            <Loading label="Loading event…" />
          ) : events && events.event_id ? (
            <>
              <EventDetail event={events} />
              {detections?.items?.length ? (
                <div style={{ marginTop: 16 }}>
                  <div className="panel-header" style={{ marginBottom: 8 }}>
                    <h3 style={{ fontSize: 12.5 }}>Detections for this event</h3>
                  </div>
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th style={{ width: 110 }}>Detection</th>
                          <th style={{ width: 170 }}>Rule</th>
                          <th style={{ width: 80 }}>Engine</th>
                          <th style={{ width: 90 }}>Score</th>
                          <th>Description</th>
                        </tr>
                      </thead>
                      <tbody>
                        {detections.items.map((detection) => (
                          <tr key={detection.detection_id}>
                            <td className="mono">{detection.detection_id}</td>
                            <td>{detection.rule_key}</td>
                            <td>{detection.engine}</td>
                            <td className="mono">{Number(detection.rule_score).toFixed(1)}</td>
                            <td className="text-muted">{detection.description}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              ) : null}
              {relatedEvents?.items?.length ? (
                <div style={{ marginTop: 16 }}>
                  <div className="panel-header" style={{ marginBottom: 8 }}>
                    <h3 style={{ fontSize: 12.5 }}>Related activity (same entity, 2h)</h3>
                  </div>
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th style={{ width: 110 }}>Event</th>
                          <th style={{ width: 130 }}>Source</th>
                          <th style={{ width: 150 }}>Destination</th>
                          <th style={{ width: 70 }}>Proto</th>
                          <th style={{ width: 90 }}>Risk</th>
                          <th style={{ width: 168 }}>Source feed</th>
                          <th>Type</th>
                        </tr>
                      </thead>
                      <tbody>
                        {relatedEvents.items.map((item) => (
                          <tr key={item.event_id}>
                            <td className="mono">{item.event_id}</td>
                            <td className="mono">{item.source_ip}</td>
                            <td className="mono">
                              {item.destination_ip}
                              {item.destination_port ? `:${item.destination_port}` : ''}
                            </td>
                            <td className="mono">{item.protocol}</td>
                            <td>
                              <Severity value={item} showScore />
                            </td>
                            <td>
                              <ProvenanceTag record={item} />
                            </td>
                            <td className="text-muted">{String(item.event_type).replace(/_/g, ' ')}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              ) : null}
            </>
          ) : (
            <ErrorBox error={eventsError || { message: 'Event not found' }} />
          )}
        </div>
      ) : null}

      {subject?.type === 'ip' ? (
        <>
          <div className="grid cols-4">
            <div className="panel" style={{ padding: '12px 16px' }}>
              <div className="label text-dim" style={{ fontSize: 11 }}>Events (recent sample)</div>
              <div className="value" style={{ fontSize: 20 }}>{formatNumber(events?.items?.length || 0)}</div>
            </div>
            <div className="panel" style={{ padding: '12px 16px' }}>
              <div className="label text-dim" style={{ fontSize: 11 }}>Alerts</div>
              <div className="value" style={{ fontSize: 20 }}>{formatNumber(alerts?.items?.length || 0)}</div>
            </div>
            <div className="panel" style={{ padding: '12px 16px' }}>
              <div className="label text-dim" style={{ fontSize: 11 }}>Peak risk</div>
              <div className="value" style={{ fontSize: 20 }}>
                {Math.max(0, ...(alerts?.items || []).map((item) => Number(item.risk_score) || 0)).toFixed(1)}
              </div>
            </div>
            <div className="panel" style={{ padding: '12px 16px' }}>
              <div className="label text-dim" style={{ fontSize: 11 }}>Volume observed</div>
              <div className="value" style={{ fontSize: 20 }}>
                {formatBytes((events?.items || []).reduce((sum, item) => sum + (Number(item.bytes) || 0), 0))}
              </div>
            </div>
          </div>

          <div className="panel">
            <div className="panel-header">
              <h3>Merged timeline — {subject.value}</h3>
              <span className="hint">alerts and events in one narrative</span>
            </div>
            {timeline.length ? (
              <ul className="timeline">
                {timeline.map((entry) => (
                  <li key={entry.key}>
                    <div className="when">
                      {formatDateTime(entry.timestamp)} · {entry.kind}
                    </div>
                    <div className="what">{entry.text}</div>
                  </li>
                ))}
              </ul>
            ) : (
              <Loading label="Loading history…" />
            )}
          </div>

          <div className="grid cols-2">
            <div className="panel">
              <div className="panel-header">
                <h3>Alerts from this source</h3>
              </div>
              {loadingAlerts ? (
                <Loading label="Loading alerts…" />
              ) : alerts?.items?.length ? (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th style={{ width: 100 }}>Alert</th>
                        <th style={{ width: 160 }}>Detection</th>
                        <th style={{ width: 90 }}>Severity</th>
                        <th style={{ width: 70 }}>Score</th>
                        <th>Recommended action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {alerts.items.map((alert) => (
                        <tr key={alert.alert_id} onClick={() => setSubject({ type: 'alert', value: alert.alert_id })} className="clickable">
                          <td className="mono">{alert.alert_id}</td>
                          <td>{String(alert.detection_type).replace(/_/g, ' ')}</td>
                          <td>
                            <Severity value={alert} />
                          </td>
                          <td className="mono">{Number(alert.risk_score).toFixed(1)}</td>
                          <td className="text-muted truncate" title={alert.recommended_action}>
                            {alert.recommended_action}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <Empty label="No alerts for this source" hint="That is good news — the host has stayed within baseline." />
              )}
            </div>
            <div className="panel">
              <div className="panel-header">
                <h3>Recent events</h3>
              </div>
              {loadingEvents ? (
                <Loading label="Loading events…" />
              ) : events?.items?.length ? (
                <div className="table-wrap" style={{ maxHeight: 420, overflowY: 'auto' }}>
                  <table>
                    <thead>
                      <tr>
                        <th style={{ width: 110 }}>Event</th>
                        <th style={{ width: 140 }}>Destination</th>
                        <th style={{ width: 70 }}>Proto</th>
                        <th style={{ width: 90 }}>Risk</th>
                        <th>Type</th>
                      </tr>
                    </thead>
                    <tbody>
                      {events.items.map((item) => (
                        <tr key={item.event_id} onClick={() => setSubject({ type: 'event', value: item.event_id })} className="clickable">
                          <td className="mono">{item.event_id}</td>
                          <td className="mono">
                            {item.destination_ip}
                            {item.destination_port ? `:${item.destination_port}` : ''}
                          </td>
                          <td className="mono">{item.protocol}</td>
                          <td>
                            <Severity value={item} showScore />
                          </td>
                          <td className="text-muted">{String(item.event_type).replace(/_/g, ' ')}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <Empty label="No events found for this address" />
              )}
            </div>
          </div>
        </>
      ) : null}
    </>
  )
}

function buildTimeline(subject, events, alerts) {
  if (subject?.type !== 'ip') return []
  const entries = []
  ;(events?.items || []).forEach((event) => {
    entries.push({
      key: `e-${event.event_id}`,
      timestamp: event.timestamp,
      kind: 'event',
      text: `${event.source_ip} → ${event.destination_ip}${event.destination_port ? `:${event.destination_port}` : ''} (${event.protocol}, ${String(event.event_type).replace(/_/g, ' ')}, risk ${Number(event.risk_score).toFixed(0)})`,
    })
  })
  ;(alerts?.items || []).forEach((alert) => {
    entries.push({
      key: `a-${alert.alert_id}`,
      timestamp: alert.first_seen,
      kind: 'alert',
      text: `${alert.alert_id} · ${String(alert.detection_type).replace(/_/g, ' ')} · ${alert.severity} · risk ${Number(alert.risk_score).toFixed(1)} — ${alert.description || ''}`,
    })
  })
  return entries
    .filter((entry) => entry.timestamp)
    .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
    .slice(-120)
}
