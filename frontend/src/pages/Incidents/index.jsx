import { useCallback, useState } from 'react'
import { IncidentTable } from '../../components/tables/Tables.jsx'
import { Empty, ErrorBox, Loading, Severity, StatusBadge } from '../../components/common/States.jsx'
import { useApi, useAction } from '../../hooks/useApi.js'
import { useAuth } from '../../hooks/useAuth.jsx'
import api from '../../services/api.js'
import { formatDateTime, formatNumber, relativeTime } from '../../utils/format.js'

export default function Incidents() {
  const { permissions } = useAuth()
  const [filters, setFilters] = useState({ status: '', severity: '', search: '' })
  const [selectedId, setSelectedId] = useState(null)
  const [note, setNote] = useState('')
  const [resolution, setResolution] = useState('')

  const { data, error, loading, reload } = useApi('/incidents', { params: filters, pollMs: 20000 })
  const { data: detail, reload: reloadDetail } = useApi(
    selectedId ? `/incidents/${selectedId}` : null,
    { enabled: Boolean(selectedId) },
  )
  const { data: statistics } = useApi('/incidents/statistics', { params: { minutes: 1440 }, pollMs: 60000 })
  const action = useAction()

  const run = useCallback(
    async (status) => {
      if (!selectedId) return
      await action.run(() =>
        api.patch(`/incidents/${selectedId}`, {
          status,
          resolution: resolution || undefined,
          note: note || undefined,
        }),
      )
      setNote('')
      setResolution('')
      await Promise.all([reload({ quiet: true }), reloadDetail({ quiet: true })])
    },
    [selectedId, resolution, note, action, reload, reloadDetail],
  )

  const addNote = async () => {
    if (!selectedId || !note.trim()) return
    await action.run(() => api.post(`/incidents/${selectedId}/notes`, { note: note.trim() }))
    setNote('')
    await reloadDetail({ quiet: true })
  }

  const incidents = data?.items || []

  return (
    <>
      <div className="grid cols-4">
        <div className="panel" style={{ padding: '12px 16px' }}>
          <div className="label text-dim" style={{ fontSize: 11 }}>Total incidents</div>
          <div className="value" style={{ fontSize: 20 }}>{formatNumber(statistics?.totals?.total)}</div>
        </div>
        <div className="panel" style={{ padding: '12px 16px' }}>
          <div className="label text-dim" style={{ fontSize: 11 }}>Open</div>
          <div className="value" style={{ fontSize: 20 }}>{formatNumber(statistics?.totals?.open)}</div>
        </div>
        <div className="panel" style={{ padding: '12px 16px' }}>
          <div className="label text-dim" style={{ fontSize: 11 }}>Severity mix (24h)</div>
          <div style={{ marginTop: 8, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {(statistics?.by_severity || []).map((item) => (
              <span key={item.value} className="badge">
                {item.value} {item.count}
              </span>
            ))}
          </div>
        </div>
        <div className="panel" style={{ padding: '12px 16px' }}>
          <div className="label text-dim" style={{ fontSize: 11 }}>Correlation</div>
          <div className="text-dim" style={{ fontSize: 11.5, marginTop: 6 }}>
            Alerts from one entity are grouped automatically; analysts can escalate any alert manually.
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h3>Incident queue</h3>
          <div className="filters">
            <div className="field">
              <label htmlFor="status">Status</label>
              <select
                id="status"
                value={filters.status}
                onChange={(event) => setFilters({ ...filters, status: event.target.value })}
              >
                <option value="">all</option>
                {['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED'].map((status) => (
                  <option key={status}>{status}</option>
                ))}
              </select>
            </div>
            <div className="field">
              <label htmlFor="severity">Severity</label>
              <select
                id="severity"
                value={filters.severity}
                onChange={(event) => setFilters({ ...filters, severity: event.target.value })}
              >
                <option value="">all</option>
                {['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((severity) => (
                  <option key={severity}>{severity}</option>
                ))}
              </select>
            </div>
            <div className="field">
              <label htmlFor="search">Search</label>
              <input
                id="search"
                value={filters.search}
                onChange={(event) => setFilters({ ...filters, search: event.target.value })}
                placeholder="title, id, entity"
              />
            </div>
            <button className="sm" onClick={() => reload()}>
              Refresh
            </button>
          </div>
        </div>

        <ErrorBox error={error} onRetry={reload} />
        {loading && !incidents.length ? (
          <Loading label="Loading incidents…" />
        ) : incidents.length ? (
          <IncidentTable
            incidents={incidents}
            onSelect={(incident) => setSelectedId(incident.incident_id)}
            selectedId={selectedId}
          />
        ) : (
          <Empty
            label="No incidents yet"
            hint="Incidents open automatically for HIGH/CRITICAL alerts or when one source produces multiple detection types."
          />
        )}
      </div>

      {selectedId ? (
        <div className="panel">
          <div className="panel-header">
            <h3>
              {detail?.title || selectedId} <StatusBadge status={detail?.status} />
            </h3>
            <button className="sm ghost" onClick={() => setSelectedId(null)}>
              Close
            </button>
          </div>
          {detail ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div className="grid cols-3">
                <div>
                  <dl className="detail-grid" style={{ gridTemplateColumns: '130px 1fr' }}>
                    <dt>Incident</dt>
                    <dd className="mono">{detail.incident_id}</dd>
                    <dt>Severity</dt>
                    <dd>
                      <Severity value={detail} showScore />
                    </dd>
                    <dt>Status</dt>
                    <dd>{detail.status}</dd>
                    <dt>Alerts</dt>
                    <dd className="mono">{detail.alert_count}</dd>
                    <dt>Created</dt>
                    <dd>{formatDateTime(detail.created_at)}</dd>
                    <dt>Updated</dt>
                    <dd>{relativeTime(detail.updated_at)}</dd>
                  </dl>
                </div>
                <div>
                  <div className="text-dim" style={{ fontSize: 11.5, textTransform: 'uppercase' }}>Source entities</div>
                  <div className="kv" style={{ marginTop: 6 }}>
                    {(detail.source_entities || []).map((entity) => (
                      <span key={entity} className="badge mono">
                        {entity}
                      </span>
                    ))}
                    {!(detail.source_entities || []).length ? <span className="text-dim">—</span> : null}
                  </div>
                  <div className="text-dim" style={{ fontSize: 11.5, textTransform: 'uppercase', marginTop: 12 }}>
                    Destination entities
                  </div>
                  <div className="kv" style={{ marginTop: 6 }}>
                    {(detail.destination_entities || []).map((entity) => (
                      <span key={entity} className="badge mono">
                        {entity}
                      </span>
                    ))}
                    {!(detail.destination_entities || []).length ? <span className="text-dim">—</span> : null}
                  </div>
                </div>
                <div>
                  <div className="text-dim" style={{ fontSize: 11.5, textTransform: 'uppercase' }}>Summary</div>
                  <div style={{ marginTop: 6 }}>{detail.summary || '—'}</div>
                  {detail.resolution ? (
                    <>
                      <div className="text-dim" style={{ fontSize: 11.5, textTransform: 'uppercase', marginTop: 12 }}>
                        Resolution
                      </div>
                      <div>{detail.resolution}</div>
                    </>
                  ) : null}
                </div>
              </div>

              <div>
                <div className="panel-header" style={{ marginBottom: 8 }}>
                  <h3 style={{ fontSize: 12.5 }}>Timeline</h3>
                  <span className="hint">alerts and analyst actions</span>
                </div>
                <ul className="timeline">
                  {(detail.timeline || []).slice().reverse().map((entry, index) => (
                    <li key={`${entry.timestamp}-${index}`}>
                      <div className="when">
                        {formatDateTime(entry.timestamp)} · {entry.event}
                        {entry.severity ? ` · ${entry.severity}` : ''}
                      </div>
                      <div className="what">{entry.description}</div>
                    </li>
                  ))}
                </ul>
              </div>

              <div>
                <div className="panel-header" style={{ marginBottom: 8 }}>
                  <h3 style={{ fontSize: 12.5 }}>Related alerts</h3>
                </div>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th style={{ width: 100 }}>Alert</th>
                        <th style={{ width: 160 }}>Detection</th>
                        <th style={{ width: 88 }}>Severity</th>
                        <th style={{ width: 78 }}>Score</th>
                        <th style={{ width: 130 }}>Status</th>
                        <th>Description</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(detail.alerts || []).map((alert) => (
                        <tr key={alert.alert_id}>
                          <td className="mono">{alert.alert_id}</td>
                          <td>{String(alert.detection_type).replace(/_/g, ' ')}</td>
                          <td>
                            <Severity value={alert} />
                          </td>
                          <td className="mono">{Number(alert.risk_score).toFixed(1)}</td>
                          <td>
                            <StatusBadge status={alert.status} />
                          </td>
                          <td className="text-muted truncate" title={alert.description}>
                            {alert.description}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              <div>
                <div className="panel-header" style={{ marginBottom: 8 }}>
                  <h3 style={{ fontSize: 12.5 }}>Analyst notes</h3>
                </div>
                {(detail.notes || []).length ? (
                  <ul className="timeline">
                    {detail.notes.map((entry) => (
                      <li key={entry.id}>
                        <div className="when">
                          {formatDateTime(entry.created_at)} · {entry.author || 'unknown'}
                        </div>
                        <div className="what">{entry.note}</div>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <div className="text-dim" style={{ fontSize: 12.5 }}>No notes recorded yet.</div>
                )}
              </div>

              {permissions.investigate ? (
                <div className="panel" style={{ background: '#0e1729' }}>
                  <div className="panel-header" style={{ marginBottom: 10 }}>
                    <h3 style={{ fontSize: 12.5 }}>Update incident</h3>
                    <span className="hint">every change is audited</span>
                  </div>
                  <div className="grid cols-2">
                    <div className="field">
                      <label htmlFor="note">Note</label>
                      <textarea
                        id="note"
                        value={note}
                        onChange={(event) => setNote(event.target.value)}
                        placeholder="Findings, containment steps, evidence references…"
                      />
                    </div>
                    <div className="field">
                      <label htmlFor="resolution">Resolution (used when resolving)</label>
                      <textarea
                        id="resolution"
                        value={resolution}
                        onChange={(event) => setResolution(event.target.value)}
                        placeholder="Source host isolated and credentials rotated…"
                      />
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 10 }}>
                    <button className="sm" disabled={action.pending} onClick={() => run('INVESTIGATING')}>
                      Investigating
                    </button>
                    <button className="sm" disabled={action.pending} onClick={() => run('CONTAINED')}>
                      Contained
                    </button>
                    <button className="sm primary" disabled={action.pending} onClick={() => run('RESOLVED')}>
                      Resolve
                    </button>
                    <button className="sm ghost" disabled={action.pending} onClick={() => run('CLOSED')}>
                      Close
                    </button>
                    <button className="sm" disabled={!note.trim() || action.pending} onClick={addNote}>
                      Save note only
                    </button>
                  </div>
                  {action.error ? <div className="form-error" style={{ marginTop: 8 }}>{action.error.message}</div> : null}
                </div>
              ) : null}
            </div>
          ) : (
            <Loading label="Loading incident…" />
          )}
        </div>
      ) : null}
    </>
  )
}
