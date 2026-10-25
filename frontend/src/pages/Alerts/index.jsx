import { useCallback, useMemo, useState } from 'react'
import { AlertTable } from '../../components/tables/Tables.jsx'
import { AlertDetail } from '../../components/alerts/DetailPanels.jsx'
import { Empty, ErrorBox, Loading, StatusBadge } from '../../components/common/States.jsx'
import { useApi, useAction } from '../../hooks/useApi.js'
import { useAuth } from '../../hooks/useAuth.jsx'
import { useChannel } from '../../hooks/useWebSocket.js'
import api from '../../services/api.js'
import { SEVERITIES, formatDateTime, formatNumber } from '../../utils/format.js'

export default function Alerts() {
  const { permissions } = useAuth()
  const [filters, setFilters] = useState({
    severity: '',
    status: 'NEW',
    detection_type: '',
    source_ip: '',
    search: '',
    limit: 100,
  })
  const [selectedId, setSelectedId] = useState(null)
  const [note, setNote] = useState('')
  const [liveBanner, setLiveBanner] = useState(null)

  const listPath = useMemo(() => '/alerts', [])
  const { data, error, loading, reload } = useApi(listPath, {
    params: filters,
    pollMs: 15000,
  })
  const { data: detail, reload: reloadDetail } = useApi(
    selectedId ? `/alerts/${selectedId}` : null,
    { enabled: Boolean(selectedId) },
  )
  const { data: statistics } = useApi('/alerts/statistics', { params: { minutes: 1440 }, pollMs: 30000 })
  const action = useAction()

  useChannel('alerts', {
    onMessage: (payload) => {
      if (payload?.type === 'alert.created' || payload?.type === 'alert.updated') {
        setLiveBanner(`${payload.data.alert_id} · ${payload.data.detection_type} · ${payload.data.severity}`)
        reload({ quiet: true })
      }
    },
  })

  const act = useCallback(
    async (status, resolution) => {
      if (!selectedId) return
      await action.run(() =>
        api.patch(`/alerts/${selectedId}`, {
          status,
          resolution: resolution || undefined,
          note: note || undefined,
        }),
      )
      setNote('')
      await Promise.all([reload({ quiet: true }), reloadDetail({ quiet: true })])
    },
    [selectedId, note, action, reload, reloadDetail],
  )

  const addNote = async () => {
    if (!selectedId || !note.trim()) return
    await action.run(() =>
      api.post(`/alerts/${selectedId}/notes`, { note: note.trim(), action_taken: 'ANALYST_NOTE' }),
    )
    setNote('')
    await reloadDetail({ quiet: true })
  }

  const alerts = data?.items || []
  const totals = statistics?.totals || {}

  return (
    <>
      <div className="grid cols-4">
        <div className="panel" style={{ padding: '12px 16px' }}>
          <div className="label text-dim" style={{ fontSize: 11 }}>Alerts (24h)</div>
          <div className="value" style={{ fontSize: 20 }}>{formatNumber(totals.total)}</div>
        </div>
        <div className="panel" style={{ padding: '12px 16px' }}>
          <div className="label text-dim" style={{ fontSize: 11 }}>Still open</div>
          <div className="value" style={{ fontSize: 20 }}>{formatNumber(totals.active)}</div>
        </div>
        <div className="panel" style={{ padding: '12px 16px' }}>
          <div className="label text-dim" style={{ fontSize: 11 }}>Critical open</div>
          <div className="value" style={{ fontSize: 20 }}>{formatNumber(totals.critical)}</div>
        </div>
        <div className="panel" style={{ padding: '12px 16px' }}>
          <div className="label text-dim" style={{ fontSize: 11 }}>Real-time</div>
          <div className="text-muted" style={{ fontSize: 12, marginTop: 8 }}>
            {liveBanner || 'listening on /ws/alerts'}
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h3>Alert queue</h3>
          <div className="filters">
            <div className="field">
              <label htmlFor="severity">Severity</label>
              <select
                id="severity"
                value={filters.severity}
                onChange={(event) => setFilters({ ...filters, severity: event.target.value })}
              >
                <option value="">all</option>
                {SEVERITIES.map((severity) => (
                  <option key={severity}>{severity}</option>
                ))}
              </select>
            </div>
            <div className="field">
              <label htmlFor="status">Status</label>
              <select
                id="status"
                value={filters.status}
                onChange={(event) => setFilters({ ...filters, status: event.target.value })}
              >
                <option value="">all</option>
                {['NEW', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'].map((status) => (
                  <option key={status}>{status}</option>
                ))}
              </select>
            </div>
            <div className="field">
              <label htmlFor="source">Source IP</label>
              <input
                id="source"
                value={filters.source_ip}
                onChange={(event) => setFilters({ ...filters, source_ip: event.target.value })}
                placeholder="10.0.0.1"
              />
            </div>
            <div className="field">
              <label htmlFor="search">Search</label>
              <input
                id="search"
                value={filters.search}
                onChange={(event) => setFilters({ ...filters, search: event.target.value })}
                placeholder="description, id, type"
              />
            </div>
            <div className="field">
              <label htmlFor="limit">Limit</label>
              <select
                id="limit"
                value={filters.limit}
                onChange={(event) => setFilters({ ...filters, limit: Number(event.target.value) })}
              >
                {[50, 100, 200, 500].map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </div>
            <button className="sm" onClick={() => reload()}>
              Refresh
            </button>
          </div>
        </div>

        <ErrorBox error={error} onRetry={reload} />
        {loading && !alerts.length ? (
          <Loading label="Loading alerts…" />
        ) : alerts.length ? (
          <AlertTable alerts={alerts} onSelect={(alert) => setSelectedId(alert.alert_id)} selectedId={selectedId} />
        ) : (
          <Empty
            label="No alerts match the current filters"
            hint="Detection runs on every normalized event; an empty queue means nothing suspicious in this window."
          />
        )}
        {data?.total ? (
          <div className="text-dim" style={{ fontSize: 11.5, marginTop: 8 }}>
            showing {alerts.length} of {formatNumber(data.total)} matching alerts
          </div>
        ) : null}
      </div>

      {selectedId ? (
        <div className="panel">
          <div className="panel-header">
            <h3>
              Alert detail — {selectedId} <StatusBadge status={detail?.status} />
            </h3>
            <button className="sm ghost" onClick={() => setSelectedId(null)}>
              Close
            </button>
          </div>
          {detail ? (
            <>
              <AlertDetail
                alert={detail}
                permissions={permissions}
                pending={action.pending}
                onAction={(status) => act(status, status === 'RESOLVED' ? 'Handled by analyst' : undefined)}
              />
              {permissions.investigate ? (
                <div style={{ marginTop: 16 }}>
                  <div className="field">
                    <label htmlFor="note">Add investigation note</label>
                    <textarea
                      id="note"
                      value={note}
                      onChange={(event) => setNote(event.target.value)}
                      placeholder="What did you check, and what did you conclude?"
                    />
                  </div>
                  <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                    <button className="sm" disabled={!note.trim() || action.pending} onClick={addNote}>
                      Save note
                    </button>
                    {action.error ? <span className="form-error">{action.error.message}</span> : null}
                  </div>
                </div>
              ) : (
                <div className="form-note">Your role can view alerts but not change their state.</div>
              )}
              <div className="text-dim" style={{ fontSize: 11.5, marginTop: 10 }}>
                Created {formatDateTime(detail.created_at)} · updated {formatDateTime(detail.updated_at)}
              </div>
            </>
          ) : (
            <Loading label="Loading alert detail…" />
          )}
        </div>
      ) : null}
    </>
  )
}
