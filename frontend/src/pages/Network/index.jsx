import { useState } from 'react'
import { BarList, DistributionBar, TimeSeriesChart } from '../../components/charts/Charts.jsx'
import { Empty, ErrorBox, Loading } from '../../components/common/States.jsx'
import { EventTable } from '../../components/tables/Tables.jsx'
import { useApi, useAction } from '../../hooks/useApi.js'
import { useAuth } from '../../hooks/useAuth.jsx'
import api from '../../services/api.js'
import { formatBytes, formatNumber } from '../../utils/format.js'

export default function Network() {
  const { permissions } = useAuth()
  const [minutes, setMinutes] = useState(60)
  const { data: traffic, error, loading, reload } = useApi('/network/traffic', {
    params: { minutes, buckets: 24 },
    pollMs: 20000,
  })
  const { data: statistics } = useApi('/network/statistics', { params: { minutes: 1440 }, pollMs: 60000 })
  const [selected, setSelected] = useState(null)
  const { data: recent } = useApi('/events', { params: { limit: 25, min_risk: 1 }, pollMs: 20000 })
  const { data: assets, reload: reloadAssets } = useApi('/network/assets', { params: { limit: 100 }, pollMs: 60000 })
  const [assetDraft, setAssetDraft] = useState({ ip: '', importance: 3, hostname: '' })
  const action = useAction()

  const saveAsset = async () => {
    if (!assetDraft.ip.trim()) return
    await action.run(() =>
      api.put(`/network/assets/${assetDraft.ip.trim()}`, {
        hostname: assetDraft.hostname || undefined,
        importance: Number(assetDraft.importance),
      }),
    )
    setAssetDraft({ ip: '', importance: 3, hostname: '' })
    await reloadAssets({ quiet: true })
  }

  if (loading && !traffic) return <Loading label="Loading network analytics…" />
  if (error) return <ErrorBox error={error} onRetry={reload} />
  if (!traffic) return <Empty label="No network data yet" />

  return (
    <>
      <div className="panel">
        <div className="panel-header">
          <h3>Traffic volume</h3>
          <div className="filters">
            <div className="field">
              <label htmlFor="window">Window</label>
              <select id="window" value={minutes} onChange={(event) => setMinutes(Number(event.target.value))}>
                {[15, 60, 240, 1440].map((value) => (
                  <option key={value} value={value}>
                    {value < 60 ? `${value} min` : `${value / 60} h`}
                  </option>
                ))}
              </select>
            </div>
            <span className="text-dim" style={{ fontSize: 11.5 }}>
              {formatNumber(traffic.events_per_second, 2)} events/s now
            </span>
          </div>
        </div>
        <TimeSeriesChart buckets={traffic.events_over_time} color="#22d3ee" label="events" height={240} />
      </div>

      <div className="grid cols-3">
        <div className="panel">
          <div className="panel-header">
            <h3>Top sources</h3>
            <span className="hint">who talks most</span>
          </div>
          <BarList items={traffic.top_sources} color="#22d3ee" />
        </div>
        <div className="panel">
          <div className="panel-header">
            <h3>Top destinations</h3>
            <span className="hint">where traffic goes</span>
          </div>
          <BarList items={traffic.top_destinations} color="#38bdf8" />
        </div>
        <div className="panel">
          <div className="panel-header">
            <h3>Targeted ports</h3>
            <span className="hint">most contacted services</span>
          </div>
          <BarList items={traffic.top_destination_ports} color="#fbbf24" />
        </div>
      </div>

      <div className="grid cols-2">
        <div className="panel">
          <div className="panel-header">
            <h3>Protocol mix (24h)</h3>
            <span className="hint">including ground truth for baselining</span>
          </div>
          <DistributionBar items={statistics?.protocol_distribution} color="#34d399" height={240} />
        </div>
        <div className="panel">
          <div className="panel-header">
            <h3>Connection states</h3>
            <span className="hint">failed/reset ratios feed detection</span>
          </div>
          <DistributionBar items={statistics?.connection_state_distribution} color="#fb923c" height={240} />
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h3>Highest-risk recent events</h3>
          <span className="hint">risk ≥ 1, newest first</span>
        </div>
        {recent?.items?.length ? (
          <EventTable events={recent.items} onSelect={setSelected} selectedId={selected?.event_id} />
        ) : (
          <Empty label="No risky events in the recent window" />
        )}
      </div>

      <div className="panel">
        <div className="panel-header">
          <h3>Asset inventory</h3>
          <span className="hint">importance directly scales the asset risk component</span>
        </div>
        {permissions.investigate ? (
          <div className="filters" style={{ marginBottom: 12 }}>
            <div className="field">
              <label htmlFor="asset-ip">IP address</label>
              <input
                id="asset-ip"
                value={assetDraft.ip}
                onChange={(event) => setAssetDraft({ ...assetDraft, ip: event.target.value })}
                placeholder="192.168.50.10"
              />
            </div>
            <div className="field">
              <label htmlFor="asset-host">Hostname</label>
              <input
                id="asset-host"
                value={assetDraft.hostname}
                onChange={(event) => setAssetDraft({ ...assetDraft, hostname: event.target.value })}
                placeholder="finance-db-01"
              />
            </div>
            <div className="field">
              <label htmlFor="asset-imp">Importance (1-5)</label>
              <select
                id="asset-imp"
                value={assetDraft.importance}
                onChange={(event) => setAssetDraft({ ...assetDraft, importance: event.target.value })}
              >
                {[1, 2, 3, 4, 5].map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </div>
            <button className="sm primary" disabled={action.pending} onClick={saveAsset}>
              Save asset
            </button>
            {action.error ? <span className="form-error">{action.error.message}</span> : null}
          </div>
        ) : null}
        {assets?.items?.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th style={{ width: 140 }}>IP</th>
                  <th style={{ width: 200 }}>Hostname</th>
                  <th style={{ width: 120 }}>Type</th>
                  <th style={{ width: 110 }}>Importance</th>
                  <th>Tags / notes</th>
                </tr>
              </thead>
              <tbody>
                {assets.items.map((asset) => (
                  <tr key={asset.ip_address}>
                    <td className="mono">{asset.ip_address}</td>
                    <td>{asset.hostname || '—'}</td>
                    <td className="text-muted">{asset.asset_type}</td>
                    <td className="mono">{asset.importance}</td>
                    <td className="text-dim">
                      {(asset.tags || []).join(', ') || asset.notes || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty
            label="No assets registered"
            hint="Registering important hosts raises the risk score of activity involving them."
          />
        )}
      </div>

      {statistics ? (
        <div className="panel">
          <div className="panel-header">
            <h3>Collection health</h3>
            <span className="hint">where events come from</span>
          </div>
          <div className="kv">
            {(statistics.collectors || []).map((item) => (
              <span key={item.value} className="badge">
                {item.value || 'unknown'}: {formatNumber(item.count)}
              </span>
            ))}
            {statistics.events_per_second !== undefined ? (
              <span className="badge">peak window {formatNumber(statistics.events_per_second, 2)}/s</span>
            ) : null}
            <span className="badge">total {formatNumber(statistics.total_events)}</span>
            <span className="badge">
              bytes captured metadata only — no payloads are stored
            </span>
          </div>
        </div>
      ) : null}
    </>
  )
}
