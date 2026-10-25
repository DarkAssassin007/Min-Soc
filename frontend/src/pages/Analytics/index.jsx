import { useState } from 'react'
import {
  BarList,
  DistributionBar,
  MultiSeriesChart,
  SeverityPie,
  TimeSeriesChart,
} from '../../components/charts/Charts.jsx'
import { Empty, ErrorBox, Loading } from '../../components/common/States.jsx'
import { useApi } from '../../hooks/useApi.js'
import { formatNumber } from '../../utils/format.js'

export default function Analytics() {
  const [minutes, setMinutes] = useState(1440)
  const [buckets, setBuckets] = useState(24)
  const { data, error, loading, reload } = useApi('/analytics', {
    params: { minutes, buckets },
    pollMs: 60000,
  })

  if (loading && !data) return <Loading label="Loading analytics…" />
  if (error) return <ErrorBox error={error} onRetry={reload} />
  if (!data) return <Empty label="No analytics available yet" />

  return (
    <>
      <div className="panel">
        <div className="panel-header">
          <h3>Events, detections and alerts</h3>
          <div className="filters">
            <div className="field">
              <label htmlFor="window">Window</label>
              <select id="window" value={minutes} onChange={(event) => setMinutes(Number(event.target.value))}>
                {[60, 240, 1440, 10080, 43200].map((value) => (
                  <option key={value} value={value}>
                    {value < 60 ? `${value} min` : value < 1440 ? `${value / 60} h` : `${value / 1440} d`}
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label htmlFor="buckets">Resolution</label>
              <select id="buckets" value={buckets} onChange={(event) => setBuckets(Number(event.target.value))}>
                {[12, 24, 48, 96].map((value) => (
                  <option key={value} value={value}>
                    {value} buckets
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>
        <MultiSeriesChart
          series={[
            { name: 'events', buckets: data.events_over_time },
            { name: 'detections', buckets: data.detections_over_time },
            { name: 'alerts', buckets: data.alerts_over_time },
          ]}
          height={260}
        />
      </div>

      <div className="grid cols-2">
        <div className="panel">
          <div className="panel-header">
            <h3>Alert severity over the window</h3>
            <span className="hint">
              {formatNumber((data.severity_distribution || []).reduce((sum, item) => sum + item.count, 0))} alerts
            </span>
          </div>
          <SeverityPie items={data.severity_distribution} height={240} />
        </div>
        <div className="panel">
          <div className="panel-header">
            <h3>Detection type distribution</h3>
            <span className="hint">which detections dominate</span>
          </div>
          <DistributionBar items={data.detection_type_distribution} color="#fb923c" height={240} />
        </div>
      </div>

      <div className="grid cols-4">
        <div className="panel">
          <div className="panel-header">
            <h3>Top source IPs</h3>
          </div>
          <BarList items={data.top_source_ips} color="#22d3ee" />
        </div>
        <div className="panel">
          <div className="panel-header">
            <h3>Top destination IPs</h3>
          </div>
          <BarList items={data.top_destination_ips} color="#38bdf8" />
        </div>
        <div className="panel">
          <div className="panel-header">
            <h3>Top attacked ports</h3>
          </div>
          <BarList items={data.top_attacked_ports} color="#fbbf24" />
        </div>
        <div className="panel">
          <div className="panel-header">
            <h3>Rules firing</h3>
          </div>
          <BarList items={data.rule_frequency} color="#34d399" />
        </div>
      </div>

      <div className="grid cols-2">
        <div className="panel">
          <div className="panel-header">
            <h3>Protocol distribution (24h)</h3>
            <span className="hint">baseline shape for anomaly comparisons</span>
          </div>
          <DistributionBar items={data.protocol_distribution} color="#34d399" height={240} />
        </div>
        <div className="panel">
          <div className="panel-header">
            <h3>Incidents by severity</h3>
            <span className="hint">outcomes, not just alerts</span>
          </div>
          <DistributionBar items={data.incidents_by_severity} color="#ef4444" height={240} />
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h3>Anomaly engine performance</h3>
          <span className="hint">measured, not claimed</span>
        </div>
        {(data.anomaly_distribution || []).length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Model</th>
                  <th style={{ width: 130 }}>Version</th>
                  <th style={{ width: 130 }}>Inferences</th>
                  <th style={{ width: 130 }}>Anomalies</th>
                  <th style={{ width: 150 }}>Anomaly rate</th>
                  <th style={{ width: 150 }}>Mean latency</th>
                </tr>
              </thead>
              <tbody>
                {data.anomaly_distribution.map((model) => (
                  <tr key={`${model.model_name}-${model.model_version}`}>
                    <td>{model.model_name}</td>
                    <td className="mono">{model.model_version}</td>
                    <td className="mono">{formatNumber(model.predictions)}</td>
                    <td className="mono">{formatNumber(model.anomalies)}</td>
                    <td className="mono">
                      {model.predictions ? `${((model.anomalies / model.predictions) * 100).toFixed(2)}%` : '0%'}
                    </td>
                    <td className="mono">{(model.avg_latency_ms || 0).toFixed(3)} ms</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty label="No model inferences in this window" />
        )}
      </div>
    </>
  )
}
