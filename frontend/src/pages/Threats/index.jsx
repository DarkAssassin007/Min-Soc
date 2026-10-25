import { useState } from 'react'
import { BarList, SeverityPie, TimeSeriesChart } from '../../components/charts/Charts.jsx'
import { Empty, ErrorBox, Loading } from '../../components/common/States.jsx'
import { AlertTable } from '../../components/tables/Tables.jsx'
import { useApi } from '../../hooks/useApi.js'
import { formatNumber, percent } from '../../utils/format.js'

export default function Threats() {
  const [minutes, setMinutes] = useState(1440)
  const { data, error, loading, reload } = useApi('/threats', { params: { minutes }, pollMs: 20000 })
  const { data: recentAlerts } = useApi('/alerts', { params: { limit: 20 }, pollMs: 20000 })

  if (loading && !data) return <Loading label="Loading threat activity…" />
  if (error) return <ErrorBox error={error} onRetry={reload} />
  if (!data) return <Empty label="No threat data yet" />

  const models = data.ml_anomalies || []

  return (
    <>
      <div className="panel">
        <div className="panel-header">
          <h3>Attacks over time</h3>
          <div className="filters">
            <div className="field">
              <label htmlFor="window">Window</label>
              <select id="window" value={minutes} onChange={(event) => setMinutes(Number(event.target.value))}>
                {[60, 240, 1440, 10080].map((value) => (
                  <option key={value} value={value}>
                    {value < 60 ? `${value} min` : value < 1440 ? `${value / 60} h` : `${value / 1440} d`}
                  </option>
                ))}
              </select>
            </div>
            <span className="text-dim" style={{ fontSize: 11.5 }}>
              {formatNumber(data.active_alerts?.active)} open · {formatNumber(data.active_alerts?.critical)} critical
            </span>
          </div>
        </div>
        <TimeSeriesChart buckets={data.alerts_over_time} color="#ef4444" label="alerts" height={240} />
      </div>

      <div className="grid cols-3">
        <div className="panel">
          <div className="panel-header">
            <h3>Severity mix</h3>
            <span className="hint">what analysts should look at first</span>
          </div>
          <SeverityPie items={data.severity_distribution} />
        </div>
        <div className="panel">
          <div className="panel-header">
            <h3>Attack techniques</h3>
            <span className="hint">detection types</span>
          </div>
          <BarList items={data.detection_types} color="#fb923c" />
        </div>
        <div className="panel">
          <div className="panel-header">
            <h3>Rules firing</h3>
            <span className="hint">rule coverage in use</span>
          </div>
          <BarList items={data.rule_frequency} color="#22d3ee" />
        </div>
      </div>

      <div className="grid cols-3">
        <div className="panel">
          <div className="panel-header">
            <h3>Threat sources</h3>
            <span className="hint">peak risk per source</span>
          </div>
          <BarList
            items={data.top_threat_sources}
            labelKey="source_ip"
            valueKey="max_risk"
            color="#ef4444"
            formatter={(item) => `${item.source_ip} · ${formatNumber(item.events)} events`}
          />
        </div>
        <div className="panel">
          <div className="panel-header">
            <h3>Targeted ports</h3>
            <span className="hint">what the attacks aim at</span>
          </div>
          <BarList items={data.targeted_ports} color="#fbbf24" />
        </div>
        <div className="panel">
          <div className="panel-header">
            <h3>ML anomaly engine</h3>
            <span className="hint">model behaviour in this window</span>
          </div>
          {models.length ? (
            <div className="bar-list">
              {models.map((model) => (
                <div key={`${model.model_name}-${model.model_version}`}>
                  <div className="mono" style={{ fontSize: 12.5 }}>
                    {model.model_name}:{model.model_version}
                  </div>
                  <div className="text-dim" style={{ fontSize: 11.5 }}>
                    {formatNumber(model.predictions)} inferences ·{' '}
                    {formatNumber(model.anomalies)} flagged (
                    {percent(model.predictions ? model.anomalies / model.predictions : 0)}) ·{' '}
                    {(model.avg_latency_ms || 0).toFixed(2)} ms mean
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <Empty label="No ML inferences recorded yet" hint="The detector scores every event when a model is deployed." />
          )}
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h3>Recent alerts</h3>
          <span className="hint">click through from the Alerts page for full investigation</span>
        </div>
        {recentAlerts?.items?.length ? (
          <AlertTable alerts={recentAlerts.items} />
        ) : (
          <Empty label="No alerts" />
        )}
      </div>
    </>
  )
}
