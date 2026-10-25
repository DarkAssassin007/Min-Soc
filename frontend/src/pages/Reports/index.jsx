import { useMemo, useState } from 'react'
import { BarList, SeverityPie, TimeSeriesChart } from '../../components/charts/Charts.jsx'
import { Empty, ErrorBox, Loading } from '../../components/common/States.jsx'
import { useApi } from '../../hooks/useApi.js'
import { formatDateTime, formatNumber, percent } from '../../utils/format.js'

/**
 * Reports are generated from the same data the dashboard shows, so a report can
 * never disagree with the console. Export is client-side (JSON/CSV) which keeps
 * the API surface small and the data in the analyst's hands.
 */
export default function Reports() {
  const [minutes, setMinutes] = useState(1440)
  const { data: summary, error, loading, reload } = useApi('/dashboard/summary', { params: { minutes } })
  const { data: analytics } = useApi('/analytics', { params: { minutes, buckets: 24 } })
  const { data: alerts } = useApi('/alerts', { params: { minutes, limit: 200 } })
  const { data: incidents } = useApi('/incidents', { params: { limit: 100 } })
  const { data: models } = useApi('/models', { params: { minutes } })

  const report = useMemo(() => buildReport({ minutes, summary, analytics, alerts, incidents, models }), [
    minutes,
    summary,
    analytics,
    alerts,
    incidents,
    models,
  ])

  if (loading && !summary) return <Loading label="Generating report…" />
  if (error) return <ErrorBox error={error} onRetry={reload} />
  if (!summary) return <Empty label="Not enough data to build a report yet" />

  const download = (filename, content, type = 'application/json') => {
    const blob = new Blob([content], { type })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = filename
    anchor.click()
    URL.revokeObjectURL(url)
  }

  return (
    <>
      <div className="panel">
        <div className="panel-header">
          <h3>Report window</h3>
          <div className="filters">
            <div className="field">
              <label htmlFor="window">Period</label>
              <select id="window" value={minutes} onChange={(event) => setMinutes(Number(event.target.value))}>
                {[60, 240, 1440, 10080].map((value) => (
                  <option key={value} value={value}>
                    {value < 60 ? `${value} min` : value < 1440 ? `${value / 60} h` : `${value / 1440} d`}
                  </option>
                ))}
              </select>
            </div>
            <button className="sm" onClick={() => window.print()}>
              Print / save as PDF
            </button>
            <button
              className="sm"
              onClick={() => download(`mini-soc-report-${minutes}m.json`, JSON.stringify(report, null, 2))}
            >
              Export JSON
            </button>
            <button
              className="sm"
              onClick={() => download(`mini-soc-alerts-${minutes}m.csv`, report.alertsCsv, 'text/csv')}
            >
              Export alerts CSV
            </button>
          </div>
        </div>
        <div className="text-dim" style={{ fontSize: 12 }}>
          Generated {formatDateTime(report.generatedAt)} · window {report.windowLabel} · data source: live Mini SOC
          database
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h3>1. Posture summary</h3>
        </div>
        <div className="grid cols-4">
          <div className="stat-card">
            <div className="label">Events analysed</div>
            <div className="value">{formatNumber(report.totals.events)}</div>
            <div className="foot">{formatNumber(report.totals.eventsPerSecond, 1)}/s current throughput</div>
          </div>
          <div className="stat-card">
            <div className="label">Alerts raised</div>
            <div className="value">{formatNumber(report.totals.alerts)}</div>
            <div className="foot">
              {formatNumber(report.totals.criticalAlerts)} critical · {formatNumber(report.totals.openAlerts)} open
            </div>
          </div>
          <div className="stat-card">
            <div className="label">Incidents</div>
            <div className="value">{formatNumber(report.totals.incidents)}</div>
            <div className="foot">{formatNumber(report.totals.openIncidents)} still open</div>
          </div>
          <div className="stat-card">
            <div className="label">Analyst outcome</div>
            <div className="value">{percent(report.outcomes.resolutionRate)}</div>
            <div className="foot">
              {formatNumber(report.outcomes.resolved)} resolved · {formatNumber(report.outcomes.falsePositives)} false
              positives
            </div>
          </div>
        </div>
      </div>

      <div className="grid cols-2">
        <div className="panel">
          <div className="panel-header">
            <h3>2. Activity trend</h3>
          </div>
          <TimeSeriesChart buckets={summary.network_activity} color="#22d3ee" label="events" />
        </div>
        <div className="panel">
          <div className="panel-header">
            <h3>3. Threat severity mix</h3>
          </div>
          <SeverityPie items={summary.severity_distribution} />
        </div>
      </div>

      <div className="grid cols-3">
        <div className="panel">
          <div className="panel-header">
            <h3>4. Top attack sources</h3>
          </div>
          <BarList items={summary.high_risk_sources} labelKey="source_ip" valueKey="max_risk" color="#ef4444" />
        </div>
        <div className="panel">
          <div className="panel-header">
            <h3>5. Detection coverage</h3>
          </div>
          <BarList items={analytics?.rule_frequency} color="#fbbf24" />
        </div>
        <div className="panel">
          <div className="panel-header">
            <h3>6. Targeted services</h3>
          </div>
          <BarList items={analytics?.top_attacked_ports} color="#38bdf8" />
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h3>7. Detection engine performance</h3>
          <span className="hint">measured during this window</span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Capability</th>
                <th style={{ width: 220 }}>Result</th>
                <th>Notes</th>
              </tr>
            </thead>
            <tbody>
              {report.engineRows.map((row) => (
                <tr key={row.capability}>
                  <td>{row.capability}</td>
                  <td className="mono">{row.result}</td>
                  <td className="text-muted">{row.notes}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h3>8. Recommended follow-up</h3>
        </div>
        <ul style={{ margin: '0 0 0 18px', fontSize: 13 }}>
          {report.recommendations.map((item) => (
            <li key={item} style={{ marginBottom: 6 }}>
              {item}
            </li>
          ))}
        </ul>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h3>9. Highest risk alerts in the window</h3>
          <span className="hint">{formatNumber(alerts?.items?.length || 0)} alerts examined</span>
        </div>
        {report.topAlerts.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th style={{ width: 100 }}>Alert</th>
                  <th style={{ width: 150 }}>Detection</th>
                  <th style={{ width: 90 }}>Severity</th>
                  <th style={{ width: 80 }}>Score</th>
                  <th style={{ width: 130 }}>Source</th>
                  <th>Description</th>
                </tr>
              </thead>
              <tbody>
                {report.topAlerts.map((alert) => (
                  <tr key={alert.alert_id}>
                    <td className="mono">{alert.alert_id}</td>
                    <td>{String(alert.detection_type).replace(/_/g, ' ')}</td>
                    <td>{alert.severity}</td>
                    <td className="mono">{Number(alert.risk_score).toFixed(1)}</td>
                    <td className="mono">{alert.source_ip || '—'}</td>
                    <td className="text-muted">{alert.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty label="No alerts in this window" hint="A quiet window is a valid report outcome." />
        )}
      </div>
    </>
  )
}

function buildReport({ minutes, summary, analytics, alerts, incidents, models }) {
  const alertItems = alerts?.items || []
  const incidentItems = incidents?.items || []
  const resolved = alertItems.filter((alert) => ['RESOLVED', 'FALSE_POSITIVE'].includes(alert.status)).length
  const falsePositives = alertItems.filter((alert) => alert.status === 'FALSE_POSITIVE').length
  const severityTotals = (summary?.severity_distribution || []).reduce((acc, item) => {
    acc[item.value] = item.count
    return acc
  }, {})

  const modelsSummary = models?.artifacts?.length
    ? models.artifacts.map((artifact) => ({
        capability: `ML anomaly model · ${artifact.name}`,
        result: `${artifact.version} (${artifact.algorithm})`,
        notes: artifact.metrics
          ? `precision ${artifact.metrics.precision} · recall ${artifact.metrics.recall} · F1 ${artifact.metrics.f1_score} · FPR ${artifact.metrics.false_positive_rate}`
          : 'metrics not recorded',
      }))
    : []

  return {
    generatedAt: new Date().toISOString(),
    windowMinutes: minutes,
    windowLabel: minutes < 60 ? `${minutes} minutes` : minutes < 1440 ? `${minutes / 60} hours` : `${minutes / 1440} days`,
    totals: {
      events: summary?.events?.last_24h ?? summary?.events?.total ?? 0,
      eventsPerSecond: summary?.events?.per_second || 0,
      alerts: summary?.alerts?.total || 0,
      criticalAlerts: summary?.alerts?.critical || 0,
      openAlerts: summary?.alerts?.active ?? summary?.alerts?.open_total ?? 0,
      incidents: summary?.incidents?.total || 0,
      openIncidents: summary?.incidents?.open || 0,
    },
    severity: severityTotals,
    outcomes: {
      resolved,
      falsePositives,
      resolutionRate: alertItems.length ? resolved / alertItems.length : 0,
    },
    topAlerts: alertItems
      .slice()
      .sort((a, b) => (Number(b.risk_score) || 0) - (Number(a.risk_score) || 0))
      .slice(0, 15),
    incidents: incidentItems.slice(0, 10),
    recommendations: buildRecommendations({ summary, analytics, alertItems, incidentItems }),
    engineRows: [
      {
        capability: 'Rule engine',
        result: `${formatNumber((analytics?.rule_frequency || []).reduce((sum, item) => sum + item.count, 0))} detections`,
        notes: `${(analytics?.rule_frequency || []).length} distinct rules fired in the window`,
      },
      {
        capability: 'Detection pipeline',
        result: `${formatNumber(summary?.events?.per_second || 0, 2)} events/s`,
        notes: 'normalisation, deduplication and feature extraction run per event',
      },
      ...modelsSummary,
    ],
    alertsCsv: toCsv(
      alertItems.map((alert) => ({
        alert_id: alert.alert_id,
        first_seen: alert.first_seen,
        last_seen: alert.last_seen,
        source_ip: alert.source_ip || '',
        destination_ip: alert.destination_ip || '',
        detection_type: alert.detection_type,
        rule_key: alert.rule_key || '',
        engine: alert.engine,
        severity: alert.severity,
        risk_score: alert.risk_score,
        confidence: alert.confidence,
        status: alert.status,
        occurrences: alert.event_count,
        incident_id: alert.incident_id || '',
        description: (alert.description || '').replace(/[\r\n]+/g, ' '),
      })),
    ),
  }
}

function buildRecommendations({ summary, analytics, alertItems, incidentItems }) {
  const items = []
  const openIncidents = incidentItems.filter((incident) => !['RESOLVED', 'CLOSED'].includes(incident.status))
  if (openIncidents.length) {
    items.push(
      `${openIncidents.length} incident(s) are still open — review the timelines, confirm containment and record a resolution.`,
    )
  }
  const critical = alertItems.filter((alert) => alert.severity === 'CRITICAL' && alert.status === 'NEW')
  if (critical.length) {
    items.push(`${critical.length} critical alert(s) are unacknowledged; triage them before anything else.`)
  }
  const topSource = (summary?.high_risk_sources || [])[0]
  if (topSource) {
    items.push(
      `Highest risk source is ${topSource.source_ip} (peak risk ${Number(topSource.max_risk).toFixed(1)} across ${topSource.events} events) — confirm whether it is an expected internal host.`,
    )
  }
  const ruleFrequency = analytics?.rule_frequency || []
  if (ruleFrequency.length === 0) {
    items.push('No detection rules fired in this window: confirm the collectors are receiving traffic before concluding the network is quiet.')
  } else if (ruleFrequency[0]) {
    items.push(`Most frequent detection is ${ruleFrequency[0].value} — tune its threshold if it is producing noise.`)
  }
  const falsePositives = alertItems.filter((alert) => alert.status === 'FALSE_POSITIVE').length
  if (falsePositives) {
    items.push(
      `${falsePositives} alert(s) were marked false positive — adjust the corresponding rule parameters to reduce analyst load.`,
    )
  }
  if (!items.length) items.push('No follow-up required for this window.')
  return items
}

function toCsv(rows) {
  if (!rows.length) return ''
  const headers = Object.keys(rows[0])
  const escape = (value) => {
    const text = value === null || value === undefined ? '' : String(value)
    return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text
  }
  return [headers.join(','), ...rows.map((row) => headers.map((header) => escape(row[header])).join(','))].join('\n')
}
