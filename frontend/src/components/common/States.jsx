import { severityClass, severityColor } from '../../utils/format.js'

export function Loading({ label = 'Loading…' }) {
  return <div className="loading">{label}</div>
}

export function Empty({ label = 'Nothing to show', hint }) {
  return (
    <div className="empty">
      <div>{label}</div>
      {hint ? <div className="form-note" style={{ marginTop: 6 }}>{hint}</div> : null}
    </div>
  )
}

export function ErrorBox({ error, onRetry }) {
  if (!error) return null
  return (
    <div className="error-box">
      <div>{error.message || 'Request failed'}</div>
      {onRetry ? (
        <div style={{ marginTop: 10 }}>
          <button className="sm" onClick={() => onRetry()}>
            Retry
          </button>
        </div>
      ) : null}
    </div>
  )
}

export function Severity({ value, showScore }) {
  // Accepts either a severity string or an object (event/alert/incident record).
  const isRecord = Boolean(value) && typeof value === 'object'
  const severity = String((isRecord ? value.severity : value) || 'LOW').toUpperCase()
  const score = isRecord ? value.risk_score : undefined
  return (
    <span className={severityClass(severity)} title={`Severity ${severity}`}>
      <span className="sev-dot" style={{ background: severityColor(severity) }} />
      {severity}
      {showScore && Number.isFinite(Number(score)) ? (
        <span className="text-dim mono" style={{ marginLeft: 6 }}>
          {Number(score).toFixed(0)}
        </span>
      ) : null}
    </span>
  )
}

export function RiskScore({ score }) {
  const value = Number(score) || 0
  return (
    <span className="mono" style={{ color: severityColor(value > 80 ? 'CRITICAL' : value > 60 ? 'HIGH' : value > 30 ? 'MEDIUM' : 'LOW') }}>
      {value.toFixed(1)}
    </span>
  )
}

export function StatusBadge({ status }) {
  const normalized = String(status || '').toUpperCase()
  const tone =
    normalized === 'NEW'
      ? 'warn'
      : normalized === 'RESOLVED' || normalized === 'CLOSED'
        ? 'ok'
        : normalized === 'FALSE_POSITIVE'
          ? ''
          : ''
  return <span className={`badge ${tone}`}>{normalized || 'UNKNOWN'}</span>
}

export function LiveDot({ active, label }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
      <span className={`pulse ${active ? '' : 'stale'}`} />
      <span className="text-muted" style={{ fontSize: 11.5 }}>
        {label}
      </span>
    </span>
  )
}

export function KeyValue({ items }) {
  return (
    <dl className="detail-grid">
      {items.filter(Boolean).map(({ label, value }) => (
        <div key={label} style={{ display: 'contents' }}>
          <dt>{label}</dt>
          <dd>{value ?? '—'}</dd>
        </div>
      ))}
    </dl>
  )
}

export default { Loading, Empty, ErrorBox, Severity, RiskScore, StatusBadge, LiveDot, KeyValue }
