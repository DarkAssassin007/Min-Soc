export function StatCard({ label, value, foot, accent, title }) {
  const accentClass =
    accent === 'critical' ? 'accent-critical' : accent === 'high' ? 'accent-high' : ''
  return (
    <div className={`stat-card ${accentClass}`} title={title}>
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      {foot ? <div className="foot">{foot}</div> : null}
    </div>
  )
}

export default StatCard
