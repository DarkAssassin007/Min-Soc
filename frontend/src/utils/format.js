/** Formatting helpers shared by every page (keeps the colour language consistent). */

export const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
export const SEVERITY_COLORS = {
  LOW: '#38bdf8',
  MEDIUM: '#fbbf24',
  HIGH: '#fb923c',
  CRITICAL: '#ef4444',
}
export const SEVERITY_RANK = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 }

export function severityClass(severity) {
  return `sev sev-${(severity || 'LOW').toUpperCase()}`
}

export function severityColor(severity) {
  return SEVERITY_COLORS[(severity || 'LOW').toUpperCase()] || '#6b7f9e'
}

export function riskColor(score) {
  const value = Number(score) || 0
  if (value > 80) return SEVERITY_COLORS.CRITICAL
  if (value > 60) return SEVERITY_COLORS.HIGH
  if (value > 30) return SEVERITY_COLORS.MEDIUM
  return SEVERITY_COLORS.LOW
}

export function formatTime(value, { withDate = false, seconds = true } = {}) {
  if (!value) return '—'
  const date = new Date(value.endsWith && value.endsWith('Z') ? value : `${value}${value.includes('+') ? '' : 'Z'}`)
  if (Number.isNaN(date.getTime())) return String(value)
  const options = {
    hour: '2-digit',
    minute: '2-digit',
    ...(seconds ? { second: '2-digit' } : {}),
    hour12: false,
    ...(withDate ? { day: '2-digit', month: 'short' } : {}),
  }
  return date.toLocaleTimeString('en-GB', options)
}

export function formatDateTime(value) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return String(value)
  return `${date.toLocaleDateString('en-GB')} ${date.toLocaleTimeString('en-GB', { hour12: false })}`
}

export function relativeTime(value) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return String(value)
  const delta = (Date.now() - date.getTime()) / 1000
  if (delta < 60) return `${Math.max(Math.round(delta), 0)}s ago`
  if (delta < 3600) return `${Math.round(delta / 60)}m ago`
  if (delta < 86400) return `${Math.round(delta / 3600)}h ago`
  return `${Math.round(delta / 86400)}d ago`
}

export function formatNumber(value, digits = 0) {
  const number = Number(value)
  if (!Number.isFinite(number)) return '0'
  return number.toLocaleString('en-GB', { minimumFractionDigits: digits, maximumFractionDigits: digits })
}

export function formatBytes(bytes) {
  const value = Number(bytes) || 0
  if (value < 1024) return `${value} B`
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MB`
  return `${(value / 1024 ** 3).toFixed(2)} GB`
}

export function formatDuration(seconds) {
  const value = Number(seconds) || 0
  if (value < 60) return `${value.toFixed(1)}s`
  if (value < 3600) return `${Math.floor(value / 60)}m ${Math.round(value % 60)}s`
  const hours = Math.floor(value / 3600)
  const minutes = Math.round((value % 3600) / 60)
  return `${hours}h ${minutes}m`
}

export function shortId(value, length = 12) {
  if (!value) return '—'
  return value.length > length ? `${value.slice(0, length)}…` : value
}

export function truncate(value, length = 60) {
  if (value === null || value === undefined) return '—'
  const text = String(value)
  return text.length > length ? `${text.slice(0, length)}…` : text
}

export function percent(value, digits = 1) {
  const number = Number(value)
  if (!Number.isFinite(number)) return '0%'
  return `${(number * 100).toFixed(digits)}%`
}

export function bucketLabel(value) {
  return formatTime(value, { seconds: false })
}

export function toChartSeries(buckets = []) {
  return buckets.map((bucket) => ({
    label: bucketLabel(bucket.bucket_start || bucket.bucket_end),
    value: Number(bucket.count) || 0,
  }))
}

export function distributionSeries(items = []) {
  return items.map((item) => ({
    label: item.value === null || item.value === undefined ? 'unknown' : String(item.value),
    value: Number(item.count) || 0,
  }))
}
