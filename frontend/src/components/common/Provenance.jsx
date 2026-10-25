/**
 * Provenance: where a record came from.
 *
 * Every event and alert reports the collector that produced it plus, when the
 * source has one, the interface/endpoint it arrived on (`interface` for raw
 * events, copied from `collectors`/`interfaces` for aggregated alerts). Anything
 * produced by the authorized-lab generator is labelled LAB so synthetic traffic
 * can never be read as observed traffic.
 */
const COLLECTOR_LABELS = {
  packet: 'live capture',
  syslog: 'syslog feed',
  system: 'host telemetry',
  api: 'api ingest',
  synthetic: 'lab generator',
}

export function collectorLabel(collector) {
  if (!collector) return 'unknown source'
  return COLLECTOR_LABELS[collector] || collector
}

export function originOf(record) {
  if (!record) return 'UNKNOWN'
  if (record.data_origin || record.origin) return record.data_origin || record.origin
  const collectors = record.collectors || (record.collector ? [record.collector] : [])
  if (collectors.includes('synthetic') || record.lab) return 'LAB'
  return collectors.length ? 'LIVE' : 'UNKNOWN'
}

export function sourceOf(record) {
  if (!record) return { collectors: [], interfaces: [] }
  const collectors = record.collectors || (record.collector ? [record.collector] : [])
  const interfaces = record.interfaces || (record.interface ? [record.interface] : [])
  return { collectors, interfaces }
}

/** Short text used in dense tables: "packet · Ethernet" or "lab generator". */
export function provenanceText(record) {
  const { collectors, interfaces } = sourceOf(record)
  if (!collectors.length) return '—'
  const name = collectors.join(' + ')
  return interfaces.length ? `${name} · ${interfaces.join(' + ')}` : name
}

/** Full sentence used as the tooltip. */
export function provenanceTitle(record) {
  const { collectors, interfaces } = sourceOf(record)
  const origin = originOf(record)
  if (!collectors.length) return 'Source not recorded for this record'
  const feeds = collectors.map((collector) => collectorLabel(collector)).join(', ')
  const where = interfaces.length ? ` on ${interfaces.join(', ')}` : ''
  const prefix = origin === 'LAB' ? 'LAB-GENERATED (not observed traffic) — ' : ''
  return `${prefix}${feeds}${where}`
}

export function ProvenanceTag({ record, compact = false, showInterface = true }) {
  const { collectors, interfaces } = sourceOf(record)
  const origin = originOf(record)
  if (!collectors.length && origin === 'UNKNOWN') {
    return <span className="text-dim">—</span>
  }
  const lab = origin === 'LAB'
  const title = provenanceTitle(record)
  return (
    <span className={`prov${lab ? ' lab' : ''}`} title={title}>
      <span className={`prov-dot ${lab ? 'lab' : origin === 'LIVE' ? 'live' : 'unknown'}`} />
      {lab ? <span className="prov-lab">LAB</span> : null}
      <span className="prov-name">{collectors.join(' + ') || 'unknown'}</span>
      {showInterface && !compact && interfaces.length ? (
        <span className="prov-iface">{interfaces.join(' + ')}</span>
      ) : null}
    </span>
  )
}

export default ProvenanceTag
