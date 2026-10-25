import { useMemo, useState } from 'react'
import { Empty, ErrorBox, LiveDot, Severity } from '../../components/common/States.jsx'
import { EventDetail } from '../../components/alerts/DetailPanels.jsx'
import { ProvenanceTag } from '../../components/common/Provenance.jsx'
import { useChannel } from '../../hooks/useWebSocket.js'
import { useApi } from '../../hooks/useApi.js'
import { SEVERITIES, formatBytes, formatNumber, formatTime } from '../../utils/format.js'

export default function LiveMonitor() {
  const [filters, setFilters] = useState({ severity: '', protocol: '', address: '' })
  const [paused, setPaused] = useState(false)
  const [selected, setSelected] = useState(null)
  const [pausedBuffer, setPausedBuffer] = useState([])

  const { buffer, status, lastMessageAt, clear } = useChannel('live', {
    onMessage: (payload) => {
      if (paused && payload?.type === 'events') {
        setPausedBuffer((current) => [...payload.data, ...current].slice(0, 500))
      }
    },
  })
  const { data: metrics } = useApi('/system/metrics', { pollMs: 5000, params: { history: 0 } })

  const rows = useMemo(() => {
    const source = paused ? pausedBuffer : buffer
    return source.filter((event) => {
      if (filters.severity && event.severity !== filters.severity) return false
      if (filters.protocol && event.protocol !== filters.protocol) return false
      if (filters.address) {
        const needle = filters.address.trim()
        if (!`${event.source_ip} ${event.destination_ip}`.includes(needle)) return false
      }
      return true
    })
  }, [buffer, pausedBuffer, paused, filters])

  const byProtocol = useMemo(() => {
    const counts = {}
    buffer.forEach((event) => {
      counts[event.protocol] = (counts[event.protocol] || 0) + 1
    })
    return Object.entries(counts).sort((a, b) => b[1] - a[1])
  }, [buffer])

  const resume = () => {
    setPaused(false)
    setPausedBuffer([])
  }

  return (
    <>
      <div className="grid cols-4">
        <div className="panel" style={{ padding: '12px 16px' }}>
          <div className="label text-dim" style={{ fontSize: 11 }}>
            Feed
          </div>
          <div style={{ marginTop: 6 }}>
            <LiveDot active={status === 'open' && !paused} label={paused ? 'paused' : status} />
          </div>
          <div className="text-dim" style={{ fontSize: 11.5, marginTop: 4 }}>
            last message {lastMessageAt ? formatTime(lastMessageAt) : '—'}
          </div>
        </div>
        <div className="panel" style={{ padding: '12px 16px' }}>
          <div className="label text-dim" style={{ fontSize: 11 }}>
            Throughput
          </div>
          <div className="value" style={{ fontSize: 20 }}>
            {formatNumber(metrics?.events_per_second || 0, 1)}/s
          </div>
          <div className="text-dim" style={{ fontSize: 11.5 }}>
            {formatNumber(metrics?.events_total || 0)} processed · queue {formatNumber(metrics?.queue_depth || 0)}
          </div>
        </div>
        <div className="panel" style={{ padding: '12px 16px' }}>
          <div className="label text-dim" style={{ fontSize: 11 }}>
            Pipeline latency
          </div>
          <div className="value" style={{ fontSize: 20 }}>
            {(metrics?.latency?.processing?.mean_ms || 0).toFixed(1)}
            <span style={{ fontSize: 13 }}> ms</span>
          </div>
          <div className="text-dim" style={{ fontSize: 11.5 }}>
            detection {(metrics?.latency?.detection?.mean_ms || 0).toFixed(2)} ms · ws{' '}
            {(metrics?.latency?.websocket?.mean_ms || 0).toFixed(2)} ms
          </div>
        </div>
        <div className="panel" style={{ padding: '12px 16px' }}>
          <div className="label text-dim" style={{ fontSize: 11 }}>
            Protocols in buffer
          </div>
          <div style={{ marginTop: 6, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {byProtocol.length ? (
              byProtocol.map(([protocol, count]) => (
                <span key={protocol} className="badge">
                  {protocol} {count}
                </span>
              ))
            ) : (
              <span className="text-dim" style={{ fontSize: 12 }}>
                waiting for traffic
              </span>
            )}
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h3>Live network activity</h3>
          <div className="filters">
            <div className="field">
              <label htmlFor="sev">Severity</label>
              <select
                id="sev"
                value={filters.severity}
                onChange={(event) => setFilters({ ...filters, severity: event.target.value })}
              >
                <option value="">all</option>
                {SEVERITIES.map((severity) => (
                  <option key={severity} value={severity}>
                    {severity}
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label htmlFor="proto">Protocol</label>
              <select
                id="proto"
                value={filters.protocol}
                onChange={(event) => setFilters({ ...filters, protocol: event.target.value })}
              >
                <option value="">all</option>
                {['TCP', 'UDP', 'ICMP', 'ICMPV6', 'ARP', 'OTHER'].map((protocol) => (
                  <option key={protocol} value={protocol}>
                    {protocol}
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label htmlFor="addr">Address contains</label>
              <input
                id="addr"
                value={filters.address}
                onChange={(event) => setFilters({ ...filters, address: event.target.value })}
                placeholder="192.168.50."
              />
            </div>
            <button className="sm" onClick={() => (paused ? resume() : setPaused(true))}>
              {paused ? 'Resume' : 'Pause'}
            </button>
            <button className="sm ghost" onClick={() => (paused ? setPausedBuffer([]) : clear())}>
              Clear
            </button>
          </div>
        </div>

        {status === 'rejected' ? (
          <ErrorBox error={{ message: 'Live feed rejected by the server (session expired?)' }} onRetry={resume} />
        ) : null}

        {rows.length === 0 ? (
          <Empty
            label="No events in the live buffer"
            hint="Traffic appears here as the live collectors normalize it. Nothing is generated locally: the feed is populated only by real packet capture and syslog events."
          />
        ) : (
          <div className="live-feed">
            <div className="live-row header">
              <span>Time</span>
              <span>Source</span>
              <span>Destination</span>
              <span>Proto</span>
              <span>Risk</span>
              <span>Source feed</span>
              <span>Type / detail</span>
            </div>
            {rows.slice(0, 300).map((event) => (
              <div
                key={`${event.event_id}-${event.timestamp}`}
                className="live-row"
                onClick={() => setSelected(event)}
                style={{ cursor: 'pointer' }}
              >
                <span className="text-muted">{formatTime(event.timestamp)}</span>
                <span>{event.source_ip || '—'}</span>
                <span>
                  {event.destination_ip || '—'}
                  {event.destination_port ? `:${event.destination_port}` : ''}
                </span>
                <span className="text-muted">{event.protocol}</span>
                <span>
                  <Severity value={event} showScore />
                </span>
                <span>
                  <ProvenanceTag record={event} />
                </span>
                <span className="text-dim truncate" title={event.event_type}>
                  {String(event.event_type).replace(/_/g, ' ')}
                  {event.metadata?.tls_sni ? ` · ${event.metadata.tls_sni}` : ''}
                  {event.metadata?.dns_query ? ` · ${event.metadata.dns_query}` : ''}
                  {event.bytes ? ` · ${formatBytes(event.bytes)}` : ''}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {selected ? (
        <div className="panel">
          <div className="panel-header">
            <h3>Event detail — {selected.event_id}</h3>
            <button className="sm ghost" onClick={() => setSelected(null)}>
              Close
            </button>
          </div>
          <EventDetail event={selected} />
        </div>
      ) : null}
    </>
  )
}
