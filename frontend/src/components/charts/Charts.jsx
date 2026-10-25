import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { SEVERITY_COLORS, distributionSeries, severityColor, toChartSeries } from '../../utils/format.js'
import { Empty } from '../common/States.jsx'

const AXIS = { stroke: '#6b7f9e', fontSize: 11 }
const GRID = { stroke: '#22304d', strokeDasharray: '3 3' }

const tooltipStyle = {
  contentStyle: {
    background: '#111a2b',
    border: '1px solid #2f4166',
    borderRadius: 6,
    fontSize: 12,
    color: '#e6edf7',
  },
  labelStyle: { color: '#94a6c4', fontSize: 11 },
}

/** Events / alerts over time — the "is it getting worse?" chart. */
export function TimeSeriesChart({ buckets = [], color = '#22d3ee', height = 220, label = 'count' }) {
  const data = toChartSeries(buckets)
  if (!data.length) return <Empty label="No data in this window" />
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 6, right: 12, bottom: 0, left: -18 }}>
        <defs>
          <linearGradient id={`grad-${color.replace('#', '')}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity={0.45} />
            <stop offset="100%" stopColor={color} stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid {...GRID} vertical={false} />
        <XAxis dataKey="label" {...AXIS} tickLine={false} minTickGap={24} />
        <YAxis {...AXIS} tickLine={false} allowDecimals={false} width={44} />
        <Tooltip {...tooltipStyle} formatter={(value) => [value, label]} />
        <Area
          type="monotone"
          dataKey="value"
          stroke={color}
          strokeWidth={2}
          fill={`url(#grad-${color.replace('#', '')})`}
        />
      </AreaChart>
    </ResponsiveContainer>
  )
}

export function MultiSeriesChart({ series = [], height = 220 }) {
  const { data, keys } = mergeSeries(series)
  if (!data.length) return <Empty label="No data in this window" />
  const palette = ['#22d3ee', '#fbbf24', '#fb923c', '#ef4444', '#34d399']
  return (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart data={data} margin={{ top: 6, right: 12, bottom: 0, left: -18 }}>
        <CartesianGrid {...GRID} vertical={false} />
        <XAxis dataKey="label" {...AXIS} tickLine={false} minTickGap={24} />
        <YAxis {...AXIS} tickLine={false} allowDecimals={false} width={44} />
        <Tooltip {...tooltipStyle} />
        <Legend wrapperStyle={{ fontSize: 11, color: '#94a6c4' }} />
        {keys.map((key, index) => (
          <Line
            key={key}
            type="monotone"
            dataKey={key}
            stroke={palette[index % palette.length]}
            strokeWidth={2}
            dot={false}
          />
        ))}
      </LineChart>
    </ResponsiveContainer>
  )
}

function mergeSeries(series) {
  const buckets = new Map()
  series.forEach(({ name, buckets: items }) => {
    toChartSeries(items).forEach((point, index) => {
      const existing = buckets.get(index) || { label: point.label }
      existing[name] = point.value
      buckets.set(index, existing)
    })
  })
  return { data: [...buckets.values()], keys: series.map((entry) => entry.name) }
}

/** Severity distribution: the analyst's triage order. */
export function SeverityPie({ items = [], height = 220 }) {
  const data = distributionSeries(items).map((item) => ({
    ...item,
    color: severityColor(item.label.toUpperCase()),
  }))
  if (!data.length) return <Empty label="No alerts in this window" />
  return (
    <ResponsiveContainer width="100%" height={height}>
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="label" innerRadius="52%" outerRadius="82%" paddingAngle={2}>
          {data.map((entry) => (
            <Cell key={entry.label} fill={entry.color} stroke="#0b1220" />
          ))}
        </Pie>
        <Tooltip {...tooltipStyle} />
        <Legend wrapperStyle={{ fontSize: 11, color: '#94a6c4' }} />
      </PieChart>
    </ResponsiveContainer>
  )
}

export function DistributionBar({ items = [], color = '#22d3ee', height = 220, horizontal = true }) {
  const data = distributionSeries(items).slice(0, 12)
  if (!data.length) return <Empty label="No data in this window" />
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart
        data={data}
        layout={horizontal ? 'vertical' : 'horizontal'}
        margin={{ top: 6, right: 16, bottom: 0, left: horizontal ? 8 : -18 }}
      >
        <CartesianGrid {...GRID} vertical={!horizontal} horizontal={horizontal} />
        {horizontal ? (
          <>
            <XAxis type="number" {...AXIS} tickLine={false} allowDecimals={false} />
            <YAxis type="category" dataKey="label" {...AXIS} tickLine={false} width={130} />
          </>
        ) : (
          <>
            <XAxis dataKey="label" {...AXIS} tickLine={false} />
            <YAxis {...AXIS} tickLine={false} allowDecimals={false} width={44} />
          </>
        )}
        <Tooltip {...tooltipStyle} />
        <Bar dataKey="value" fill={color} radius={[3, 3, 3, 3]} />
      </BarChart>
    </ResponsiveContainer>
  )
}

/** Ranked list with proportional bars (top talkers, top ports). */
export function BarList({ items = [], valueKey = 'count', labelKey = 'value', color = '#22d3ee', formatter }) {
  if (!items.length) return <Empty label="No data" />
  const max = Math.max(...items.map((item) => Number(item[valueKey]) || 0), 1)
  return (
    <div className="bar-list">
      {items.map((item) => {
        const label = item[labelKey] ?? 'unknown'
        const value = Number(item[valueKey]) || 0
        return (
          <div key={`${label}`} className="bar-row">
            <div style={{ minWidth: 0 }}>
              <div className="mono truncate" title={String(label)}>
                {formatter ? formatter(item) : String(label)}
              </div>
              <div className="bar-track">
                <div className="bar-fill" style={{ width: `${(value / max) * 100}%`, background: color }} />
              </div>
            </div>
            <div className="mono text-muted">{value.toLocaleString('en-GB')}</div>
          </div>
        )
      })}
    </div>
  )
}

export { SEVERITY_COLORS }
export default { TimeSeriesChart, MultiSeriesChart, SeverityPie, DistributionBar, BarList }
