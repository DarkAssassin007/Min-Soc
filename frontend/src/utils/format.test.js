import { describe, expect, it } from 'vitest'
import {
  distributionSeries,
  formatBytes,
  formatDuration,
  formatNumber,
  percent,
  riskColor,
  SEVERITY_COLORS,
  severityClass,
  severityColor,
  toChartSeries,
  truncate,
} from './format.js'

describe('severity helpers', () => {
  it('builds the severity class used by the colour language', () => {
    expect(severityClass('critical')).toBe('sev sev-CRITICAL')
    expect(severityClass(undefined)).toBe('sev sev-LOW')
  })

  it('maps severities and risk scores to colours consistently', () => {
    expect(severityColor('HIGH')).toBe(SEVERITY_COLORS.HIGH)
    expect(riskColor(95)).toBe(SEVERITY_COLORS.CRITICAL)
    expect(riskColor(70)).toBe(SEVERITY_COLORS.HIGH)
    expect(riskColor(40)).toBe(SEVERITY_COLORS.MEDIUM)
    expect(riskColor(5)).toBe(SEVERITY_COLORS.LOW)
  })
})

describe('number and size formatting', () => {
  it('formats bytes with sensible units', () => {
    expect(formatBytes(512)).toBe('512 B')
    expect(formatBytes(2048)).toBe('2.0 KB')
    expect(formatBytes(5 * 1024 * 1024)).toBe('5.0 MB')
  })

  it('formats counts and durations', () => {
    expect(formatNumber(1234)).toBe('1,234')
    expect(formatDuration(45)).toBe('45.0s')
    expect(formatDuration(3725)).toBe('1h 2m')
    expect(percent(0.255, 1)).toBe('25.5%')
  })

  it('truncates long values for dense tables', () => {
    expect(truncate('abcdefghij', 5)).toBe('abcde…')
    expect(truncate(null)).toBe('—')
  })
})

describe('chart series conversion', () => {
  it('converts repository time buckets into chart points', () => {
    const series = toChartSeries([
      { bucket_start: '2026-08-18T22:00:00', count: 4 },
      { bucket_start: '2026-08-18T23:00:00', count: 7 },
    ])
    expect(series).toHaveLength(2)
    expect(series[1].value).toBe(7)
    expect(typeof series[0].label).toBe('string')
  })

  it('handles empty and null values without throwing', () => {
    expect(toChartSeries(undefined)).toEqual([])
    expect(distributionSeries([{ value: null, count: 3 }])).toEqual([{ label: 'unknown', value: 3 }])
  })
})
