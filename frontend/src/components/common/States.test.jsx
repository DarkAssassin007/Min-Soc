import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Empty, ErrorBox, RiskScore, Severity, StatusBadge } from './States.jsx'
import StatCard from '../cards/StatCard.jsx'

describe('Severity', () => {
  it('renders the severity label and score', () => {
    render(<Severity value={{ severity: 'HIGH', risk_score: 72.4 }} showScore />)
    expect(screen.getByText('HIGH')).toBeInTheDocument()
    expect(screen.getByText('72')).toBeInTheDocument()
  })

  it('falls back to LOW when severity is missing', () => {
    const { container } = render(<Severity value={{}} />)
    expect(container.querySelector('.sev-LOW')).not.toBeNull()
  })
})

describe('RiskScore and StatusBadge', () => {
  it('formats the risk score', () => {
    render(<RiskScore score={81.235} />)
    expect(screen.getByText('81.2')).toBeInTheDocument()
  })

  it('shows the lifecycle status', () => {
    render(<StatusBadge status="investigating" />)
    expect(screen.getByText('INVESTIGATING')).toBeInTheDocument()
  })
})

describe('Empty and ErrorBox', () => {
  it('renders an empty state with a hint', () => {
    render(<Empty label="No alerts" hint="nothing suspicious" />)
    expect(screen.getByText('No alerts')).toBeInTheDocument()
    expect(screen.getByText('nothing suspicious')).toBeInTheDocument()
  })

  it('offers a retry that calls back', async () => {
    const onRetry = vi.fn()
    render(<ErrorBox error={{ message: 'boom' }} onRetry={onRetry} />)
    await userEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(onRetry).toHaveBeenCalledTimes(1)
  })
})

describe('StatCard', () => {
  it('renders the label, value and footnote', () => {
    render(<StatCard label="Active alerts" value="12" foot="3 critical" />)
    expect(screen.getByText('Active alerts')).toBeInTheDocument()
    expect(screen.getByText('12')).toBeInTheDocument()
    expect(screen.getByText('3 critical')).toBeInTheDocument()
  })
})
