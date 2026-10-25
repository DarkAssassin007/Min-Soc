/**
 * WebSocket client for the three live channels (/ws/live, /ws/alerts, /ws/network).
 *
 * Browsers cannot set headers on a WebSocket handshake, so the access token is
 * passed as a query parameter; the backend validates it before accepting the
 * socket. Reconnection uses capped exponential backoff and stops permanently
 * when the server rejects the handshake as unauthorised (4401) — retrying a
 * bad token forever would just hammer the API.
 */

import { getTokens } from './api.js'

const RECONNECT_BASE_MS = 1000
const RECONNECT_MAX_MS = 20000
export const HANDSHAKE_UNAUTHORIZED = 4401
export const HANDSHAKE_UNAVAILABLE = 4503

function socketUrl(channel) {
  const configured = import.meta.env.VITE_WS_BASE
  const base = configured
    ? configured.replace(/\/$/, '')
    : `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}`
  const { access } = getTokens()
  const token = access ? `?token=${encodeURIComponent(access)}` : ''
  return `${base}/ws/${channel}${token}`
}

export function createSocket(channel, { onMessage, onStatus } = {}) {
  let socket = null
  let attempt = 0
  let timer = null
  let closed = false

  const notify = (status, detail) => {
    if (onStatus) onStatus(status, detail)
  }

  const connect = () => {
    if (closed) return
    notify(attempt === 0 ? 'connecting' : 'reconnecting')
    try {
      socket = new WebSocket(socketUrl(channel))
    } catch (error) {
      notify('error', String(error))
      schedule()
      return
    }

    socket.onopen = () => {
      attempt = 0
      notify('open')
    }

    socket.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data)
        if (onMessage) onMessage(payload)
      } catch {
        /* ignore malformed frames rather than breaking the feed */
      }
    }

    socket.onclose = (event) => {
      socket = null
      if (event.code === HANDSHAKE_UNAUTHORIZED || event.code === HANDSHAKE_UNAVAILABLE) {
        closed = true
        notify('rejected', event.reason || `closed (${event.code})`)
        return
      }
      notify('closed')
      schedule()
    }

    socket.onerror = () => {
      notify('error')
    }
  }

  const schedule = () => {
    if (closed) return
    attempt += 1
    const delay = Math.min(RECONNECT_BASE_MS * 2 ** (attempt - 1), RECONNECT_MAX_MS)
    timer = window.setTimeout(connect, delay)
  }

  connect()

  return {
    close() {
      closed = true
      if (timer) window.clearTimeout(timer)
      if (socket) socket.close(1000, 'client closing')
    },
    get connected() {
      return Boolean(socket) && socket.readyState === WebSocket.OPEN
    },
    get attempts() {
      return attempt
    },
  }
}

export default createSocket
