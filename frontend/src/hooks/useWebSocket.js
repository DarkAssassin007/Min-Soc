import { useEffect, useRef, useState } from 'react'
import { createSocket } from '../services/websocket.js'

/**
 * Subscribe to one live channel.
 *
 * Mirrors the specification's real-time requirements: the dashboard never needs
 * to poll for new events or alerts, but it *does* show the connection state so
 * an analyst can tell the difference between "quiet network" and "lost feed".
 */
export function useChannel(channel, { onMessage, enabled = true, bufferSize = 200 } = {}) {
  const [status, setStatus] = useState('idle')
  const [detail, setDetail] = useState(null)
  const [buffer, setBuffer] = useState([])
  const [lastMessageAt, setLastMessageAt] = useState(null)
  const handler = useRef(onMessage)

  useEffect(() => {
    handler.current = onMessage
  }, [onMessage])

  useEffect(() => {
    if (!enabled) return undefined
    const socket = createSocket(channel, {
      onStatus: (nextStatus, nextDetail) => {
        setStatus(nextStatus)
        setDetail(nextDetail || null)
      },
      onMessage: (payload) => {
        setLastMessageAt(new Date().toISOString())
        if (payload?.type === 'events' && Array.isArray(payload.data)) {
          setBuffer((current) => [...payload.data, ...current].slice(0, bufferSize))
        }
        if (handler.current) handler.current(payload)
      },
    })
    return () => socket.close()
  }, [channel, enabled, bufferSize])

  return { status, detail, buffer, lastMessageAt, clear: () => setBuffer([]) }
}

export default useChannel
