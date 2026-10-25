import { useCallback, useEffect, useRef, useState } from 'react'
import api, { buildQuery } from '../services/api.js'

/**
 * Fetch a REST path, with optional polling and manual reload.
 * Cancels in-flight requests on unmount so a fast navigation cannot set state
 * on an unmounted component.
 */
export function useApi(path, { params, pollMs = 0, enabled = true } = {}) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(Boolean(enabled))
  const [updatedAt, setUpdatedAt] = useState(null)
  const controller = useRef(null)
  const query = buildQuery(params)

  const load = useCallback(
    async ({ quiet = false } = {}) => {
      if (!enabled || !path) return
      controller.current?.abort()
      const next = new AbortController()
      controller.current = next
      if (!quiet) setLoading(true)
      try {
        const payload = await api.get(`${path}${query}`, { signal: next.signal })
        setData(payload)
        setError(null)
        setUpdatedAt(new Date().toISOString())
      } catch (err) {
        if (err.name !== 'AbortError') setError(err)
      } finally {
        if (!quiet) setLoading(false)
      }
    },
    [path, query, enabled],
  )

  useEffect(() => {
    load()
    return () => controller.current?.abort()
  }, [load])

  useEffect(() => {
    if (!pollMs || !enabled) return undefined
    const timer = window.setInterval(() => load({ quiet: true }), pollMs)
    return () => window.clearInterval(timer)
  }, [pollMs, enabled, load])

  return { data, error, loading, updatedAt, reload: load }
}

/** Like useApi but re-fetches whenever a dependency key changes. */
export function useApiKeyed(path, key, options = {}) {
  const [tick, setTick] = useState(0)
  useEffect(() => {
    setTick((value) => value + 1)
  }, [key])
  const result = useApi(path, options)
  return { ...result, refreshKey: tick }
}

/** Small helper for actions (PATCH/POST) with pending + error state. */
export function useAction() {
  const [pending, setPending] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)

  const run = useCallback(async (fn) => {
    setPending(true)
    setError(null)
    try {
      const value = await fn()
      setResult(value)
      return value
    } catch (err) {
      setError(err)
      throw err
    } finally {
      setPending(false)
    }
  }, [])

  return { run, pending, error, result, reset: () => { setError(null); setResult(null) } }
}

export default useApi
