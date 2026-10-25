import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../services/api.js'
import { useAuth } from '../hooks/useAuth.jsx'

export default function Login() {
  const { login, bootstrap } = useAuth()
  const navigate = useNavigate()
  const [mode, setMode] = useState('login')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState(null)
  const [pending, setPending] = useState(false)
  const [checking, setChecking] = useState(true)

  useEffect(() => {
    let cancelled = false
    api
      .needsBootstrap()
      .then((required) => {
        if (!cancelled && required) setMode('bootstrap')
      })
      .catch(() => {})
      .finally(() => {
        if (!cancelled) setChecking(false)
      })
    return () => {
      cancelled = true
    }
  }, [])

  const submit = async (event) => {
    event.preventDefault()
    setError(null)
    if (mode === 'bootstrap' && password !== confirm) {
      setError(new Error('passwords do not match'))
      return
    }
    setPending(true)
    try {
      if (mode === 'bootstrap') await bootstrap(username, password)
      else await login(username, password)
      navigate('/', { replace: true })
    } catch (err) {
      setError(err)
    } finally {
      setPending(false)
    }
  }

  return (
    <div className="login-shell">
      <div className="login-card">
        <h1>Mini SOC</h1>
        <p>
          {mode === 'bootstrap'
            ? 'First run: create the administrator account for this installation.'
            : 'Authenticate to access the security operations console.'}
        </p>
        <form onSubmit={submit}>
          <div className="field">
            <label htmlFor="username">Username</label>
            <input
              id="username"
              autoComplete="username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              required
              minLength={3}
            />
          </div>
          <div className="field">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              autoComplete={mode === 'bootstrap' ? 'new-password' : 'current-password'}
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
            />
          </div>
          {mode === 'bootstrap' ? (
            <div className="field">
              <label htmlFor="confirm">Confirm password</label>
              <input
                id="confirm"
                type="password"
                autoComplete="new-password"
                value={confirm}
                onChange={(event) => setConfirm(event.target.value)}
                required
              />
            </div>
          ) : null}
          {error ? <div className="form-error">{error.message}</div> : null}
          <button className="primary" type="submit" disabled={pending || checking}>
            {pending ? 'Working…' : mode === 'bootstrap' ? 'Create administrator' : 'Sign in'}
          </button>
          {mode === 'bootstrap' ? (
            <div className="form-note">
              Password policy: at least 12 characters with upper case, lower case, a digit and a symbol,
              and it must not contain the username.
            </div>
          ) : (
            <div className="form-note">
              Sessions use short-lived access tokens with refresh rotation. Five failed attempts lock the
              account for 15 minutes.
            </div>
          )}
        </form>
      </div>
    </div>
  )
}
