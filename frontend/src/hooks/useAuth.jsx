import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import api, { clearTokens, getStoredUser, getTokens } from '../services/api.js'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(getStoredUser())
  const [status, setStatus] = useState('idle') // idle | checking | ready | error
  const [error, setError] = useState(null)
  const [bootstrapRequired, setBootstrapRequired] = useState(false)

  const refresh = useCallback(async () => {
    const { access } = getTokens()
    if (!access) {
      setUser(null)
      setStatus('ready')
      return null
    }
    setStatus('checking')
    try {
      const me = await api.me()
      setUser(me)
      setStatus('ready')
      return me
    } catch (err) {
      if (err.status === 401) {
        clearTokens()
        setUser(null)
      } else {
        setError(err)
      }
      setStatus('ready')
      return null
    }
  }, [])

  useEffect(() => {
    refresh()
  }, [refresh])

  const login = useCallback(async (username, password) => {
    setError(null)
    const me = await api.login(username, password)
    setUser(me)
    return me
  }, [])

  const bootstrap = useCallback(async (username, password) => {
    setError(null)
    const me = await api.bootstrap(username, password)
    setUser(me)
    setBootstrapRequired(false)
    return me
  }, [])

  const logout = useCallback(async () => {
    await api.logout()
    setUser(null)
  }, [])

  const value = useMemo(
    () => ({
      user,
      status,
      error,
      bootstrapRequired,
      setBootstrapRequired,
      permissions: {
        read: Boolean(user),
        investigate: ['ANALYST', 'ADMIN'].includes(user?.role),
        manageRules: user?.role === 'ADMIN',
        manageUsers: user?.role === 'ADMIN',
        manageModels: user?.role === 'ADMIN',
      },
      login,
      bootstrap,
      logout,
      refresh,
    }),
    [user, status, error, bootstrapRequired, login, bootstrap, logout, refresh],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) throw new Error('useAuth must be used inside <AuthProvider>')
  return context
}

export default useAuth
