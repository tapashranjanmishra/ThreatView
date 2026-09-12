import { useEffect, useState } from 'react'
import './App.css'

const API_URL = 'http://127.0.0.1:8000'

function App() {
  const [token, setToken] = useState(
    localStorage.getItem('threatview_token')
  )

  const [email, setEmail] = useState('test@threatview.com')
  const [password, setPassword] = useState('')
  const [loginError, setLoginError] = useState('')
  const [loading, setLoading] = useState(false)

  const [threats, setThreats] = useState([])
  const [threatTotal, setThreatTotal] = useState(0)
  const [threatPage, setThreatPage] = useState(0)

  const [ingestionStatus, setIngestionStatus] = useState({
    status: 'starting',
    last_run: null,
    last_result: {
      otx: 0,
      openphish: 0,
    },
    last_error: null,
    interval_minutes: 60,
  })

  const [threatSearch, setThreatSearch] = useState('')
  const [threatSource, setThreatSource] = useState('')
  const [threatType, setThreatType] = useState('')
  const [iocType, setIocType] = useState('')

  const [alerts, setAlerts] = useState([])
  const [notifications, setNotifications] = useState([])

  const [alertEditorOpen, setAlertEditorOpen] = useState(false)
  const [editingAlert, setEditingAlert] = useState(null)
  const [alertForm, setAlertForm] = useState({
    name: '',
    source: '',
    threat_type: '',
    ioc_type: '',
    country: '',
    industry: '',
    min_confidence_score: '',
    is_active: true,
  })
  const [alertSaving, setAlertSaving] = useState(false)
  const [alertError, setAlertError] = useState('')
  const [deleteAlert, setDeleteAlert] = useState(null)
  const [alertDeleting, setAlertDeleting] = useState(false)

  const [stats, setStats] = useState({
    total: 0,
    otx: 0,
    alerts: 0,
    notifications: 0,
  })

  const [activePage, setActivePage] = useState('dashboard')

  async function login(e) {
    e.preventDefault()

    setLoading(true)
    setLoginError('')

    try {
      const response = await fetch(`${API_URL}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email,
          password,
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.detail || 'Login failed')
      }

      localStorage.setItem('threatview_token', data.access_token)
      setToken(data.access_token)
      setPassword('')
    } catch (error) {
      setLoginError(error.message)
    } finally {
      setLoading(false)
    }
  }

  function logout() {
    localStorage.removeItem('threatview_token')
    setToken(null)
    setThreats([])
    setAlerts([])
    setNotifications([])
  }

  async function fetchThreats(page = 0) {
    const limit = 100
    const skip = page * limit

    const params = new URLSearchParams({
      skip: String(skip),
      limit: String(limit),
    })

    if (threatSearch.trim()) {
      params.set('ioc', threatSearch.trim())
    }

    if (threatSource) {
      params.set('source', threatSource)
    }

    if (threatType) {
      params.set('threat_type', threatType)
    }

    if (iocType) {
      params.set('ioc_type', iocType)
    }

    const response = await fetch(
      `${API_URL}/api/threats/filter?${params.toString()}`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    )

    if (response.status === 401) {
      logout()
      return
    }

    if (!response.ok) {
      throw new Error('Failed to load threats')
    }

    const data = await response.json()

    const threatList = Array.isArray(data)
      ? data
      : data.items || []

    setThreats(threatList)
    setThreatTotal(data.total ?? threatList.length)
    setThreatPage(page)
  }

  async function fetchThreatStats() {
    const response = await fetch(
      `${API_URL}/api/threats/stats`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    )

    if (response.status === 401) {
      logout()
      return
    }

    if (!response.ok) {
      throw new Error('Failed to load threat statistics')
    }

    const data = await response.json()

    setStats((previous) => ({
      ...previous,
      total: data.total ?? 0,
      otx: data.otx ?? 0,
    }))
  }

  function applyThreatFilters() {
    fetchThreats(0)
  }

  function clearThreatFilters() {
    setThreatSearch('')
    setThreatSource('')
    setThreatType('')
    setIocType('')

    setTimeout(() => {
      fetchThreats(0)
    }, 0)
  }

  async function fetchIngestionStatus() {
    const response = await fetch(
      `${API_URL}/api/ingestion/status`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    )

    if (response.status === 401) {
      logout()
      return
    }

    if (!response.ok) {
      throw new Error('Failed to load ingestion status')
    }

    const data = await response.json()

    setIngestionStatus(data)
  }

  async function fetchNotifications() {
    const response = await fetch(
      `${API_URL}/api/alerts/notifications`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    )

    if (response.status === 401) {
      logout()
      return
    }

    if (!response.ok) {
      throw new Error('Failed to load notifications')
    }

    const data = await response.json()

    const notificationList = Array.isArray(data)
      ? data
      : data.items || []

    setNotifications(notificationList)

    setStats((previous) => ({
      ...previous,
      notifications: notificationList.length,
    }))
  }

  async function fetchAlerts() {
    const response = await fetch(`${API_URL}/api/alerts`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    })

    if (response.status === 401) {
      logout()
      return
    }

    if (!response.ok) {
      throw new Error('Failed to load alerts')
    }

    const data = await response.json()

    const alertList = Array.isArray(data)
      ? data
      : data.items || []

    setAlerts(alertList)

    setStats((previous) => ({
      ...previous,
      alerts: alertList.length,
    }))
  }

  function openCreateAlert() {
    setEditingAlert(null)
    setAlertForm({
      name: '',
      source: '',
      threat_type: '',
      ioc_type: '',
      country: '',
      industry: '',
      min_confidence_score: '',
      is_active: true,
    })
    setAlertError('')
    setAlertEditorOpen(true)
  }

  function openEditAlert(alert) {
    const conditions = alert.conditions || {}

    setEditingAlert(alert)
    setAlertForm({
      name: alert.name || '',
      source: conditions.source || '',
      threat_type: conditions.threat_type || '',
      ioc_type: conditions.ioc_type || '',
      country: conditions.country || '',
      industry: conditions.industry || '',
      min_confidence_score: conditions.min_confidence_score ?? '',
      is_active: Boolean(alert.is_active),
    })
    setAlertError('')
    setAlertEditorOpen(true)
  }

  function closeAlertEditor() {
    if (alertSaving) return
    setAlertEditorOpen(false)
    setEditingAlert(null)
    setAlertError('')
  }

  function updateAlertForm(field, value) {
    setAlertForm((previous) => ({
      ...previous,
      [field]: value,
    }))
  }

  function buildAlertConditions() {
    const conditions = {}

    if (alertForm.source) conditions.source = alertForm.source
    if (alertForm.threat_type) conditions.threat_type = alertForm.threat_type
    if (alertForm.ioc_type) conditions.ioc_type = alertForm.ioc_type
    if (alertForm.country.trim()) conditions.country = alertForm.country.trim().toUpperCase()
    if (alertForm.industry.trim()) conditions.industry = alertForm.industry.trim()

    if (alertForm.min_confidence_score !== '') {
      conditions.min_confidence_score = Number(alertForm.min_confidence_score)
    }

    return conditions
  }

  async function saveAlertRule(e) {
    e.preventDefault()
    setAlertSaving(true)
    setAlertError('')

    const confidence =
      alertForm.min_confidence_score === ''
        ? null
        : Number(alertForm.min_confidence_score)

    if (
      confidence !== null &&
      (!Number.isFinite(confidence) || confidence < 0 || confidence > 100)
    ) {
      setAlertError('Minimum confidence must be between 0 and 100.')
      setAlertSaving(false)
      return
    }

    const payload = {
      name: alertForm.name.trim(),
      conditions: buildAlertConditions(),
      is_active: alertForm.is_active,
    }

    if (!payload.name) {
      setAlertError('Rule name is required.')
      setAlertSaving(false)
      return
    }

    try {
      const url = editingAlert
        ? `${API_URL}/api/alerts/${editingAlert.id}`
        : `${API_URL}/api/alerts`

      const response = await fetch(url, {
        method: editingAlert ? 'PUT' : 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(payload),
      })

      if (response.status === 401) {
        logout()
        return
      }

      const data = await response.json().catch(() => ({}))

      if (!response.ok) {
        throw new Error(data.detail || 'Failed to save alert rule')
      }

      setAlertEditorOpen(false)
      setEditingAlert(null)
      await fetchAlerts()
    } catch (error) {
      setAlertError(error.message)
    } finally {
      setAlertSaving(false)
    }
  }

  async function toggleAlertRule(alert) {
    setAlertError('')

    try {
      const response = await fetch(`${API_URL}/api/alerts/${alert.id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          is_active: !alert.is_active,
        }),
      })

      if (response.status === 401) {
        logout()
        return
      }

      const data = await response.json().catch(() => ({}))

      if (!response.ok) {
        throw new Error(data.detail || 'Failed to update alert rule')
      }

      await fetchAlerts()
    } catch (error) {
      setAlertError(error.message)
    }
  }

  function requestDeleteAlert(alert) {
    setAlertError('')
    setDeleteAlert(alert)
  }

  function cancelDeleteAlert() {
    if (alertDeleting) return
    setDeleteAlert(null)
  }

  async function confirmDeleteAlert() {
    if (!deleteAlert) return

    setAlertDeleting(true)
    setAlertError('')

    try {
      const response = await fetch(
        `${API_URL}/api/alerts/${deleteAlert.id}`,
        {
          method: 'DELETE',
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      )

      if (response.status === 401) {
        logout()
        return
      }

      if (!response.ok && response.status !== 204) {
        const data = await response.json().catch(() => ({}))
        throw new Error(data.detail || 'Failed to delete alert rule')
      }

      setDeleteAlert(null)

      await Promise.all([
        fetchAlerts(),
        fetchNotifications(),
      ])
    } catch (error) {
      setAlertError(error.message)
    } finally {
      setAlertDeleting(false)
    }
  }

  async function loadDashboard() {
    try {
      await Promise.all([
        fetchThreats(),
        fetchThreatStats(),
        fetchIngestionStatus(),
        fetchAlerts(),
        fetchNotifications(),
      ])
    } catch (error) {
      console.error(error)
    }
  }

  useEffect(() => {
    if (token) {
      loadDashboard()
    }
  }, [token])

  if (!token) {
    return (
      <div className="login-page">
        <div className="login-card">

          <div className="brand">
            <div className="brand-icon">TV</div>

            <div>
              <h1>ThreatView</h1>
              <p>Threat Intelligence Platform</p>
            </div>
          </div>

          <div className="login-header">
            <h2>Welcome back</h2>
            <p>
              Sign in to access your threat intelligence dashboard.
            </p>
          </div>

          <form onSubmit={login}>

            <label>Email</label>

            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="Enter your email"
              required
            />

            <label>Password</label>

            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter your password"
              required
            />

            {loginError && (
              <div className="error-message">
                {loginError}
              </div>
            )}

            <button
              className="login-button"
              type="submit"
              disabled={loading}
            >
              {loading ? 'Signing in...' : 'Sign in'}
            </button>

          </form>

          <div className="login-footer">
            ThreatView Security Operations
          </div>

        </div>
      </div>
    )
  }

  return (
    <div className="app">

      <aside className="sidebar">

        <div className="sidebar-brand">

          <div className="brand-icon">TV</div>

          <div>
            <strong>ThreatView</strong>
            <span>Threat Intelligence</span>
          </div>

        </div>

        <nav>

          <button
            className={
              activePage === 'dashboard'
                ? 'nav-item active'
                : 'nav-item'
            }
            onClick={() => setActivePage('dashboard')}
          >
            <span>◆</span>
            Dashboard
          </button>

          <button
            className={
              activePage === 'threats'
                ? 'nav-item active'
                : 'nav-item'
            }
            onClick={() => setActivePage('threats')}
          >
            <span>◈</span>
            Threats
          </button>

          <button
            className={
              activePage === 'alerts'
                ? 'nav-item active'
                : 'nav-item'
            }
            onClick={() => setActivePage('alerts')}
          >
            <span>⚠</span>
            Alerts

            {stats.notifications > 0 && (
              <small>
                {stats.notifications > 999
                  ? '999+'
                  : stats.notifications}
              </small>
            )}

          </button>

        </nav>

        <div className="sidebar-bottom">

          <button
            className="nav-item"
            onClick={loadDashboard}
          >
            <span>↻</span>
            Refresh
          </button>

          <button
            className="nav-item logout"
            onClick={logout}
          >
            <span>⇥</span>
            Logout
          </button>

        </div>

      </aside>

      <main className="main">

        <header className="topbar">

          <div>

            <h1>
              {activePage === 'dashboard' &&
                'Security Dashboard'}

              {activePage === 'threats' &&
                'Threat Intelligence'}

              {activePage === 'alerts' &&
                'Alert Center'}
            </h1>

            <p>
              {activePage === 'dashboard'
                ? 'Monitor threats and security activity'
                : activePage === 'threats'
                  ? 'Indicators collected from threat intelligence sources'
                  : 'Manage alert rules and triggered notifications'}
            </p>

          </div>

          <div className="user-area">
            <div className="status-dot"></div>
            <span>API Connected</span>
          </div>

        </header>

        {/* ================= DASHBOARD ================= */}

        {activePage === 'dashboard' && (
          <>

            <section className="stats-grid">

              <div className="stat-card">

                <div className="stat-icon">◈</div>

                <div>
                  <p>Total Threats</p>
                  <h2>{stats.total}</h2>
                </div>

              </div>

              <div className="stat-card">

                <div className="stat-icon">◎</div>

                <div>
                  <p>OTX Threats</p>
                  <h2>{stats.otx}</h2>
                </div>

              </div>

              <div className="stat-card">

                <div className="stat-icon">⚠</div>

                <div>
                  <p>Alert Rules</p>
                  <h2>{stats.alerts}</h2>
                </div>

              </div>

            </section>

            {/* INGESTION STATUS */}

            <section className="panel ingestion-panel">

              <div className="panel-header">

                <div>
                  <h2>Ingestion Status</h2>

                  <p>
                    Automatic threat intelligence feed monitoring
                  </p>
                </div>

                <div
                  className={`ingestion-status-badge ${ingestionStatus.status}`}
                >
                  <span className="status-dot"></span>
                  {ingestionStatus.status}
                </div>

              </div>

              <div className="ingestion-grid">

                <div className="ingestion-card">
                  <span className="ingestion-label">
                    OTX
                  </span>

                  <strong>
                    {ingestionStatus.last_result?.otx ?? 0}
                  </strong>

                  <small>
                    New indicators
                  </small>
                </div>

                <div className="ingestion-card">
                  <span className="ingestion-label">
                    OpenPhish
                  </span>

                  <strong>
                    {ingestionStatus.last_result?.openphish ?? 0}
                  </strong>

                  <small>
                    New indicators
                  </small>
                </div>

                <div className="ingestion-card">
                  <span className="ingestion-label">
                    Last Run
                  </span>

                  <strong>
                    {ingestionStatus.last_run
                      ? new Date(
                          ingestionStatus.last_run
                        ).toLocaleTimeString()
                      : 'Not completed'}
                  </strong>

                  <small>
                    {ingestionStatus.last_run
                      ? new Date(
                          ingestionStatus.last_run
                        ).toLocaleDateString()
                      : 'Waiting for first run'}
                  </small>
                </div>

                <div className="ingestion-card">
                  <span className="ingestion-label">
                    Interval
                  </span>

                  <strong>
                    {ingestionStatus.interval_minutes} min
                  </strong>

                  <small>
                    Automatic schedule
                  </small>
                </div>

              </div>

              {ingestionStatus.last_error && (
                <div className="ingestion-error">
                  Last ingestion error:{' '}
                  {ingestionStatus.last_error}
                </div>
              )}

            </section>

            {/* NOTIFICATION SUMMARY */}

            <section className="panel">

              <div className="panel-header">

                <div>
                  <h2>Triggered Alerts</h2>

                  <p>
                    {notifications.length} notification
                    {notifications.length !== 1 ? 's' : ''} generated
                  </p>
                </div>

                <button
                  className="secondary-button"
                  onClick={() => setActivePage('alerts')}
                >
                  View alerts
                </button>

              </div>

              {notifications.length === 0 ? (
                <div className="empty-state">
                  No triggered alerts.
                </div>
              ) : (
                <NotificationList
                  notifications={notifications.slice(0, 5)}
                />
              )}

            </section>

            {/* RECENT THREATS */}

            <section className="panel">

              <div className="panel-header">

                <div>
                  <h2>Recent Threats</h2>

                  <p>
                    Latest indicators from your intelligence feeds
                  </p>
                </div>

                <button
                  className="secondary-button"
                  onClick={() => setActivePage('threats')}
                >
                  View all
                </button>

              </div>

              <ThreatTable
                threats={threats.slice(0, 10)}
                token={token}
              />

            </section>

          </>
        )}

        {/* ================= THREATS ================= */}

        {activePage === 'threats' && (
          <section className="panel">

            <div className="panel-header">

              <div className="threat-filters">

                <div className="filter-group search-filter">

                  <label>Search IOC</label>

                  <input
                    type="text"
                    value={threatSearch}
                    onChange={(e) => setThreatSearch(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        applyThreatFilters()
                      }
                    }}
                    placeholder="Search IP, domain, URL, hash..."
                  />

                </div>

                <div className="filter-group">

                  <label>Source</label>

                  <select
                    value={threatSource}
                    onChange={(e) => {
                      setThreatSource(e.target.value)
                      setThreatPage(0)

                      setTimeout(() => {
                        fetchThreats(0)
                      }, 0)
                    }}
                  >
                    <option value="">
                      All Sources
                    </option>

                    <option value="otx">
                      OTX
                    </option>

                    <option value="openphish">
                      OpenPhish
                    </option>

                  </select>

                </div>

                <div className="filter-group">

                  <label>Threat Type</label>

                  <select
                    value={threatType}
                    onChange={(e) => {
                      setThreatType(e.target.value)
                      setThreatPage(0)

                      setTimeout(() => {
                        fetchThreats(0)
                      }, 0)
                    }}
                  >

                    <option value="">
                      All Threats
                    </option>

                    <option value="malware">
                      Malware
                    </option>

                    <option value="phishing">
                      Phishing
                    </option>

                    <option value="ransomware">
                      Ransomware
                    </option>

                    <option value="botnet">
                      Botnet
                    </option>

                    <option value="scanning">
                      Scanning
                    </option>

                    <option value="other">
                      Other
                    </option>

                  </select>

                </div>

                <div className="filter-group">

                  <label>IOC Type</label>

                  <select
                    value={iocType}
                    onChange={(e) => {
                      setIocType(e.target.value)
                      setThreatPage(0)

                      setTimeout(() => {
                        fetchThreats(0)
                      }, 0)
                    }}
                  >

                    <option value="">
                      All Types
                    </option>

                    <option value="ip">
                      IP
                    </option>

                    <option value="domain">
                      Domain
                    </option>

                    <option value="url">
                      URL
                    </option>

                    <option value="file_hash">
                      File Hash
                    </option>

                    <option value="email">
                      Email
                    </option>

                  </select>

                </div>

                <button
                  className="secondary-button"
                  onClick={applyThreatFilters}
                >
                  Search
                </button>

                <button
                  className="secondary-button"
                  onClick={clearThreatFilters}
                >
                  Clear
                </button>

              </div>

              <div>

                <h2>All Threats</h2>

                <p>
                  Showing {threats.length} of {threatTotal} indicators
                </p>

              </div>

              <button
                className="secondary-button"
                onClick={() => fetchThreats(threatPage)}
              >
                Refresh
              </button>

            </div>

            <ThreatTable
              threats={threats}
              token={token}
            />

            {threatTotal > 100 && (
              <div className="pagination">

                <button
                  className="secondary-button"
                  disabled={threatPage === 0}
                  onClick={() => fetchThreats(threatPage - 1)}
                >
                  ← Previous
                </button>

                <span className="pagination-info">
                  Page {threatPage + 1} of{' '}
                  {Math.ceil(threatTotal / 100)}
                </span>

                <button
                  className="secondary-button"
                  disabled={
                    threatPage >=
                    Math.ceil(threatTotal / 100) - 1
                  }
                  onClick={() => fetchThreats(threatPage + 1)}
                >
                  Next →
                </button>

              </div>
            )}

          </section>
        )}

        {/* ================= ALERTS ================= */}

        {activePage === 'alerts' && (
          <>
            <section className="panel">
              <div className="panel-header">
                <div>
                  <h2>Triggered Notifications</h2>
                  <p>Threats that matched your alert rules</p>
                </div>

                <button
                  className="secondary-button"
                  onClick={fetchNotifications}
                >
                  Refresh
                </button>
              </div>

              {notifications.length === 0 ? (
                <div className="empty-state">
                  No alert notifications found.
                </div>
              ) : (
                <NotificationList notifications={notifications} />
              )}
            </section>

            <section className="panel">
              <div className="panel-header">
                <div>
                  <h2>Alert Rules</h2>
                  <p>Create, edit and control threat detection rules</p>
                </div>

                <div className="alert-header-actions">
                  <button
                    className="secondary-button"
                    onClick={fetchAlerts}
                  >
                    Refresh
                  </button>

                  <button
                    className="primary-button"
                    onClick={openCreateAlert}
                  >
                    + New Rule
                  </button>
                </div>
              </div>

              {alertError && !alertEditorOpen && !deleteAlert && (
                <div className="alert-management-error">
                  {alertError}
                </div>
              )}

              {alerts.length === 0 ? (
                <div className="empty-state">
                  No alert rules found. Create your first rule above.
                </div>
              ) : (
                <div className="alerts-list">
                  {alerts.map((alert) => {
                    const notificationCount = notifications.filter(
                      (notification) => notification.rule_id === alert.id
                    ).length

                    const conditionEntries = Object.entries(
                      alert.conditions || {}
                    )

                    return (
                      <div className="alert-card" key={alert.id}>
                        <div className="alert-card-main">
                          <div className="alert-title-row">
                            <h3>{alert.name || 'Unnamed Rule'}</h3>

                            <span
                              className={
                                alert.is_active
                                  ? 'badge active'
                                  : 'badge inactive'
                              }
                            >
                              {alert.is_active ? 'Active' : 'Inactive'}
                            </span>
                          </div>

                          <div className="rule-condition-list">
                            {conditionEntries.length === 0 ? (
                              <span className="rule-condition-empty">
                                Matches all threats
                              </span>
                            ) : (
                              conditionEntries.map(([key, value]) => (
                                <span className="rule-condition" key={key}>
                                  <strong>
                                    {formatConditionLabel(key)}
                                  </strong>
                                  {String(value)}
                                </span>
                              ))
                            )}
                          </div>

                          <div className="alert-meta">
                            <span>
                              {notificationCount}{' '}
                              {notificationCount === 1
                                ? 'notification'
                                : 'notifications'}
                            </span>

                            <span>
                              Created{' '}
                              {alert.created_at
                                ? new Date(alert.created_at).toLocaleString()
                                : '—'}
                            </span>
                          </div>
                        </div>

                        <div className="alert-actions">
                          <button
                            className="rule-action-button"
                            onClick={() => openEditAlert(alert)}
                          >
                            Edit
                          </button>

                          <button
                            className="rule-action-button"
                            onClick={() => toggleAlertRule(alert)}
                          >
                            {alert.is_active ? 'Disable' : 'Enable'}
                          </button>

                          <button
                            className="rule-action-button danger"
                            onClick={() => requestDeleteAlert(alert)}
                          >
                            Delete
                          </button>
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}
            </section>

            {alertEditorOpen && (
              <AlertRuleModal
                editingAlert={editingAlert}
                form={alertForm}
                saving={alertSaving}
                error={alertError}
                onChange={updateAlertForm}
                onClose={closeAlertEditor}
                onSubmit={saveAlertRule}
              />
            )}

            {deleteAlert && (
              <DeleteAlertModal
                alert={deleteAlert}
                notificationCount={
                  notifications.filter(
                    (notification) =>
                      notification.rule_id === deleteAlert.id
                  ).length
                }
                deleting={alertDeleting}
                onCancel={cancelDeleteAlert}
                onConfirm={confirmDeleteAlert}
              />
            )}
          </>
        )}

      </main>

    </div>
  )
}

function formatConditionLabel(key) {
  const labels = {
    threat_type: 'Threat',
    ioc_type: 'IOC',
    source: 'Source',
    country: 'Country',
    industry: 'Industry',
    min_confidence_score: 'Min confidence',
  }

  return labels[key] || key
}

function AlertRuleModal({
  editingAlert,
  form,
  saving,
  error,
  onChange,
  onClose,
  onSubmit,
}) {
  return (
    <div className="modal-overlay">
      <div className="alert-rule-modal">
        <div className="modal-header">
          <div>
            <h2>
              {editingAlert ? 'Edit Alert Rule' : 'Create Alert Rule'}
            </h2>
            <p>
              Define the conditions that should trigger notifications.
            </p>
          </div>

          <button
            className="modal-close"
            onClick={onClose}
            disabled={saving}
            aria-label="Close"
          >
            ×
          </button>
        </div>

        <form onSubmit={onSubmit}>
          <div className="alert-form-grid">
            <div className="alert-form-field full">
              <label>Rule Name</label>
              <input
                type="text"
                value={form.name}
                onChange={(e) => onChange('name', e.target.value)}
                placeholder="e.g. High Confidence Phishing"
                maxLength={255}
                required
              />
            </div>

            <div className="alert-form-field">
              <label>Source</label>
              <select
                value={form.source}
                onChange={(e) => onChange('source', e.target.value)}
              >
                <option value="">Any Source</option>
                <option value="otx">OTX</option>
                <option value="openphish">OpenPhish</option>
              </select>
            </div>

            <div className="alert-form-field">
              <label>Threat Type</label>
              <select
                value={form.threat_type}
                onChange={(e) =>
                  onChange('threat_type', e.target.value)
                }
              >
                <option value="">Any Threat</option>
                <option value="malware">Malware</option>
                <option value="phishing">Phishing</option>
                <option value="ransomware">Ransomware</option>
                <option value="botnet">Botnet</option>
                <option value="scanning">Scanning</option>
                <option value="other">Other</option>
              </select>
            </div>

            <div className="alert-form-field">
              <label>IOC Type</label>
              <select
                value={form.ioc_type}
                onChange={(e) => onChange('ioc_type', e.target.value)}
              >
                <option value="">Any IOC Type</option>
                <option value="ip">IP</option>
                <option value="domain">Domain</option>
                <option value="url">URL</option>
                <option value="file_hash">File Hash</option>
                <option value="email">Email</option>
              </select>
            </div>

            <div className="alert-form-field">
              <label>Minimum Confidence</label>
              <input
                type="number"
                min="0"
                max="100"
                step="1"
                value={form.min_confidence_score}
                onChange={(e) =>
                  onChange('min_confidence_score', e.target.value)
                }
                placeholder="0–100"
              />
            </div>

            <div className="alert-form-field">
              <label>Country</label>
              <input
                type="text"
                value={form.country}
                onChange={(e) => onChange('country', e.target.value)}
                placeholder="e.g. IN"
                maxLength={2}
              />
            </div>

            <div className="alert-form-field">
              <label>Industry</label>
              <input
                type="text"
                value={form.industry}
                onChange={(e) => onChange('industry', e.target.value)}
                placeholder="e.g. finance"
                maxLength={100}
              />
            </div>
          </div>

          <label className="alert-active-toggle">
            <input
              type="checkbox"
              checked={form.is_active}
              onChange={(e) => onChange('is_active', e.target.checked)}
            />
            <span>
              <strong>Rule active</strong>
              <small>
                Active rules are evaluated against newly ingested threats.
              </small>
            </span>
          </label>

          {error && (
            <div className="alert-management-error">{error}</div>
          )}

          <div className="modal-actions">
            <button
              type="button"
              className="secondary-button"
              onClick={onClose}
              disabled={saving}
            >
              Cancel
            </button>

            <button
              type="submit"
              className="primary-button"
              disabled={saving}
            >
              {saving
                ? 'Saving...'
                : editingAlert
                  ? 'Save Changes'
                  : 'Create Rule'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function DeleteAlertModal({
  alert,
  notificationCount,
  deleting,
  onCancel,
  onConfirm,
}) {
  return (
    <div className="modal-overlay">
      <div className="delete-alert-modal">
        <div className="delete-alert-icon">!</div>

        <div>
          <h2>Delete Alert Rule?</h2>
          <p>
            You are about to permanently delete{' '}
            <strong>{alert.name}</strong>.
          </p>

          <div className="delete-warning">
            <strong>
              {notificationCount} existing notification
              {notificationCount === 1 ? '' : 's'} will also be deleted.
            </strong>
            <span>
              ThreatView deletes notifications associated with a rule when
              that rule is removed.
            </span>
          </div>
        </div>

        <div className="modal-actions">
          <button
            className="secondary-button"
            onClick={onCancel}
            disabled={deleting}
          >
            Cancel
          </button>

          <button
            className="danger-button"
            onClick={onConfirm}
            disabled={deleting}
          >
            {deleting ? 'Deleting...' : 'Delete Rule'}
          </button>
        </div>
      </div>
    </div>
  )
}

/* =========================================================
   NOTIFICATION LIST
========================================================= */

function NotificationList({ notifications }) {
  return (
    <div className="notifications-list">

      {notifications.map((notification) => (

        <div
          className="notification-card"
          key={notification.id}
        >

          <div className="notification-icon">
            ⚠
          </div>

          <div className="notification-content">

            <div className="notification-header">

              <h3>
                {notification.rule_name || 'Alert Triggered'}
              </h3>

              <span className="badge active">
                Triggered
              </span>

            </div>

            <div className="notification-details">

              <div className="notification-field">

                <span className="notification-label">
                  IOC
                </span>

                <strong className="ioc">
                  {notification.ioc_value || '—'}
                </strong>

              </div>

              <div className="notification-field">

                <span className="notification-label">
                  Type
                </span>

                <span className="type-badge">
                  {(notification.ioc_type || '—').toUpperCase()}
                </span>

              </div>

              <div className="notification-field">

                <span className="notification-label">
                  Threat
                </span>

                <span className="threat-value">
                  {(notification.threat_type || '—').toUpperCase()}
                </span>

              </div>

              <div className="notification-field">

                <span className="notification-label">
                  Source
                </span>

                <span className="source-badge">
                  {(notification.source || '—').toUpperCase()}
                </span>

              </div>

              <div className="notification-field">

                <span className="notification-label">
                  Confidence
                </span>

                <span>
                  {notification.confidence_score ?? 'N/A'}
                </span>

              </div>

            </div>

            <div className="notification-time">

              Triggered:{' '}

              {notification.sent_at
                ? new Date(
                    notification.sent_at
                  ).toLocaleString()
                : '—'}

            </div>

          </div>

        </div>

      ))}

    </div>
  )
}

/* =========================================================
   THREAT TABLE
========================================================= */

function ThreatTable({ threats, token }) {
  const [selectedThreat, setSelectedThreat] = useState(null)
  const [loadingThreat, setLoadingThreat] = useState(false)
  const [threatError, setThreatError] = useState('')

  async function openThreatDetails(threatId) {
    setLoadingThreat(true)
    setThreatError('')
    setSelectedThreat(null)

    try {
      const response = await fetch(
        `${API_URL}/api/threats/${threatId}`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      )

      if (!response.ok) {
        throw new Error('Failed to load threat details')
      }

      const data = await response.json()
      setSelectedThreat(data)

    } catch (error) {
      setThreatError(error.message)

    } finally {
      setLoadingThreat(false)
    }
  }

  function closeThreatDetails() {
    setSelectedThreat(null)
    setThreatError('')
  }

  if (!threats.length) {
    return (
      <div className="empty-state">
        No threats available.
      </div>
    )
  }

  return (
    <>

      <div className="table-wrapper">

        <table>

          <thead>

            <tr>
              <th>IOC</th>
              <th>Type</th>
              <th>Threat Type</th>
              <th>Source</th>
              <th>Confidence</th>
            </tr>

          </thead>

          <tbody>

            {threats.map((threat) => (

              <tr
                key={threat.id}
                className="threat-row"
                onClick={() => openThreatDetails(threat.id)}
              >

                <td className="ioc">

                  <span className="ioc-link">
                    {threat.ioc_value || '—'}
                  </span>

                </td>

                <td>

                  <span className="type-badge">
                    {threat.ioc_type || '—'}
                  </span>

                </td>

                <td>
                  {threat.threat_type || '—'}
                </td>

                <td>

                  <span className="source-badge">
                    {threat.source || '—'}
                  </span>

                </td>

                <td>

                  <div className="confidence">

                    <div className="confidence-bar">

                      <div
                        className="confidence-fill"
                        style={{
                          width: `${Math.min(
                            Number(
                              threat.confidence_score || 0
                            ),
                            100
                          )}%`,
                        }}
                      />

                    </div>

                    <span>
                      {threat.confidence_score ?? 0}
                    </span>

                  </div>

                </td>

              </tr>

            ))}

          </tbody>

        </table>

      </div>

      {loadingThreat && (

        <div className="threat-modal-overlay">

          <div className="threat-modal">

            <div className="threat-modal-loading">
              Loading threat intelligence...
            </div>

          </div>

        </div>

      )}

      {threatError && (

        <div className="threat-modal-overlay">

          <div className="threat-modal">

            <div className="threat-modal-header">

              <h2>Threat Details</h2>

              <button
                className="modal-close"
                onClick={closeThreatDetails}
              >
                ×
              </button>

            </div>

            <div className="threat-error">
              {threatError}
            </div>

          </div>

        </div>

      )}

      {selectedThreat && (

        <div
          className="threat-modal-overlay"
          onClick={closeThreatDetails}
        >

          <div
            className="threat-modal"
            onClick={(event) => event.stopPropagation()}
          >

            <div className="threat-modal-header">

              <div>

                <h2>Threat Investigation</h2>

                <p>
                  IOC intelligence record
                </p>

              </div>

              <button
                className="modal-close"
                onClick={closeThreatDetails}
              >
                ×
              </button>

            </div>

            <div className="threat-ioc-section">

              <span className="threat-modal-label">
                IOC
              </span>

              <div className="threat-modal-ioc">
                {selectedThreat.ioc_value || '—'}
              </div>

            </div>

            <div className="threat-detail-grid">

              <div className="threat-detail-card">

                <span>IOC Type</span>

                <strong>
                  {selectedThreat.ioc_type || '—'}
                </strong>

              </div>

              <div className="threat-detail-card">

                <span>Threat Type</span>

                <strong>
                  {selectedThreat.threat_type || '—'}
                </strong>

              </div>

              <div className="threat-detail-card">

                <span>Source</span>

                <strong>
                  {selectedThreat.source || '—'}
                </strong>

              </div>

              <div className="threat-detail-card">

                <span>Confidence</span>

                <strong>
                  {selectedThreat.confidence_score ?? 'N/A'}
                </strong>

              </div>

              <div className="threat-detail-card">

                <span>Country</span>

                <strong>
                  {selectedThreat.country || '—'}
                </strong>

              </div>

              <div className="threat-detail-card">

                <span>Industry</span>

                <strong>
                  {selectedThreat.industry || '—'}
                </strong>

              </div>

              <div className="threat-detail-card">

                <span>First Seen</span>

                <strong>
                  {selectedThreat.first_seen
                    ? new Date(
                        selectedThreat.first_seen
                      ).toLocaleString()
                    : '—'}
                </strong>

              </div>

              <div className="threat-detail-card">

                <span>Last Seen</span>

                <strong>
                  {selectedThreat.last_seen
                    ? new Date(
                        selectedThreat.last_seen
                      ).toLocaleString()
                    : '—'}
                </strong>

              </div>

            </div>

            <div className="raw-data-section">

              <div className="raw-data-header">
                <span>
                  Raw Intelligence Data
                </span>
              </div>

              <pre>
                {JSON.stringify(
                  selectedThreat.raw_data || {},
                  null,
                  2
                )}
              </pre>

            </div>

          </div>

        </div>

      )}

    </>
  )
}

export default App