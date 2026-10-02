import { useState, useEffect } from 'react'
import Sidebar from './components/Sidebar'
import TopBar from './components/TopBar'
import Dashboard from './pages/Dashboard'
import ScanHistory from './pages/ScanHistory'
import SecurityTips from './pages/SecurityTips'
import Settings from './pages/Settings'

const STORAGE_KEYS = {
  THEME: 'phishshield_theme',
  HISTORY: 'phishshield_scan_history',
}

const MAX_HISTORY = 50

export default function App() {
  const [currentPage, setCurrentPage] = useState('dashboard')
  const [darkMode, setDarkMode] = useState(false) // Forced light mode by default
  const [scanHistory, setScanHistory] = useState(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEYS.HISTORY)
      return saved ? JSON.parse(saved) : []
    } catch {
      return []
    }
  })
  const [sidebarOpen, setSidebarOpen] = useState(false)

  // Apply theme
  useEffect(() => {
    document.documentElement.classList.toggle('dark', darkMode)
    localStorage.setItem(STORAGE_KEYS.THEME, darkMode ? 'dark' : 'light')
  }, [darkMode])

  // Persist history
  useEffect(() => {
    localStorage.setItem(STORAGE_KEYS.HISTORY, JSON.stringify(scanHistory))
  }, [scanHistory])

  const addScan = (result) => {
    const scan = {
      id: Date.now().toString(),
      timestamp: new Date().toISOString(),
      ...result,
    }
    setScanHistory(prev => {
      const updated = [scan, ...prev]
      return updated.slice(0, MAX_HISTORY)
    })
  }

  const clearHistory = () => {
    setScanHistory([])
  }

  const toggleTheme = () => setDarkMode(prev => !prev)

  const renderPage = () => {
    switch (currentPage) {
      case 'dashboard':
        return (
          <Dashboard
            scanHistory={scanHistory}
            addScan={addScan}
            onNavigate={setCurrentPage}
          />
        )
      case 'scan':
        return (
          <Dashboard
            scanHistory={scanHistory}
            addScan={addScan}
            onNavigate={setCurrentPage}
            autoFocusScanner
          />
        )
      case 'history':
        return (
          <ScanHistory
            history={scanHistory}
            clearHistory={clearHistory}
          />
        )
      case 'tips':
        return <SecurityTips />
      case 'settings':
        return (
          <Settings
            darkMode={darkMode}
            toggleTheme={toggleTheme}
            clearHistory={clearHistory}
            historyCount={scanHistory.length}
          />
        )
      default:
        return (
          <Dashboard
            scanHistory={scanHistory}
            addScan={addScan}
            onNavigate={setCurrentPage}
          />
        )
    }
  }

  return (
    <div className="app-layout">
      {/* Mobile overlay */}
      <div
        className={`sidebar-overlay ${sidebarOpen ? 'visible' : ''}`}
        onClick={() => setSidebarOpen(false)}
        aria-hidden="true"
      />

      <Sidebar
        currentPage={currentPage}
        onNavigate={(page) => {
          setCurrentPage(page)
          setSidebarOpen(false)
        }}
        isOpen={sidebarOpen}
      />

      <div className="main-area">
        <TopBar
          darkMode={darkMode}
          toggleTheme={toggleTheme}
          onMenuClick={() => setSidebarOpen(prev => !prev)}
        />
        <div className="page-content">
          {renderPage()}
        </div>
      </div>

      {/* Mobile sidebar toggle */}
      <button
        className="sidebar-toggle"
        onClick={() => setSidebarOpen(prev => !prev)}
        aria-label="Toggle sidebar"
        title="Toggle sidebar"
      >
        ☰
      </button>
    </div>
  )
}
