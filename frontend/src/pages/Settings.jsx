import { useState } from 'react'

export default function Settings({ darkMode, toggleTheme, clearHistory, historyCount }) {
  const [showConfirm, setShowConfirm] = useState(false)

  const handleClear = () => {
    clearHistory()
    setShowConfirm(false)
  }

  return (
    <>
      <div className="page-header">
        <h2>Settings</h2>
        <p>Configure your PhishShield AI experience.</p>
      </div>

      {/* Appearance */}
      <div className="settings-section">
        <h4>🎨 Appearance</h4>
        <div className="setting-row">
          <div className="setting-info">
            <h5>Dark Mode</h5>
            <p>Switch between light and dark themes.</p>
          </div>
          <label className="toggle-switch">
            <input
              type="checkbox"
              checked={darkMode}
              onChange={toggleTheme}
              aria-label="Toggle dark mode"
            />
            <span className="toggle-slider" />
          </label>
        </div>
      </div>

      {/* Scanning */}
      <div className="settings-section">
        <h4>🔍 Scanning</h4>
        <div className="setting-row">
          <div className="setting-info">
            <h5>Risk Thresholds</h5>
            <p>Application-level risk classification bands used for URL analysis.</p>
          </div>
          <div style={{ textAlign: 'right', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            <div><span className="result-risk-badge risk-low" style={{ marginBottom: 4, display: 'inline-block' }}>Low</span> 0% – 29%</div>
            <div style={{ marginTop: 4 }}><span className="result-risk-badge risk-medium" style={{ marginBottom: 4, display: 'inline-block' }}>Medium</span> 30% – 69%</div>
            <div style={{ marginTop: 4 }}><span className="result-risk-badge risk-high" style={{ display: 'inline-block' }}>High</span> 70% – 100%</div>
          </div>
        </div>
      </div>

      {/* Privacy */}
      <div className="settings-section">
        <h4>🔒 Privacy</h4>
        <div className="setting-row">
          <div className="setting-info">
            <h5>Data Storage</h5>
            <p>
              Scan history is stored locally in your browser's localStorage.
              No data is sent to external servers. Your scan records remain private and
              are only accessible on this device and browser.
            </p>
          </div>
        </div>
      </div>

      {/* History */}
      <div className="settings-section">
        <h4>📋 History</h4>
        <div className="setting-row">
          <div className="setting-info">
            <h5>Clear Scan History</h5>
            <p>Remove all {historyCount} stored scan records from this browser.</p>
          </div>
          <button
            className="settings-btn danger"
            onClick={() => setShowConfirm(true)}
            disabled={historyCount === 0}
            aria-label="Clear scan history"
          >
            Clear History
          </button>
        </div>
      </div>

      {/* About */}
      <div className="settings-section">
        <h4>ℹ️ About</h4>
        <div className="about-grid">
          <div className="about-item">
            <span>Application</span>
            <span>PhishShield AI</span>
          </div>
          <div className="about-item">
            <span>Description</span>
            <span>Deep-learning based phishing URL detection</span>
          </div>
          <div className="about-item">
            <span>Model</span>
            <span>Feed-Forward Neural Network (MLP)</span>
          </div>
          <div className="about-item">
            <span>Framework</span>
            <span>TensorFlow / Keras</span>
          </div>
          <div className="about-item">
            <span>Backend</span>
            <span>FastAPI + Python</span>
          </div>
          <div className="about-item">
            <span>Frontend</span>
            <span>React + Vite</span>
          </div>
          <div className="about-item">
            <span>Features</span>
            <span>16 engineered URL features</span>
          </div>
          <div className="about-item">
            <span>Version</span>
            <span>1.0.0</span>
          </div>
        </div>
      </div>

      {/* Confirm Dialog */}
      {showConfirm && (
        <div className="confirm-overlay" onClick={() => setShowConfirm(false)} role="dialog" aria-modal="true">
          <div className="confirm-dialog" onClick={e => e.stopPropagation()}>
            <h4>Clear Scan History?</h4>
            <p>This will permanently delete all {historyCount} scan records. This action cannot be undone.</p>
            <div className="confirm-actions">
              <button className="confirm-cancel" onClick={() => setShowConfirm(false)}>Cancel</button>
              <button className="confirm-delete" onClick={handleClear}>Clear All</button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
