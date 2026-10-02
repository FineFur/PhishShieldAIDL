import { useState } from 'react'
import { Search, Trash2, Clock, X, Eye } from 'lucide-react'
import EmptyState from '../components/EmptyState'

export default function ScanHistory({ history, clearHistory }) {
  const [searchQuery, setSearchQuery] = useState('')
  const [filter, setFilter] = useState('all')
  const [selectedScan, setSelectedScan] = useState(null)
  const [showConfirm, setShowConfirm] = useState(false)

  // Filter and search
  const filteredHistory = history.filter(scan => {
    const matchesSearch = scan.url?.toLowerCase().includes(searchQuery.toLowerCase())
    const matchesFilter = filter === 'all'
      || (filter === 'phishing' && scan.verdict === 'Phishing')
      || (filter === 'legitimate' && scan.verdict === 'Legitimate')
    return matchesSearch && matchesFilter
  })

  const handleClear = () => {
    clearHistory()
    setShowConfirm(false)
  }

  return (
    <>
      <div className="page-header">
        <h2>Scan History</h2>
        <p>View and manage your past URL scans.</p>
      </div>

      {/* Controls */}
      <div className="history-controls">
        <div className="history-search">
          <Search size={18} aria-hidden="true" />
          <input
            type="search"
            placeholder="Search by URL..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            aria-label="Search scan history"
          />
        </div>

        <div className="filter-group" role="group" aria-label="Filter scans">
          {['all', 'phishing', 'legitimate'].map(f => (
            <button
              key={f}
              className={`filter-btn ${filter === f ? 'active' : ''}`}
              onClick={() => setFilter(f)}
              aria-pressed={filter === f}
            >
              {f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
        </div>

        {history.length > 0 && (
          <button
            className="clear-history-btn"
            onClick={() => setShowConfirm(true)}
            aria-label="Clear scan history"
          >
            <Trash2 size={16} />
            Clear History
          </button>
        )}
      </div>

      {/* Table */}
      {filteredHistory.length === 0 ? (
        <div className="recent-scans">
          <EmptyState
            icon={Clock}
            title="No scans yet"
            description={searchQuery ? 'No scans match your search.' : 'Start scanning URLs to build your history.'}
          />
        </div>
      ) : (
        <div className="recent-scans">
          <div className="scans-table-wrapper">
            <table className="scans-table">
              <thead>
                <tr>
                  <th>URL</th>
                  <th>Verdict</th>
                  <th>Risk</th>
                  <th>Probability</th>
                  <th>Date/Time</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredHistory.map(scan => (
                  <tr key={scan.id}>
                    <td>
                      <div className="scan-url" title={scan.url}>{scan.url}</div>
                    </td>
                    <td>
                      <span className={`verdict-badge ${scan.verdict?.toLowerCase()}`}>
                        {scan.verdict}
                      </span>
                    </td>
                    <td>
                      <span className={`result-risk-badge risk-${scan.risk_level?.toLowerCase()}`}>
                        {scan.risk_level}
                      </span>
                    </td>
                    <td>{(scan.phishing_probability * 100).toFixed(1)}%</td>
                    <td>{new Date(scan.timestamp).toLocaleString()}</td>
                    <td>
                      <button
                        className="view-btn"
                        onClick={() => setSelectedScan(scan)}
                        aria-label={`View details for ${scan.url}`}
                      >
                        <Eye size={14} style={{ marginRight: 4, verticalAlign: 'middle' }} />
                        View
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Detail Modal */}
      {selectedScan && (
        <div className="detail-overlay" onClick={() => setSelectedScan(null)} role="dialog" aria-modal="true" aria-label="Scan details">
          <div className="detail-modal" onClick={e => e.stopPropagation()}>
            <div className="detail-header">
              <h3>Scan Details</h3>
              <button className="detail-close" onClick={() => setSelectedScan(null)} aria-label="Close details">
                <X size={18} />
              </button>
            </div>
            <div className="detail-body">
              <div className="detail-row">
                <span className="detail-label">URL</span>
                <span className="detail-value" style={{ fontFamily: 'monospace' }}>{selectedScan.url}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Verdict</span>
                <span className="detail-value">
                  <span className={`verdict-badge ${selectedScan.verdict?.toLowerCase()}`}>
                    {selectedScan.verdict}
                  </span>
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Risk Level</span>
                <span className="detail-value">
                  <span className={`result-risk-badge risk-${selectedScan.risk_level?.toLowerCase()}`}>
                    {selectedScan.risk_level}
                  </span>
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Phishing Prob.</span>
                <span className="detail-value">{(selectedScan.phishing_probability * 100).toFixed(2)}%</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Legitimate Prob.</span>
                <span className="detail-value">{(selectedScan.legitimate_probability * 100).toFixed(2)}%</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Scanned At</span>
                <span className="detail-value">{new Date(selectedScan.timestamp).toLocaleString()}</span>
              </div>
              {selectedScan.recommendation && (
                <div className="detail-row">
                  <span className="detail-label">Recommendation</span>
                  <span className="detail-value">{selectedScan.recommendation}</span>
                </div>
              )}

              {/* Feature values */}
              {selectedScan.features && (
                <>
                  <div style={{ marginTop: 16 }}>
                    <h4 style={{ fontSize: '0.9rem', fontWeight: 600, marginBottom: 12, color: 'var(--text-primary)' }}>
                      Extracted Features
                    </h4>
                    {Object.entries(selectedScan.features)
                      .filter(([key]) => key !== 'explanations')
                      .map(([key, value]) => (
                        <div className="detail-row" key={key}>
                          <span className="detail-label" style={{ fontSize: '0.75rem' }}>{key}</span>
                          <span className="detail-value">{typeof value === 'number' ? value.toFixed ? Number(value.toFixed(4)) : value : String(value)}</span>
                        </div>
                      ))}
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Confirm Clear Dialog */}
      {showConfirm && (
        <div className="confirm-overlay" onClick={() => setShowConfirm(false)} role="dialog" aria-modal="true" aria-label="Confirm clear history">
          <div className="confirm-dialog" onClick={e => e.stopPropagation()}>
            <h4>Clear Scan History?</h4>
            <p>This will permanently delete all {history.length} scan records. This action cannot be undone.</p>
            <div className="confirm-actions">
              <button className="confirm-cancel" onClick={() => setShowConfirm(false)}>
                Cancel
              </button>
              <button className="confirm-delete" onClick={handleClear}>
                Clear All
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
