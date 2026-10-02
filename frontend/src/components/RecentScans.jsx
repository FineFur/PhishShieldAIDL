import { Clock } from 'lucide-react'
import EmptyState from './EmptyState'

export default function RecentScans({ scans, onViewAll }) {
  const recentScans = scans.slice(0, 5)

  if (recentScans.length === 0) {
    return (
      <div className="recent-scans">
        <div className="recent-scans-header">
          <h4>Recent Scans</h4>
        </div>
        <EmptyState
          icon={Clock}
          title="No scans yet"
          description="Scan a URL above to see your results here."
        />
      </div>
    )
  }

  return (
    <div className="recent-scans">
      <div className="recent-scans-header">
        <h4>Recent Scans</h4>
        <a onClick={onViewAll} role="button" tabIndex={0} onKeyDown={(e) => e.key === 'Enter' && onViewAll()}>
          View All
        </a>
      </div>
      <div className="scans-table-wrapper">
        <table className="scans-table">
          <thead>
            <tr>
              <th>URL</th>
              <th>Verdict</th>
              <th>Risk</th>
              <th>Probability</th>
              <th>Time</th>
            </tr>
          </thead>
          <tbody>
            {recentScans.map(scan => (
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
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
