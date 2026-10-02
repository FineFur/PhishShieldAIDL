import { useState, useEffect } from 'react'
import { Globe, ShieldAlert, Target } from 'lucide-react'
import axios from 'axios'
import StatCard from '../components/StatCard'
import UrlScanner from '../components/UrlScanner'
import ScanResult from '../components/ScanResult'
import RecentScans from '../components/RecentScans'

const API_URL = 'http://127.0.0.1:8000'

export default function Dashboard({ scanHistory, addScan, onNavigate, autoFocusScanner }) {
  const [scanResult, setScanResult] = useState(null)
  const [modelAccuracy, setModelAccuracy] = useState(null)

  // Fetch model accuracy on mount
  useEffect(() => {
    const fetchModelInfo = async () => {
      try {
        const res = await axios.get(`${API_URL}/model-info`, { timeout: 5000 })
        if (res.data?.training_metrics?.accuracy) {
          setModelAccuracy(res.data.training_metrics.accuracy)
        }
      } catch {
        // Backend may not be running; that's okay
      }
    }
    fetchModelInfo()
  }, [])

  const handleResult = (result) => {
    setScanResult(result)
    addScan(result)
  }

  // Calculate stats from actual scan history
  const totalScans = scanHistory.length
  const phishingDetected = scanHistory.filter(s => s.verdict === 'Phishing').length
  const accuracyDisplay = modelAccuracy
    ? `${(modelAccuracy * 100).toFixed(1)}%`
    : 'Not evaluated'

  return (
    <>
      {/* Page Header */}
      <div className="page-header">
        <h2>Your Cybersecurity Companion</h2>
        <p>Analyze suspicious URLs with AI-powered phishing detection.</p>
      </div>

      {/* Statistics */}
      <div className="stats-grid">
        <StatCard
          icon={Globe}
          label="URLs Scanned"
          value={totalScans}
          variant="primary"
        />
        <StatCard
          icon={ShieldAlert}
          label="Phishing Detected"
          value={phishingDetected}
          variant="danger"
        />
        <StatCard
          icon={Target}
          label="Detection Accuracy"
          value={accuracyDisplay}
          variant="success"
        />
      </div>

      {/* URL Scanner */}
      <UrlScanner
        onResult={handleResult}
        autoFocus={autoFocusScanner}
      />

      {/* Scan Result */}
      {scanResult && <ScanResult result={scanResult} />}

      {/* Recent Scans */}
      <RecentScans
        scans={scanHistory}
        onViewAll={() => onNavigate('history')}
      />
    </>
  )
}
