import { ShieldCheck, ShieldAlert, ShieldQuestion, Link } from 'lucide-react'
import FeatureCard from './FeatureCard'

export default function ScanResult({ result }) {
  if (!result) return null

  const { verdict, phishing_probability, legitimate_probability, risk_level, recommendation, url, features } = result

  const isPhishing = verdict === 'Phishing'
  const headerClass = risk_level === 'High' ? 'danger' : risk_level === 'Medium' ? 'warning' : 'safe'
  const VerdictIcon = isPhishing ? ShieldAlert : risk_level === 'Medium' ? ShieldQuestion : ShieldCheck

  const explanations = features?.explanations || []

  return (
    <div className="result-card" role="region" aria-label="Scan result">
      {/* Header */}
      <div className={`result-header ${headerClass}`}>
        <div className="result-verdict">
          <div className={`verdict-icon ${headerClass}`} aria-hidden="true">
            <VerdictIcon size={28} />
          </div>
          <div className="verdict-text">
            <h3 className={headerClass}>{verdict}</h3>
            <p>
              Risk Level:{' '}
              <span className={`result-risk-badge risk-${risk_level.toLowerCase()}`}>
                {risk_level}
              </span>
            </p>
          </div>
        </div>

        <div className="result-probabilities">
          <div className="prob-item">
            <div className={`prob-value ${isPhishing ? 'danger' : 'success'}`}>
              {(phishing_probability * 100).toFixed(1)}%
            </div>
            <div className="prob-label">Phishing</div>
          </div>
          <div className="prob-item">
            <div className={`prob-value ${!isPhishing ? 'success' : 'danger'}`}>
              {(legitimate_probability * 100).toFixed(1)}%
            </div>
            <div className="prob-label">Legitimate</div>
          </div>
        </div>
      </div>

      {/* Body */}
      <div className="result-body">
        {/* Analyzed URL */}
        <div className="result-url">
          <span><Link size={14} /> URL:</span>
          <code>{url}</code>
        </div>

        {/* Recommendation */}
        <div className="result-recommendation">
          <p>{recommendation}</p>
        </div>

        {/* Feature explanations */}
        {explanations.length > 0 && (
          <div className="features-section">
            <h4>
              {isPhishing ? '⚠️ Why this URL may be suspicious' : '✅ URL Feature Analysis'}
            </h4>
            <div className="features-grid">
              {explanations.map((exp, i) => (
                <FeatureCard key={i} explanation={exp} />
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
