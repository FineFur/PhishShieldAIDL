export default function FeatureCard({ explanation }) {
  const { feature, value, status, explanation: desc } = explanation

  return (
    <div className="feature-card">
      <div className="feature-card-header">
        <span className="feature-name">{feature}</span>
        <span className={`feature-status ${status}`} aria-label={`Status: ${status}`} />
      </div>
      <div className="feature-value">{value}</div>
      <div className="feature-explanation">{desc}</div>
    </div>
  )
}
