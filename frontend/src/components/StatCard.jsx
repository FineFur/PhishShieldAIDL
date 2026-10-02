export default function StatCard({ icon: Icon, label, value, variant = 'primary' }) {
  return (
    <div className="stat-card">
      <div className={`stat-icon ${variant}`} aria-hidden="true">
        <Icon size={24} />
      </div>
      <div className="stat-content">
        <h3>{label}</h3>
        <div className="stat-value">{value}</div>
      </div>
    </div>
  )
}
