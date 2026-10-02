export default function EmptyState({ icon: Icon, title, description }) {
  return (
    <div className="empty-state">
      <div className="empty-state-icon" aria-hidden="true">
        <Icon size={32} />
      </div>
      <h4>{title}</h4>
      <p>{description}</p>
    </div>
  )
}
