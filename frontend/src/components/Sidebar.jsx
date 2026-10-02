import { Shield, LayoutDashboard, Search, History, BookOpen, Settings } from 'lucide-react'

const navItems = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'scan', label: 'Scan URL', icon: Search },
  { id: 'history', label: 'Scan History', icon: History },
  { id: 'tips', label: 'Security Tips', icon: BookOpen },
  { id: 'settings', label: 'Settings', icon: Settings },
]

export default function Sidebar({ currentPage, onNavigate, isOpen }) {
  return (
    <aside className={`sidebar ${isOpen ? 'open' : ''}`} role="navigation" aria-label="Main navigation">
      {/* Brand */}
      <div className="sidebar-brand">
        <div className="sidebar-logo" aria-hidden="true">
          <Shield size={22} />
        </div>
        <div className="sidebar-brand-text">
          <h1>PhishShield AI</h1>
          <p>Phishing Detection</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="sidebar-nav">
        <div className="sidebar-section-label">Menu</div>
        {navItems.map(item => {
          const Icon = item.icon
          const isActive = currentPage === item.id ||
            (item.id === 'dashboard' && currentPage === 'scan')
            ? (item.id === 'dashboard' && currentPage === 'scan' ? false : true)
            : false

          // Special case: "scan" and "dashboard" share a page
          const active = currentPage === item.id

          return (
            <button
              key={item.id}
              className={`sidebar-item ${active ? 'active' : ''}`}
              onClick={() => onNavigate(item.id)}
              aria-label={`Navigate to ${item.label}`}
              title={item.label}
            >
              <Icon size={20} />
              {item.label}
            </button>
          )
        })}
      </nav>

      {/* Footer */}
      <div className="sidebar-footer">
        <p>© 2026 PhishShield AI</p>
        <p>Deep Learning Detection</p>
      </div>
    </aside>
  )
}
