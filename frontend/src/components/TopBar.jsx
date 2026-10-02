import { Search, Moon, Sun, Bell } from 'lucide-react'

export default function TopBar({ darkMode, toggleTheme, onMenuClick }) {
  return (
    <header className="topbar" role="banner">
      <div className="topbar-search">
        <Search size={18} aria-hidden="true" />
        <input
          type="search"
          placeholder="Search..."
          aria-label="Search"
        />
      </div>

      <div className="topbar-actions">
        <button
          className="topbar-btn"
          onClick={toggleTheme}
          aria-label={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
          title={darkMode ? 'Light mode' : 'Dark mode'}
        >
          {darkMode ? <Sun size={18} /> : <Moon size={18} />}
        </button>
        <button
          className="topbar-btn"
          aria-label="Notifications"
          title="Notifications"
        >
          <Bell size={18} />
        </button>
      </div>
    </header>
  )
}
