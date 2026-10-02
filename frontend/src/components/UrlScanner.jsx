import { useState, useRef, useEffect } from 'react'
import { Link, Search, AlertCircle, Loader } from 'lucide-react'
import axios from 'axios'

const API_URL = 'http://127.0.0.1:8000'

const LOADING_STAGES = [
  'Extracting URL features...',
  'Analyzing URL structure...',
  'Running deep-learning model...',
  'Generating risk assessment...',
]

export default function UrlScanner({ onResult, onError, autoFocus }) {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [stage, setStage] = useState(0)
  const inputRef = useRef(null)

  useEffect(() => {
    if (autoFocus && inputRef.current) {
      inputRef.current.focus()
    }
  }, [autoFocus])

  // Simulate loading stages for visual feedback
  useEffect(() => {
    if (!loading) {
      setStage(0)
      return
    }
    const interval = setInterval(() => {
      setStage(prev => (prev < LOADING_STAGES.length - 1 ? prev + 1 : prev))
    }, 600)
    return () => clearInterval(interval)
  }, [loading])

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')

    const trimmed = url.trim()
    if (!trimmed) {
      setError('Please enter a website URL.')
      return
    }

    setLoading(true)
    try {
      const response = await axios.post(`${API_URL}/predict`, { url: trimmed }, {
        timeout: 30000,
      })
      onResult(response.data)
    } catch (err) {
      let message = 'Something went wrong while analyzing the URL.'
      if (err.response) {
        if (err.response.data?.detail) {
          message = err.response.data.detail
        } else if (err.response.status === 503) {
          message = 'The AI model is not loaded. Please ensure the backend model is trained.'
        }
      } else if (err.code === 'ECONNABORTED') {
        message = 'Request timed out. Please try again.'
      } else if (err.message?.includes('Network Error')) {
        message = 'Unable to connect to the PhishShield AI backend. Make sure the server is running on port 8000.'
      }
      setError(message)
      if (onError) onError(message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="scanner-card">
      <h3>🔍 Website URL</h3>
      <p>Enter a URL to analyze with our AI-powered phishing detection model.</p>

      <form onSubmit={handleSubmit}>
        <div className="scanner-input-group">
          <div className="scanner-input-wrapper">
            <Link size={20} aria-hidden="true" />
            <input
              ref={inputRef}
              type="text"
              className="scanner-input"
              placeholder="Enter website URL..."
              value={url}
              onChange={(e) => {
                setUrl(e.target.value)
                setError('')
              }}
              aria-label="Website URL input"
              disabled={loading}
            />
          </div>
          <button
            type="submit"
            className="scanner-btn"
            disabled={loading}
            aria-label="Analyze URL"
          >
            {loading ? (
              <>
                <Loader size={18} className="spin-icon" />
                Analyzing...
              </>
            ) : (
              <>
                <Search size={18} />
                Analyze URL
              </>
            )}
          </button>
        </div>
      </form>

      <p className="scanner-hint">Example: https://example.com</p>

      {error && (
        <div className="scanner-error" role="alert">
          <AlertCircle size={16} />
          {error}
        </div>
      )}

      {loading && (
        <div className="loading-overlay">
          <div className="loading-spinner" aria-hidden="true" />
          <div className="loading-stages" aria-live="polite">
            {LOADING_STAGES.map((text, i) => (
              <div
                key={i}
                className={`loading-stage ${i < stage ? 'done' : ''} ${i === stage ? 'active' : ''}`}
              >
                <span className="loading-stage-dot" aria-hidden="true" />
                {text}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
