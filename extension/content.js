// content.js
// Runs on every page. Scans for password inputs and acts as a Zero-Trust shield.

// Inject overlay if phishing is detected
function injectWarningOverlay(data) {
  // Don't inject multiple times
  if (document.getElementById('phishshield-warning-overlay')) return;

  const overlay = document.createElement('div');
  overlay.id = 'phishshield-warning-overlay';
  overlay.className = 'phishshield-overlay';

  // Extract top warnings
  let warningsHtml = '';
  if (data.features && data.features.explanations) {
    const warnings = data.features.explanations.filter(f => f.status === 'warning').slice(0, 3);
    if (warnings.length > 0) {
      warningsHtml = `
        <div class="phishshield-feature-list">
          <p style="margin:0 0 0.5rem 0; color:#fff; font-weight:600; font-size: 0.9rem;">Suspicious Features Detected:</p>
          ${warnings.map(w => `<div class="phishshield-feature">⚠️ ${w.explanation}</div>`).join('')}
        </div>
      `;
    }
  }

  overlay.innerHTML = `
    <div class="phishshield-card">
      <h1 class="phishshield-title">⚠️ Phishing Detected</h1>
      <p class="phishshield-text">
        PhishShield AI has determined this website is highly dangerous. 
        It is masquerading as a legitimate login page to steal your credentials.
      </p>
      
      ${warningsHtml}
      
      <p style="color: #94a3b8; font-size: 0.85rem; margin-bottom: 1.5rem;">
        Threat Confidence: ${Math.round(data.phishing_probability * 100)}%
      </p>

      <div class="phishshield-button-container">
        <button class="phishshield-btn phishshield-btn-primary" id="phishshield-leave">Get Me Out of Here</button>
        <button class="phishshield-btn phishshield-btn-secondary" id="phishshield-ignore">I Understand the Risks</button>
      </div>
    </div>
  `;

  document.body.appendChild(overlay);

  // Disable scrolling
  document.body.style.overflow = 'hidden';

  // Event listeners
  document.getElementById('phishshield-leave').addEventListener('click', () => {
    window.location.href = 'https://www.google.com';
  });

  document.getElementById('phishshield-ignore').addEventListener('click', () => {
    overlay.remove();
    document.body.style.overflow = '';
  });
}

// Analyze the page
function scanPage() {
  // Only scan if the page asks for credentials (password field)
  // This saves API calls and prevents sending every single URL the user visits
  const hasPasswordInput = document.querySelector('input[type="password"]') !== null;
  
  if (hasPasswordInput) {
    console.log("[PhishShield AI] Login page detected. Analyzing URL...");
    
    // Send URL to background script for ML analysis
    chrome.runtime.sendMessage(
      { action: "check_url", url: window.location.href },
      (response) => {
        if (chrome.runtime.lastError) {
          console.error("[PhishShield AI] Messaging error:", chrome.runtime.lastError);
          return;
        }
        
        if (response && response.success) {
          console.log("[PhishShield AI] Verdict:", response.data.verdict);
          if (response.data.verdict === "Phishing") {
            injectWarningOverlay(response.data);
          }
        } else {
          console.error("[PhishShield AI] Analysis failed:", response?.error);
        }
      }
    );
  }
}

// Run scan when DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", scanPage);
} else {
  scanPage();
}
