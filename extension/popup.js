// popup.js

document.addEventListener('DOMContentLoaded', async () => {
  const scanBtn = document.getElementById('scan-btn');
  const statusContainer = document.getElementById('status-container');
  const statusTitle = document.getElementById('status-title');
  const statusUrl = document.getElementById('status-url');
  const loader = document.getElementById('loader');

  // Get current tab URL
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab) {
    statusUrl.textContent = tab.url;
  }

  scanBtn.addEventListener('click', async () => {
    if (!tab || !tab.url) return;

    // UI Update
    scanBtn.disabled = true;
    loader.style.display = 'block';
    statusContainer.className = 'status-card';
    statusTitle.textContent = 'Scanning...';

    // Send to background script
    chrome.runtime.sendMessage({ action: "check_url", url: tab.url, tabId: tab.id }, (response) => {
      loader.style.display = 'none';
      scanBtn.disabled = false;

      if (chrome.runtime.lastError) {
        statusTitle.textContent = "Error";
        statusTitle.style.color = "#ef4444";
        statusUrl.textContent = "Could not connect to background script.";
        return;
      }

      if (response && response.success) {
        const data = response.data;
        if (data.verdict === "Phishing") {
          statusContainer.className = 'status-card phishing';
          statusTitle.textContent = `Phishing Detected (${Math.round(data.phishing_probability * 100)}%)`;
          statusTitle.style.color = "#ef4444";
        } else {
          statusContainer.className = 'status-card safe';
          statusTitle.textContent = `Safe Website (${Math.round(data.legitimate_probability * 100)}%)`;
          statusTitle.style.color = "#10b981";
        }
      } else {
        statusTitle.textContent = "API Error";
        statusTitle.style.color = "#ef4444";
        statusUrl.textContent = "Backend server is likely not running. Ensure FastAPI is active on port 8000.";
      }
    });
  });
});
