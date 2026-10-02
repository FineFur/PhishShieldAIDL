// background.js
// Service worker for PhishShield AI extension

const API_URL = "http://127.0.0.1:8000/predict";

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "check_url") {
    // We must handle the async fetch and keep the message channel open by returning true
    (async () => {
      try {
        const response = await fetch(API_URL, {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({ url: message.url })
        });
        
        if (!response.ok) {
          throw new Error(`API error: ${response.status}`);
        }
        
        const data = await response.json();
        
        // If it's a high risk phishing site, update the badge
        const tabId = (sender.tab && sender.tab.id) ? sender.tab.id : message.tabId;
        if (tabId) {
          if (data.verdict === "Phishing") {
            await chrome.action.setBadgeText({ text: 'RISK', tabId: tabId });
            await chrome.action.setBadgeBackgroundColor({ color: '#ef4444', tabId: tabId });
          } else {
            await chrome.action.setBadgeText({ text: 'SAFE', tabId: tabId });
            await chrome.action.setBadgeBackgroundColor({ color: '#10b981', tabId: tabId });
          }
        }
        
        sendResponse({ success: true, data });
      } catch (error) {
        console.error("PhishShield API Error:", error);
        sendResponse({ success: false, error: error.message });
      }
    })();
    return true; // Keep channel open for async response
  }
});
