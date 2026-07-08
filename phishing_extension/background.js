const BACKEND_URL = "http://127.0.0.1:5000";

console.log("✅ background.js loaded");

// Track analyzed URLs to prevent duplicate popups
const analyzedUrls = new Set();

// Analyze on page load
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    if (tab.url.startsWith("http://") || tab.url.startsWith("https://")) {
      console.log("🔍 Analyzing tab:", tab.url);
      analyzeURL(tab.url, tabId);
    }
  }
});

// Listen for messages from popup (manual check)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log("📨 Message received:", request.action);

  if (request.action === "checkURL") {
    const tabId = sender.tab ? sender.tab.id : null;
    analyzeURL(request.url, tabId, sendResponse);
    return true;
  }
});

async function analyzeURL(url, tabId = null, sendResponse = null) {
  try {
    console.log("🚀 Starting analysis for:", url);

    const response = await fetch(`${BACKEND_URL}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url }),
    });

    console.log("📡 Response status:", response.status);

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const result = await response.json();
    console.log("✅ Prediction received:", result);

    if (tabId) {
      const badgeColor = result.isPhishing ? "#FF0000" : "#00AA00";
      const badgeText = result.isPhishing ? "⚠️" : "✓";

      chrome.action.setBadgeBackgroundColor({
        color: badgeColor,
        tabId: tabId,
      });
      chrome.action.setBadgeText({
        text: badgeText,
        tabId: tabId,
      });
      console.log("🎯 Badge updated:", badgeText);

      const risky =
        result.riskLevel === "CRITICAL" ||
        result.riskLevel === "HIGH" ||
        result.riskLevel === "MEDIUM";

      if (risky && !analyzedUrls.has(url)) {
        console.log(
          "📱 Opening inline Phishentia alert with risk:",
          result.riskLevel,
          "confidence:",
          result.confidence
        );
        analyzedUrls.add(url);
        openInlineAlert(tabId, result);
      } else if (!risky) {
        console.log("✅ URL is LOW risk or safe, no popup needed");
      }
    }

    chrome.storage.local.get(["urlHistory"], (data) => {
      let history = data.urlHistory || [];
      history.unshift({
        url: url,
        isPhishing: result.isPhishing,
        confidence: result.confidence,
        riskLevel: result.riskLevel,
        indicators: result.indicators,
        timestamp: new Date().toISOString(),
      });
      history = history.slice(0, 100);
      chrome.storage.local.set({ urlHistory: history });
      console.log("💾 Saved to history");
    });

    if (sendResponse) {
      console.log("📤 Sending response to popup");
      sendResponse(result);
    }
  } catch (error) {
    console.error("❌ Error:", error.message);

    const errorResult = {
      error: error.message,
      isPhishing: false,
      confidence: 0,
      riskLevel: "ERROR",
      indicators: [`Error: ${error.message}`],
    };

    if (sendResponse) {
      sendResponse(errorResult);
    }
  }
}

// Opens popup-alert.html IN THE SAME TAB (replaces page)
function openInlineAlert(tabId, data) {
  try {
    chrome.tabs.update(tabId, {
      url:
        chrome.runtime.getURL("popup-alert.html") +
        "?data=" +
        encodeURIComponent(JSON.stringify(data)),
    });
  } catch (error) {
    console.error("❌ Error opening inline alert:", error);
  }
}
