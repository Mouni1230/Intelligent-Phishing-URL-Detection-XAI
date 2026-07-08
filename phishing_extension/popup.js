console.log("✅ popup.js loaded");

document.addEventListener("DOMContentLoaded", () => {
  console.log("📋 DOM loaded - starting popup initialization");
  loadCurrentURL();
  setupEventListeners();
});

function setupEventListeners() {
  console.log("🔧 Setting up event listeners");

  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      switchTab(e.target.dataset.tab);
    });
  });

  if (document.getElementById("scanBtn")) {
    document.getElementById("scanBtn").addEventListener("click", scanCustomURL);
  }

  if (document.getElementById("urlInput")) {
    document.getElementById("urlInput").addEventListener("keypress", (e) => {
      if (e.key === "Enter") scanCustomURL();
    });
  }
}

async function loadCurrentURL() {
  try {
    console.log("🔄 Loading current URL...");

    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tabs || tabs.length === 0) {
      console.error("No active tabs found");
      displayError("No active tab");
      return;
    }

    const currentTab = tabs[0];
    const url = currentTab.url;

    console.log("📄 Current URL:", url);

    const urlDisplay = document.getElementById("urlDisplay");
    if (urlDisplay) {
      urlDisplay.textContent = url;
    }

    // Send message to background script and wait for response
    chrome.runtime.sendMessage({ action: "checkURL", url: url }, (response) => {
      console.log("📨 Response from background:", response);

      if (chrome.runtime.lastError) {
        console.error("Runtime error:", chrome.runtime.lastError);
        displayError(chrome.runtime.lastError.message);
      } else if (response && !response.error) {
        console.log("✅ Valid response received");
        displayAnalysisResult(response);
      } else if (response && response.error) {
        console.error("Error in response:", response.error);
        displayError(response.error);
      } else {
        console.error("No response received");
        displayError("No response from backend");
      }
    });
  } catch (error) {
    console.error("❌ Error loading URL:", error);
    displayError(error.message);
  }
}

function displayAnalysisResult(result) {
  console.log("🎨 Displaying result:", result);

  const resultDiv = document.getElementById("analysisResult");
  if (!resultDiv) {
    console.error("analysisResult div not found");
    return;
  }

  const verdictBox = document.getElementById("verdictBox");
  const confidenceFill = document.getElementById("confidenceFill");
  const indicatorsList = document.getElementById("indicatorsList");
  const technicalDetails = document.getElementById("technicalDetails");

  // Determine verdict class
  const verdictClass = result.isPhishing
    ? result.confidence >= 70
      ? "phishing"
      : "medium"
    : "safe";

  const verdictText = result.isPhishing
    ? result.confidence >= 70
      ? "⚠️ PHISHING DETECTED"
      : "⚠️ SUSPICIOUS"
    : "✅ SAFE & LEGITIMATE";

  // Update verdict
  verdictBox.className = `verdict ${verdictClass}`;
  verdictBox.innerHTML = verdictText;

  // Update confidence bar
  const confidence = Math.min(result.confidence || 0, 100);
  confidenceFill.style.width = confidence + "%";
  confidenceFill.textContent = confidence + "%";

  // Update indicators
  const indicators = result.indicators || ["✓ No issues detected"];
  indicatorsList.innerHTML = indicators
    .map((indicator) => {
      const isCritical = indicator.includes("❌");
      const isWarning = indicator.includes("⚠️");
      const isSafe = indicator.includes("✓");

      const className = isCritical
        ? "critical"
        : isWarning
        ? "warning"
        : "safe";
      const icon = isCritical ? "❌" : isWarning ? "⚠️" : "✅";
      const text = indicator.replace(/[❌⚠️✓]/g, "").trim();

      return `<li class="indicator-item ${className}">
        <span class="indicator-icon">${icon}</span>
        <span>${text}</span>
      </li>`;
    })
    .join("");

  // Update technical details
  technicalDetails.innerHTML = `
    <strong>Risk Level:</strong> ${result.riskLevel || "UNKNOWN"}<br>
    <strong>Confidence:</strong> ${result.confidence || 0}%<br>
    <strong>Issues Found:</strong> ${indicators.length}<br>
    <strong>Analysis:</strong> ${getAssessmentText(result)}
  `;

  // Show results
  resultDiv.style.display = "block";
  console.log("✅ Result displayed successfully");
}

function displayError(error) {
  console.error("🔴 Display error:", error);

  const resultDiv = document.getElementById("analysisResult");
  if (!resultDiv) return;

  const verdictBox = document.getElementById("verdictBox");
  const technicalDetails = document.getElementById("technicalDetails");

  verdictBox.className = "verdict medium";
  verdictBox.innerHTML = "⚠️ Unable to analyze URL";

  technicalDetails.innerHTML = `
    <strong>Error:</strong> ${error}<br>
    <strong>Troubleshooting:</strong><br>
    • Check if backend server is running<br>
    • Verify server at http://127.0.0.1:5000/health<br>
    • Check console for detailed errors
  `;

  resultDiv.style.display = "block";
}

function getAssessmentText(result) {
  if (!result.confidence) return "Unable to assess";

  if (result.confidence >= 80) {
    return "Highly likely to be phishing. DO NOT interact.";
  } else if (result.confidence >= 60) {
    return "Suspicious characteristics detected. Exercise caution.";
  } else if (result.confidence >= 40) {
    return "Some unusual patterns found. Review before proceeding.";
  } else {
    return "Appears to be legitimate. Safe to visit.";
  }
}

function scanCustomURL() {
  const urlInput = document.getElementById("urlInput");
  const url = urlInput ? urlInput.value.trim() : "";

  if (!url) {
    alert("Please enter a URL");
    return;
  }

  const fullURL = url.startsWith("http") ? url : "https://" + url;
  console.log("🔍 Scanning custom URL:", fullURL);

  chrome.runtime.sendMessage(
    { action: "checkURL", url: fullURL },
    (response) => {
      console.log("📨 Scan response:", response);

      const scanResult = document.getElementById("scanResult");
      if (!scanResult) return;

      if (response && !response.error) {
        const verdictClass = response.isPhishing
          ? response.confidence >= 70
            ? "phishing"
            : "medium"
          : "safe";

        scanResult.innerHTML = `
          <div class="verdict ${verdictClass}">
            ${response.isPhishing ? "⚠️ PHISHING DETECTED" : "✅ SAFE"}
          </div>
          <div style="margin-top: 12px; font-size: 12px;">
            <strong>Confidence:</strong> ${response.confidence}%<br>
            <strong>Risk Level:</strong> ${response.riskLevel}<br>
            <strong>Analysis:</strong><br>
            <ul class="indicator-list">
              ${(response.indicators || [])
                .map((ind) => {
                  const isCrit = ind.includes("❌");
                  return `<li class="indicator-item ${
                    isCrit
                      ? "critical"
                      : ind.includes("⚠️")
                      ? "warning"
                      : "safe"
                  }">
                  ${ind}
                </li>`;
                })
                .join("")}
            </ul>
          </div>
        `;
      } else {
        scanResult.innerHTML = `<div class="verdict medium">Error: ${
          response?.error || "Unknown error"
        }</div>`;
      }
    }
  );
}

function switchTab(tabName) {
  document.querySelectorAll(".tab-content").forEach((tab) => {
    tab.classList.remove("active");
  });
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.classList.remove("active");
  });

  const tabContent = document.getElementById(tabName);
  const tabBtn = document.querySelector(`[data-tab="${tabName}"]`);

  if (tabContent) tabContent.classList.add("active");
  if (tabBtn) tabBtn.classList.add("active");

  if (tabName === "history") {
    loadHistory();
  }
}

function loadHistory() {
  chrome.storage.local.get(["urlHistory"], (data) => {
    const history = data.urlHistory || [];
    const historyList = document.getElementById("historyList");

    if (!historyList) return;

    if (history.length === 0) {
      historyList.innerHTML =
        '<p style="color: #999; text-align: center; padding: 20px;">No scan history</p>';
      return;
    }

    historyList.innerHTML = history
      .slice(0, 20)
      .map(
        (item) => `
      <div class="history-item ${item.isPhishing ? "phishing" : "safe"}">
        <strong>${item.isPhishing ? "⚠️ Suspicious" : "✅ Safe"}</strong> - ${
          item.riskLevel
        }<br>
        <small>${item.url.substring(0, 60)}${
          item.url.length > 60 ? "..." : ""
        }</small><br>
        <small style="opacity: 0.7;">${new Date(
          item.timestamp
        ).toLocaleTimeString()}</small>
      </div>
    `
      )
      .join("");
  });
}
