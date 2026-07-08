// content.js - Intercept all link clicks and check URLs

console.log("Content script loaded on:", window.location.href);

document.addEventListener(
  "click",
  (event) => {
    const link = event.target.closest("a");
    if (!link) return;

    const href = link.getAttribute("href");
    console.log("Link clicked:", href);

    if (!href || !href.startsWith("http")) return;

    // Send to background script for analysis
    chrome.runtime.sendMessage(
      { action: "checkURL", url: href },
      (response) => {
        console.log("Response received:", response);

        if (response && response.isPhishing) {
          event.preventDefault();
          event.stopPropagation();
          console.log("Phishing detected! Showing warning...");
          showPhishingWarning(href, response);
        }
      }
    );
  },
  true
);

function showPhishingWarning(url, result) {
  // Remove existing warning if any
  const existing = document.getElementById("phishing-warning-overlay");
  if (existing) existing.remove();

  const overlay = document.createElement("div");
  overlay.id = "phishing-warning-overlay";
  overlay.innerHTML = `
    <div style="
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.7);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 999999;
      font-family: Arial, sans-serif;
    ">
      <div style="
        background: white;
        border-radius: 12px;
        padding: 30px;
        max-width: 500px;
        box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
      ">
        <h2 style="color: #d32f2f; margin: 0 0 15px 0; display: flex; align-items: center; gap: 10px; font-size: 24px;">
          ⚠️ PHISHING WARNING
        </h2>
        <p style="color: #333; margin: 0 0 10px 0; font-size: 14px; line-height: 1.6;">
          This URL appears to be <strong style="color: #d32f2f;">${
            result.riskLevel
          }</strong> risk and may be a <strong>phishing attempt</strong>.
        </p>
        <p style="color: #666; margin: 0 0 15px 0; font-size: 12px; word-break: break-all; background: #f5f5f5; padding: 10px; border-radius: 4px; border-left: 4px solid #d32f2f;">
          <strong>URL:</strong><br>${url}
        </p>
        <div style="background: #fff3e0; padding: 12px; border-radius: 6px; margin-bottom: 15px; font-size: 12px; border-left: 4px solid #f57c00;">
          <strong>🔍 Risk Indicators:</strong>
          <ul style="margin: 8px 0 0 20px; padding: 0; color: #d32f2f;">
            ${
              result.indicators && result.indicators.length > 0
                ? result.indicators.map((ind) => `<li>${ind}</li>`).join("")
                : "<li>Multiple phishing patterns detected</li>"
            }
          </ul>
        </div>
        <p style="color: #666; margin: 0 0 15px 0; font-size: 12px;">
          <strong>Confidence:</strong> ${result.confidence}%
        </p>
        <div style="display: flex; gap: 10px;">
          <button onclick="document.getElementById('phishing-warning-overlay').remove();" style="
            flex: 1;
            padding: 12px;
            background: #4CAF50;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: bold;
            font-size: 14px;
          ">← Go Back (Safe)</button>
          <button onclick="window.location.href = '${url}';" style="
            flex: 1;
            padding: 12px;
            background: #f44336;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: bold;
            font-size: 14px;
          ">Continue Anyway (⚠️ Risk)</button>
        </div>
      </div>
    </div>
  `;

  document.body.appendChild(overlay);
}
