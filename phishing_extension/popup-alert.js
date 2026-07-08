console.log("✅ popup-alert.js loaded");

document.addEventListener("DOMContentLoaded", () => {
  console.log("📋 Popup alert DOM loaded");

  const params = new URLSearchParams(window.location.search);
  const dataStr = params.get("data");
  console.log("📊 Raw data string:", dataStr);

  let data = {};
  try {
    if (dataStr) {
      data = JSON.parse(decodeURIComponent(dataStr));
    }
  } catch (e) {
    console.error("Error parsing data:", e);
    data = {
      url: "Unknown",
      isPhishing: false,
      confidence: 0,
      riskLevel: "ERROR",
      indicators: ["Error parsing analysis data"],
    };
  }

  console.log("📊 Analysis data:", data);

  displayAlert(data);
  setupButtons(data);

  // OPTIONAL: remove auto-close for safe URLs
  // If you still want auto-close for clearly safe URLs, uncomment:
  /*
  if (!data.isPhishing && data.confidence < 25) {
    console.log("⏰ Auto-closing safe URL in 5 seconds");
    setTimeout(() => {
      window.close();
    }, 5000);
  }
  */
});

function setupButtons(data) {
  const closeBtn = document.querySelector(".btn-close");
  const proceedBtn = document.getElementById("proceedBtn");

  // Close & Go Back: go back in history (user cancels visiting)
  if (closeBtn) {
    closeBtn.addEventListener("click", () => {
      console.log("🔴 Close & Go Back clicked");
      window.history.back();
    });
  }

  // Proceed Anyway: open the original (possibly risky) URL
  if (proceedBtn) {
    proceedBtn.addEventListener("click", () => {
      console.log("✅ Proceed Anyway clicked");
      if (data && data.url) {
        window.location.href = data.url;
      } else {
        window.history.back();
      }
    });
  }
}

function displayAlert(data) {
  if (!data || typeof data !== "object") {
    data = {
      url: "Unknown",
      isPhishing: false,
      confidence: 0,
      riskLevel: "ERROR",
      indicators: ["No data received"],
    };
  }

  const alertHeader = document.getElementById("alertHeader");
  const headerTitle = document.getElementById("headerTitle");
  const headerSubtitle = document.getElementById("headerSubtitle");
  const verdictBox = document.getElementById("verdictBox");

  const confidence = data.confidence || 0;
  const isPhishing = data.isPhishing || false;

  // Verdict and risk display (kept from your original logic)
  let verdictColor = "safe";
  let verdictTitle = "✅ SAFE & LEGITIMATE";
  let verdictSubtitle = "This URL appears to be legitimate";
  let verdictMessage = "✅ SAFE - No threats detected";
  let showProceed = false;

  if (confidence >= 75 && isPhishing) {
    verdictColor = "phishing";
    verdictTitle = "🛑 CRITICAL - PHISHING ALERT!";
    verdictSubtitle =
      "DO NOT interact with this URL - It is DEFINITELY malicious";
    verdictMessage = "🛑 CRITICAL PHISHING DETECTED";
    showProceed = true;
  } else if (confidence >= 60 && isPhishing) {
    verdictColor = "phishing";
    verdictTitle = "❌ PHISHING DETECTED";
    verdictSubtitle = "This URL is likely a phishing attempt";
    verdictMessage = "❌ PHISHING - HIGH THREAT";
    showProceed = true;
  } else if (confidence >= 45 && isPhishing) {
    verdictColor = "medium";
    verdictTitle = "⚠️ SUSPICIOUS URL";
    verdictSubtitle = "This URL has multiple phishing characteristics";
    verdictMessage = "⚠️ SUSPICIOUS - HIGH RISK";
    showProceed = true;
  } else if (confidence >= 25) {
    verdictColor = "medium";
    verdictTitle = "🟡 WARNING - MINOR RISKS";
    verdictSubtitle = "This URL has some unusual patterns";
    verdictMessage = "🟡 LOW-MEDIUM RISK";
    showProceed = true;
  } else {
    verdictColor = "safe";
    verdictTitle = "✅ SAFE & LEGITIMATE";
    verdictSubtitle = "This URL appears to be legitimate";
    verdictMessage = "✅ SAFE - No threats detected";
    showProceed = false;
  }

  if (alertHeader) alertHeader.className = `alert-header ${verdictColor}`;
  if (headerTitle) headerTitle.textContent = verdictTitle;
  if (headerSubtitle) headerSubtitle.textContent = verdictSubtitle;
  if (verdictBox) {
    verdictBox.className = `verdict-box ${verdictColor}`;
    verdictBox.textContent = verdictMessage;
  }

  const proceedBtn = document.getElementById("proceedBtn");
  if (proceedBtn) proceedBtn.style.display = showProceed ? "block" : "none";

  // URL display
  const urlDisplay = document.getElementById("urlDisplay");
  if (urlDisplay) {
    urlDisplay.textContent = data.url || "Unknown URL";
  }

  // Confidence bar
  const confidenceFill = document.getElementById("confidenceFill");
  if (confidenceFill) {
    const width = Math.min(confidence, 100);
    confidenceFill.style.width = width + "%";
    confidenceFill.textContent = width + "%";

    if (width >= 70) {
      confidenceFill.style.background =
        "linear-gradient(90deg, #FF0000, #CC0000)";
    } else if (width >= 45) {
      confidenceFill.style.background =
        "linear-gradient(90deg, #FFA500, #FF6600)";
    } else if (width >= 25) {
      confidenceFill.style.background =
        "linear-gradient(90deg, #FFD700, #FFA500)";
    } else {
      confidenceFill.style.background =
        "linear-gradient(90deg, #00AA00, #006600)";
    }
  }

  // Risk level
  const riskLevel = document.getElementById("riskLevel");
  if (riskLevel) {
    riskLevel.textContent = data.riskLevel || "UNKNOWN";
    riskLevel.style.color = getRiskColor(data.riskLevel);
    riskLevel.style.fontWeight = "bold";
  }

  // Threat count
  const threatsCount = document.getElementById("threatsCount");
  if (threatsCount) {
    threatsCount.textContent = (data.indicators || []).length;
  }

  // Assessment text
  const assessmentBox = document.getElementById("assessmentBox");
  if (assessmentBox) {
    assessmentBox.textContent = getDetailedAssessment(data);
    assessmentBox.style.fontWeight = "500";
  }

  // Indicators list
  const indicatorsList = document.getElementById("indicatorsList");
  if (indicatorsList) {
    const indicators = data.indicators || ["✓ No issues detected"];
    indicatorsList.innerHTML = indicators
      .map((indicator) => {
        let className = "safe";
        let icon = "✅";
        if (indicator.includes("❌")) {
          className = "critical";
          icon = "❌";
        } else if (indicator.includes("⚠️")) {
          className = "warning";
          icon = "⚠️";
        } else if (indicator.includes("✓")) {
          className = "safe";
          icon = "✓";
        }

        const text = indicator.replace(/^[❌⚠️✓]\s*/, "");
        return `
          <li class="indicator-item ${className}">
            <span class="indicator-icon">${icon}</span>
            <span>${text}</span>
          </li>
        `;
      })
      .join("");
  }
}

function getRiskColor(riskLevel) {
  const level = (riskLevel || "").toUpperCase();
  if (level === "CRITICAL" || level === "HIGH") return "#CC0000";
  if (level === "MEDIUM") return "#E65100";
  if (level === "LOW") return "#2E7D32";
  return "#333333";
}

function getDetailedAssessment(data) {
  const risk = (data.riskLevel || "UNKNOWN").toUpperCase();
  const confidence = data.confidence || 0;

  if (risk === "CRITICAL" || risk === "HIGH") {
    return `Phishentia detected a high-risk phishing URL with confidence ${confidence}%. Multiple strong indicators of fraud are present, such as suspicious hosting, path structure, and keyword patterns.`;
  }
  if (risk === "MEDIUM") {
    return `Phishentia found several moderate-risk indicators with confidence ${confidence}%. This URL may be part of a phishing or scam campaign; only continue if you fully trust the source.`;
  }
  if (risk === "LOW") {
    return `No major phishing signals were found, but Phishentia still recommends caution when entering passwords, card details, or other sensitive information.`;
  }
  if (risk === "ERROR") {
    return "The analysis service encountered an error while evaluating this URL. Please try again or verify the site using another trusted security tool.";
  }
  return "The risk for this URL could not be clearly determined. When in doubt, avoid entering any sensitive information and verify the link through an official channel.";
}
