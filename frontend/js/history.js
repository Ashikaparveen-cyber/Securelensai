/* ── Scan History Sidebar Manager ── */

let currentScanId = null;

async function loadScanHistory() {
  const container = document.getElementById("history-container");
  if (!container) return;

  try {
    const res = await fetch(`${API_BASE}/scan/history`, {
      headers: getAuthHeaders(),
    });

    if (!res.ok) {
      container.innerHTML = `<div style="padding: 16px; color: var(--sev-critical); font-size: 12px;">Failed to load history</div>`;
      return;
    }

    const scans = await res.json();
    if (scans.length === 0) {
      container.innerHTML = `<div style="padding: 20px; text-align: center; color: var(--text-dim); font-size: 13px;">No past scans found</div>`;
      return;
    }

    container.innerHTML = scans.map(s => {
      const activeClass = s.scan_id === currentScanId ? "active" : "";
      const dateStr = s.timestamp ? new Date(s.timestamp).toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : "Recent";
      const score = s.risk_score ?? 0;

      let badgeColor = "var(--sev-low)";
      if (score < 40) badgeColor = "var(--sev-critical)";
      else if (score < 60) badgeColor = "var(--sev-high)";
      else if (score < 80) badgeColor = "var(--sev-medium)";

      return `
        <div class="history-item ${activeClass}" onclick="selectHistoryScan('${s.scan_id}')">
          <span class="history-url">${escapeHtml(s.url || 'Target Website')}</span>
          <div class="history-meta">
            <span>${dateStr}</span>
            <span class="history-badge" style="background: rgba(255,255,255,0.05); color: ${badgeColor}; border: 1px solid ${badgeColor};">
              ${score}% SCORE
            </span>
          </div>
        </div>
      `;
    }).join("");

  } catch (err) {
    console.error("History fetch error:", err);
  }
}

async function selectHistoryScan(scanId) {
  if (!scanId) return;
  currentScanId = scanId;

  try {
    const res = await fetch(`${API_BASE}/scan/${scanId}`, {
      headers: getAuthHeaders(),
    });

    if (!res.ok) return;

    const data = await res.json();
    displayScanResult(data);
    loadScanHistory();
    loadChatHistory(scanId);

  } catch (err) {
    console.error("Error loading scan details:", err);
  }
}

function displayScanResult(scanData) {
  if (!scanData) return;

  const url = scanData.url || "";
  const hostname = scanData.hostname || url;
  const risk = scanData.risk || {};

  document.getElementById("target-hostname-display").innerText = hostname;
  
  renderRiskGauge(risk.overall_score, risk.risk_level, risk.risk_color);
  renderStatCounters(risk.finding_counts);
  renderVulnerabilitiesTable(risk.all_findings, hostname);
  renderAiSummary(scanData.ai_analysis);

  const btnPdf = document.getElementById("btn-export-pdf");
  if (btnPdf) {
    btnPdf.style.display = "inline-flex";
    btnPdf.onclick = () => {
      window.open(`${API_BASE}/reports/${scanData.scan_id}/pdf`, "_blank");
    };
  }
}

document.addEventListener("DOMContentLoaded", () => {
  if (window.location.pathname.includes("dashboard")) {
    loadScanHistory();
  }
});
