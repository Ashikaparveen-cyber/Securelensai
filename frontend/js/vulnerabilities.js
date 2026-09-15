/* ── Risk Gauge & Vulnerabilities Table Renderer ── */

function renderRiskGauge(score, level, color) {
  const scoreElem = document.getElementById("risk-score-value");
  const labelElem = document.getElementById("risk-level-label");
  const meterElem = document.getElementById("risk-gauge-meter");

  if (!scoreElem || !meterElem) return;

  const validScore = typeof score === "number" ? Math.max(0, Math.min(100, score)) : 0;
  scoreElem.innerText = validScore;
  labelElem.innerText = level || "UNKNOWN";

  // Calculate SVG stroke offset (Circumference of r=60 is 2 * PI * 60 ≈ 377)
  const maxDash = 377;
  const offset = maxDash - (validScore / 100) * maxDash;
  meterElem.style.strokeDashoffset = offset;

  // Set color according to level
  if (validScore >= 80) {
    meterElem.style.stroke = "var(--sev-low)";
    labelElem.style.color = "var(--sev-low)";
  } else if (validScore >= 60) {
    meterElem.style.stroke = "var(--sev-medium)";
    labelElem.style.color = "var(--sev-medium)";
  } else if (validScore >= 40) {
    meterElem.style.stroke = "var(--sev-high)";
    labelElem.style.color = "var(--sev-high)";
  } else {
    meterElem.style.stroke = "var(--sev-critical)";
    labelElem.style.color = "var(--sev-critical)";
  }
}

function renderStatCounters(counts) {
  counts = counts || { critical: 0, high: 0, medium: 0, low: 0 };
  document.getElementById("count-critical").innerText = counts.critical || 0;
  document.getElementById("count-high").innerText = counts.high || 0;
  document.getElementById("count-medium").innerText = counts.medium || 0;
  document.getElementById("count-low").innerText = counts.low || 0;
}

function renderVulnerabilitiesTable(findings, hostname) {
  const tbody = document.getElementById("vuln-table-body");
  const countDisplay = document.getElementById("vuln-count-total");
  if (!tbody) return;

  findings = findings || [];
  countDisplay.innerText = `${findings.length} findings`;

  if (findings.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="4" style="text-align: center; color: var(--sev-low); padding: 30px;">
          ✓ No critical vulnerabilities detected on target asset.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = findings.map(f => {
    const sev = (f.severity || "info").toLowerCase();
    const name = f.name || f.msg || "Security Audit Finding";
    const asset = f.asset || hostname || "Target Asset";
    const status = f.status || "open";

    return `
      <tr>
        <td><span class="sev-badge ${sev}">${sev}</span></td>
        <td style="font-weight: 500;">${escapeHtml(name)}</td>
        <td style="font-family: var(--font-mono); font-size: 12px; color: var(--text-muted);">${escapeHtml(asset)}</td>
        <td>
          <span style="display: inline-flex; align-items: center; gap: 4px; font-size: 11px; font-weight: 600; color: ${status === 'fixed' ? 'var(--sev-low)' : 'var(--sev-high)'};">
            <span style="width: 6px; height: 6px; border-radius: 50%; background: currentColor;"></span>
            ${status.toUpperCase()}
          </span>
        </td>
      </tr>
    `;
  }).join("");
}

function renderAiSummary(summary) {
  const card = document.getElementById("ai-summary-card");
  const textElem = document.getElementById("ai-summary-text");
  if (!card || !textElem) return;

  if (summary && summary.trim()) {
    card.style.display = "flex";
    textElem.innerText = summary;
  } else {
    card.style.display = "none";
  }
}

function escapeHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
