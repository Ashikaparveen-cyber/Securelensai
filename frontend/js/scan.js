/* ── Scan Execution Handler ── */

document.addEventListener("DOMContentLoaded", () => {
  const scanInput = document.getElementById("scan-url-input");
  const btnScan = document.getElementById("btn-run-scan");
  const spinner = document.getElementById("scan-spinner");

  if (!btnScan || !scanInput) return;

  async function triggerScan() {
    const url = scanInput.value.trim();
    if (!url) {
      alert("Please enter a valid target URL.");
      return;
    }

    btnScan.disabled = true;
    spinner.style.display = "inline-block";
    btnScan.querySelector("span").innerText = "Scanning...";

    try {
      const response = await fetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({ url: url, include_ai: true }),
      });

      if (response.ok) {
        const scanResult = await response.json();
        currentScanId = scanResult.scan_id;
        displayScanResult(scanResult);
        await loadScanHistory();
        loadChatHistory(currentScanId);
      } else {
        const err = await response.json();
        alert(`Scan failed: ${err.detail || "Server error"}`);
      }
    } catch (err) {
      console.error("Scan execution error:", err);
      alert("Could not complete scan. Please verify backend server connectivity on https://securelensai-backend.onrender.com.");
    } finally {
      btnScan.disabled = false;
      spinner.style.display = "none";
      btnScan.querySelector("span").innerText = "Run Scan →";
    }
  }

  btnScan.addEventListener("click", triggerScan);

  scanInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") {
      triggerScan();
    }
  });
});
