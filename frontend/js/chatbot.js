/* ── AI Security Analyst Chatbot Handler ── */

async function loadChatHistory(scanId) {
  const container = document.getElementById("chat-messages-container");
  if (!container) return;

  if (!scanId) {
    container.innerHTML = `
      <div class="chat-bubble ai">
        Hello Operator. Select a past scan or enter a URL above to inspect findings and chat with the AI Analyst.
      </div>
    `;
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/chat/${scanId}`, {
      headers: getAuthHeaders(),
    });

    if (!res.ok) return;

    const messages = await res.json();
    if (messages.length === 0) {
      container.innerHTML = `
        <div class="chat-bubble ai">
          Audit complete! Ask me any questions about SSL, HTTP headers, DNS records, or remediation steps for this target.
        </div>
      `;
      return;
    }

    container.innerHTML = messages.map(m => `
      <div class="chat-bubble ${m.sender === 'user' ? 'user' : 'ai'}">
        ${escapeHtml(m.text)}
      </div>
    `).join("");

    scrollToBottom();

  } catch (err) {
    console.error("Chat history fetch error:", err);
  }
}

function appendChatMessage(sender, text) {
  const container = document.getElementById("chat-messages-container");
  if (!container) return;

  const bubble = document.createElement("div");
  bubble.className = `chat-bubble ${sender === "user" ? "user" : "ai"}`;
  bubble.innerText = text;
  container.appendChild(bubble);
  scrollToBottom();
  return bubble;
}

function scrollToBottom() {
  const container = document.getElementById("chat-messages-container");
  if (container) {
    container.scrollTop = container.scrollHeight;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const chatForm = document.getElementById("chat-form");
  const chatInput = document.getElementById("chat-input-text");
  const btnSend = document.getElementById("btn-chat-send");

  if (!chatForm || !chatInput) return;

  chatForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const text = chatInput.value.trim();
    if (!text) return;

    if (!currentScanId) {
      alert("Please run a scan or select a scan from history first to provide context for the AI Analyst.");
      return;
    }

    appendChatMessage("user", text);
    chatInput.value = "";
    btnSend.disabled = true;

    const typingBubble = appendChatMessage("ai", "Thinking...");

    try {
      const response = await fetch(`${API_BASE}/chat`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({ scan_id: currentScanId, message: text }),
      });

      if (response.ok) {
        const data = await response.json();
        typingBubble.innerText = data.ai_response.text;
      } else {
        typingBubble.innerText = "[AI Error] Could not process request.";
      }
    } catch (err) {
      console.error("Chat submission error:", err);
      typingBubble.innerText = "[Connection Error] Network error reaching AI Analyst.";
    } finally {
      btnSend.disabled = false;
      scrollToBottom();
    }
  });
});
