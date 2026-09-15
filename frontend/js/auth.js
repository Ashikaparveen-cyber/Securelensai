/* ── SecureLens AI Auth Management ── */

const API_BASE = (window.location.protocol === "file:" || !window.location.host) ? "http://127.0.0.1:8000" : "";
const TOKEN_KEY = "securelens_token";
const OPERATOR_KEY = "securelens_operator";

function getAuthToken() {
  return localStorage.getItem(TOKEN_KEY);
}

function getOperatorId() {
  return localStorage.getItem(OPERATOR_KEY) || "operator";
}

function getAuthHeaders() {
  const token = getAuthToken();
  const headers = { "Content-Type": "application/json" };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

function logout() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(OPERATOR_KEY);
  window.location.href = "index.html";
}

document.addEventListener("DOMContentLoaded", () => {
  const isLoginPage = window.location.pathname.endsWith("index.html") || window.location.pathname === "/" || window.location.pathname.endsWith("/");
  const token = getAuthToken();

  if (!isLoginPage && !token) {
    window.location.href = "index.html";
    return;
  }

  if (isLoginPage && token) {
    window.location.href = "dashboard.html";
    return;
  }

  const userDisplay = document.getElementById("user-id-display");
  const avatarDisplay = document.getElementById("user-avatar");
  if (userDisplay && avatarDisplay) {
    const op = getOperatorId();
    userDisplay.innerText = op;
    avatarDisplay.innerText = op.substring(0, 2).toUpperCase();
  }

  const btnLogout = document.getElementById("btn-logout");
  if (btnLogout) {
    btnLogout.addEventListener("click", logout);
  }

  const loginForm = document.getElementById("login-form");
  if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const operatorId = document.getElementById("operator-id").value.trim();
      const passphrase = document.getElementById("passphrase").value.trim();
      const alertBox = document.getElementById("login-alert");
      const btnSubmit = document.getElementById("btn-login-submit");
      const spinner = document.getElementById("login-spinner");

      alertBox.style.display = "none";
      btnSubmit.disabled = true;
      spinner.style.display = "inline-block";

      try {
        const response = await fetch(`${API_BASE}/auth/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ operator_id: operatorId, passphrase: passphrase }),
        });

        if (response.ok) {
          const data = await response.json();
          localStorage.setItem(TOKEN_KEY, data.access_token);
          localStorage.setItem(OPERATOR_KEY, data.operator_id);
          window.location.href = "dashboard.html";
        } else {
          alertBox.style.display = "block";
          alertBox.innerText = "Invalid Operator ID or Passphrase.";
        }
      } catch (err) {
        alertBox.style.display = "block";
        alertBox.innerText = "Connection failed. Please ensure the backend server is running on http://127.0.0.1:8000.";
      } finally {
        btnSubmit.disabled = false;
        spinner.style.display = "none";
      }
    });
  }
});
