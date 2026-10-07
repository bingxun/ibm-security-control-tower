const HTML_ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

const escapeHtml = (value) =>
  String(value ?? "").replace(/[&<>"']/g, (ch) => HTML_ESCAPES[ch]);

const triggerDownload = (blob, filename) => {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
};

const setLoading = (isLoading, statusText = "") => {
  document.getElementById("submit-btn").disabled = isLoading;
  document.getElementById("spinner").classList.toggle("visible", isLoading);
  document.getElementById("status-text").textContent = isLoading
    ? statusText || "Analyzing..."
    : "";
};

const showError = (message) => {
  const banner = document.getElementById("error-banner");
  banner.textContent = message;
  banner.classList.remove("hidden");
};

const clearError = () => {
  const banner = document.getElementById("error-banner");
  banner.textContent = "";
  banner.classList.add("hidden");
};
