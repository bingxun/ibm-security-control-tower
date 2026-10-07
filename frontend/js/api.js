const MOCK_MODE = true;

const extractFilename = (contentDisposition) => {
  if (!contentDisposition) return null;
  const match = /filename="?([^";]+)"?/i.exec(contentDisposition);
  return match ? match[1] : null;
};

const analyzeScan = async (file, architectureContext) => {
  if (MOCK_MODE) return mockAnalyze(file, architectureContext);

  const form = new FormData();
  form.append("file", file);
  form.append("architectureContext", architectureContext);

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 120000);

  let res;
  try {
    res = await fetch("/api/scan/analyze", {
      method: "POST",
      body: form,
      signal: controller.signal,
    });
  } catch (err) {
    throw new Error("Network error reaching the server. Please try again.");
  } finally {
    clearTimeout(timeoutId);
  }

  if (!res.ok) {
    const body = await res.json().catch(() => null);
    throw new Error(body?.error?.message || `Request failed (${res.status})`);
  }

  const blob = await res.blob();
  const filename = extractFilename(res.headers.get("Content-Disposition")) || "scan-results.csv";
  return { blob, filename };
};
