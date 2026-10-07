# ibm-security-control-tower frontend

A static (HTML/CSS/JS only — no framework, no build step) single page for
uploading a Trivy vulnerability scan report plus free-text architecture
context, and viewing/downloading an AI-remediated version of it (same rows,
with `justification` and `remediation` columns added by the backend).

## Structure

- `index.html` — the single page: upload form (file input + architecture
  textarea + submit), error banner, result section (table + download
  button).
- `css/style.css` — shared stylesheet; light/dark via `prefers-color-scheme`,
  no JS theme toggle.
- `js/util.js` — `escapeHtml`, `triggerDownload`, `setLoading`,
  `showError`/`clearError`.
- `js/fileParse.js` — `parseWorkbookToRows(arrayBuffer)`, wraps SheetJS to
  turn a CSV/XLSX ArrayBuffer into `{ headers, rows }`.
- `js/mockApi.js` — `mockAnalyze()`: fabricates a plausible backend response
  client-side (reuses `fileParse.js`) so the full flow is demoable without a
  backend. Deliberately throws if the uploaded filename contains "error",
  to exercise the error UI path.
- `js/api.js` — `analyzeScan()`: single entry point for submitting a scan.
  `MOCK_MODE` flag at the top switches between the real `fetch` to
  `/api/scan/analyze` and `js/mockApi.js`. **Flip `MOCK_MODE = false` once
  the real backend endpoint exists.**
- `js/resultTable.js` — renders the result table and wires the download
  button to the raw response blob (never a client-regenerated CSV).
- `js/upload.js` — form validation, submit orchestration, loading/error
  states. Loaded last; references everything above via shared globals (no
  ES modules, no bundler — plain sequential `<script>` tags).
- `vendor/xlsx.full.min.js` — vendored SheetJS UMD standalone build
  (v1.15.0, Apache-2.0), downloaded once and committed rather than loaded
  from a live CDN at runtime.
- `docs/api-contract.md` — REST contract for the backend teammate
  (`POST /api/scan/analyze`).

## Data model notes

- The backend always responds with CSV (not XLSX), regardless of the
  uploaded file's format, so there's a single response-parsing code path.
- The response blob is downloaded byte-for-byte as the backend sent it; the
  on-screen table is parsed from that same blob via `fileParse.js`, never
  the other way around. If table rendering fails, the download button still
  works off the raw blob.
- `MOCK_MODE` in `js/api.js` is the only place that knows whether a real
  backend is being used.

## Running locally

Serve the folder over HTTP — `fetch()`/file reads will not work from a
`file://` URL. From this directory: `python -m http.server`, then open
`http://localhost:8000/`.
