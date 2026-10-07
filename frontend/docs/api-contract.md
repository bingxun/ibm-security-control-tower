# API Contract — Scan Analysis Endpoint

Analyzes an uploaded Trivy container-image vulnerability scan (exported to
Excel/CSV) alongside free-text architecture context, and returns the same
row data with two additional columns: `justification` and `remediation`.

## POST /api/scan/analyze

### Request

- Method: `POST`
- Content-Type: `multipart/form-data`

| Field                 | Type   | Required | Notes                                                                      |
|-----------------------|--------|----------|-----------------------------------------------------------------------------|
| `file`                | binary | yes      | The Trivy report. Accepted extensions: `.xlsx`, `.xls`, `.csv`. Max 10 MB. |
| `architectureContext` | text   | no       | Free-text description of the architecture/infra setup. May be empty.      |

Example:

```bash
curl -X POST https://<host>/api/scan/analyze \
  -F "file=@trivy-report.xlsx" \
  -F "architectureContext=Single-region EKS cluster, no WAF, public ALB..."
```

### Success response — 200 OK

- `Content-Type: text/csv; charset=utf-8`
- `Content-Disposition: attachment; filename="<original-name>-remediated.csv"`
- Body: raw CSV bytes, regardless of the input format (xlsx/xls/csv all
  produce a CSV response — one response code path). Columns = every column
  from the uploaded report, in the same order, **plus two appended
  columns**: `justification`, `remediation`. Row order and row count must
  match the input 1:1 (one output row per input vulnerability row).

Example body (truncated):

```csv
Target,Vulnerability ID,Severity,Package,Installed Version,Fixed Version,justification,remediation
my-image:latest,CVE-2023-1234,HIGH,openssl,1.1.1,1.1.1t,"Not exploitable: outbound TLS only, no attacker-controlled input reaches this path","Upgrade openssl to 1.1.1t via base image bump"
```

### Error responses

- `Content-Type: application/json`
- Shape:

```json
{
  "error": {
    "code": "INVALID_FILE_TYPE",
    "message": "Human-readable description safe to show in the UI"
  }
}
```

| HTTP status | code                 | Meaning                                        |
|-------------|----------------------|-------------------------------------------------|
| 400         | `MISSING_FILE`       | `file` field absent                             |
| 400         | `INVALID_FILE_TYPE`  | Extension/content not a supported spreadsheet   |
| 413         | `FILE_TOO_LARGE`     | Exceeds 10 MB                                   |
| 422         | `PARSE_FAILED`       | File could not be read as a Trivy report        |
| 502         | `ANALYSIS_FAILED`    | Downstream AI/analysis step failed              |
| 500         | `INTERNAL_ERROR`     | Unhandled server error                          |

### Operational notes

- Processing may be slow (AI step); the frontend applies a 120s client
  timeout (`js/api.js`). If the backend needs longer, raise this on both
  sides.
- CORS: if frontend and backend are served from different origins/ports
  during development, the backend must send `Access-Control-Allow-Origin`
  for the frontend's dev origin.
