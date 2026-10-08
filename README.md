# Backend — Agentic Cloud Security Control Tower

## Quick start (local dev)

```bash
# 1. Create venv with Python 3.11 (recommended) or 3.13
python3.11 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure credentials
cp .env.example .env
# Edit .env — set WATSONX_API_KEY

# 4. Start the API server
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

API is now live at **http://localhost:8000**  
Interactive docs: **http://localhost:8000/docs**

---

## Run with Docker Compose (API + UI together)

```bash
cp .env.example .env        # fill in WATSONX_API_KEY
docker compose up --build
```

- UI  → http://localhost:3000
- API → http://localhost:8000

---

## API routes

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/health` | Health check + RAG decision count |
| `POST` | `/scan` | Start a new agent run |
| `GET`  | `/run/{id}` | Poll run state |
| `GET`  | `/run/{id}/stream` | SSE stream of live events |
| `POST` | `/run/{id}/decision` | Submit Accept/Reject decision |
| `GET`  | `/scans` | List all past scans (dashboard) |
| `GET`  | `/stats` | Aggregate stats (dashboard) |

### POST /scan

```json
{
  "imageRef": "docker.io/myorg/api-gateway:2.4.1",
  "projectId": "CLOUD-247",
  "cisProfile": "CIS Docker Benchmark v1.6",
  "severityThreshold": "high",
  "scanner": "trivy",
  "autoApproveBelow": "none",
  "trivyJson": null
}
```

Omit `trivyJson` to use the built-in 5-CVE demo dataset.

### POST /run/{id}/decision

```json
{
  "cve_id": "CVE-2024-3094",
  "decision": "approved",
  "edited_rationale": "Optional edited text..."
}
```

---

## MCP server (for Claude Desktop / other agents)

```bash
# Run as stdio MCP server
python -m mcp_server.server
```

### Register in Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "control-tower": {
      "command": "/path/to/.venv/bin/python",
      "args": ["-m", "mcp_server.server"],
      "cwd": "/path/to/realhack"
    }
  }
}
```

Tools exposed: `query_memory_tool`, `persist_decision_tool`, `memory_stats_tool`

---

## Architecture

```
UI (Next.js)
    │  POST /scan
    ▼
FastAPI ──► LangGraph pipeline
              │
              ├─ Node 1: ingest      — parse Trivy JSON
              ├─ Node 2: synthesis   — RAG query + Granite generate
              ├─ Node 3: approval    — interrupt() → wait for human
              └─ Node 4: persist     — embed + store to JSON RAG store
                              │
                    SSE stream back to UI
                    (cves, agent_steps, token_fragment)
```

---

## Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `WATSONX_API_KEY` | IBM Cloud API key | **required** |
| `WATSONX_PROJECT_ID` | watsonx.ai project GUID | `58098c39-...` |
| `WATSONX_URL` | watsonx.ai regional endpoint | `https://jp-tok.ml.cloud.ibm.com` |
| `MILVUS_DB_PATH` | Path to RAG JSON store file | `./data/rag_memory.json` |
| `API_HOST` | Bind host | `0.0.0.0` |
| `API_PORT` | Bind port | `8000` |

### Project access

- **Super Admin** creates projects, manages accounts and assignments, and sees all projects.
- **Admin** scans and reviews only assigned projects.
- **DevOps Engineer** scans only assigned projects; cannot approve findings or enable auto-approval.
- **Cyber Manager** reviews only assigned projects; cannot launch scans.
- Accounts with no assignments see no project data. Membership is checked by the API for lists,
  statistics, scan creation, run details, decisions, and streams, not just by the UI.

On first startup with this version, the existing active `admin@controltower.local` admin is
promoted to Super Admin. Set `SUPER_ADMIN_EMAIL` before startup to use another existing admin.
The migration runs once; it does not reset passwords or promote accounts on subsequent starts.
A fresh installation seeds the default account as Super Admin.

Existing scan project IDs are imported into Projects without automatically assigning users.
Sign in as Super Admin, open **Settings → Projects**, create projects as needed, choose
**Assign users**, and save assignments. Create accounts in **Users & Roles** first.
New Scan only offers accessible projects; the dashboard can filter accessible projects.

RAG lookup is restricted to the current project. Historical generated rationale and logs may
contain cross-project context, so pre-migration generated content is visible only to Super Admin.
Raw historical findings remain available to assigned users; run a new scan for isolated analysis.
MCP memory tools require a valid `session_token` and project access; they no longer provide
unauthenticated global memory access.

Validation:

```bash
.venv/bin/python -m unittest discover -s tests -v
# Start an isolated backend for browser checks (do not use the real database):
DB_PATH=/tmp/project-check.db MILVUS_DB_PATH=/tmp/project-rag-check.json .venv/bin/uvicorn api.main:app --port 18001
# With the UI running on localhost:3000:
cd ui
PROJECTS_TEST_API=http://127.0.0.1:18001 node scripts/check-projects.mjs
```
