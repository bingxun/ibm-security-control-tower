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
