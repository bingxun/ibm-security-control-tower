export type Severity = "critical" | "high" | "medium" | "low";
export type CveStatus = "approved" | "rejected" | "pending" | "queued";

export interface CveRecord {
  id: string;
  severity: Severity;
  pkg: string;
  version: string;
  fixedIn: string;
  cvss: number;
  vector: string;
  authRequired: string;
  impact: string;
  description: string;
  rationale: string;
  remediation: string;
  edited?: boolean;
  ragMatch?: {
    pct: number;
    project: string;
    approver: string;
    date: string;
    summary: string;
  };
  status: CveStatus;
}

export interface AgentStep {
  id: string;
  title: string;
  desc: string;
  chips: { label: string; variant: "rag" | "tool" | "llm" | "done" | "stream" }[];
  state: "done" | "active" | "waiting";
}

export interface RunStats {
  total: number;
  approved: number;
  rejected: number;
  avgSynthesisS: number;
  ragHits: number;
  tokensUsed: number;
}
