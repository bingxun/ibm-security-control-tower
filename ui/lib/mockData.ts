import { AgentStep, CveRecord, RunStats } from "./types";

export const MOCK_CVES: CveRecord[] = [
  {
    id: "CVE-2024-3094",
    severity: "critical",
    pkg: "xz-utils",
    version: "5.6.0",
    fixedIn: "5.6.1",
    cvss: 10.0,
    vector: "Network",
    authRequired: "None",
    impact: "RCE — backdoor in build system",
    description:
      "Malicious code was found in xz-utils 5.6.0 and 5.6.1 which, under certain conditions, could allow an attacker to break sshd authentication and gain unauthorized access to the system remotely.",
    rationale:
      "Exposure is contained within CLOUD-247 by network egress restrictions preventing external SSH access, and the affected image has been rebuilt against xz-utils 5.4.6. Patch to 5.6.1 is not recommended due to ongoing upstream investigation — pinning to 5.4.6 is the accepted remediation.",
    ragMatch: {
      pct: 89,
      project: "CLOUD-233",
      approver: "S. Patel",
      date: "2024-04-01",
      summary: "Rebuild to 5.4.6 accepted with egress restriction confirmation.",
    },
    status: "approved",
  },
  {
    id: "CVE-2024-0553",
    severity: "high",
    pkg: "gnutls",
    version: "3.7.9",
    fixedIn: "3.8.3",
    cvss: 7.5,
    vector: "Network",
    authRequired: "None",
    impact: "Info disclosure via session resumption",
    description:
      "A vulnerability in GnuTLS allows a server-side timing side-channel attack during RSA-PSK key exchange, allowing a remote attacker to retrieve plaintext.",
    rationale:
      "IBM CIS TLS inspection proxy sits upstream and terminates all TLS before traffic reaches the affected container, preventing exploitation. GnuTLS patched to 3.8.3 is scheduled for Sprint 38.",
    ragMatch: {
      pct: 87,
      project: "CLOUD-199",
      approver: "M. Lim",
      date: "2024-01-08",
      summary: "TLS inspection proxy confirmed upstream — accepted with patch schedule.",
    },
    status: "approved",
  },
  {
    id: "CVE-2023-44487",
    severity: "high",
    pkg: "nghttp2",
    version: "1.52.0",
    fixedIn: "1.57.0",
    cvss: 7.5,
    vector: "Network",
    authRequired: "None",
    impact: "DoS — HTTP/2 RST flood",
    description:
      "HTTP/2 Rapid Reset Attack. An attacker can send a stream of RST_STREAM frames causing unbounded CPU consumption on the server, leading to denial of service.",
    rationale:
      "This vulnerability is mitigated within CLOUD-247 by two existing controls: WAF rate-limiting rules cap inbound HTTP/2 connections to 1,000 req/s per source IP, and the IBM CIS DDoS proxy terminates HTTP/2 streams before they reach nghttp2, eliminating the RST flood amplification path. A patch to nghttp2 1.57.0 is scheduled for Sprint 38 (ticket PROJ-4821). Residual risk is assessed as LOW.",
    ragMatch: {
      pct: 92,
      project: "CLOUD-199",
      approver: "J. Tan",
      date: "2024-03-12",
      summary: "WAF rate-limit + CIS proxy accepted. Same controls verified active here.",
    },
    status: "pending",
  },
  {
    id: "CVE-2024-2961",
    severity: "high",
    pkg: "glibc",
    version: "2.35",
    fixedIn: "2.39",
    cvss: 8.8,
    vector: "Local",
    authRequired: "Low",
    impact: "Heap buffer overflow in iconv",
    description:
      "A buffer overflow in the iconv() function in glibc can be exploited to achieve code execution on systems that use PHP's iconv filter.",
    rationale: "",
    status: "queued",
  },
  {
    id: "CVE-2023-52425",
    severity: "medium",
    pkg: "libexpat",
    version: "2.5.0",
    fixedIn: "2.6.0",
    cvss: 5.5,
    vector: "Local",
    authRequired: "None",
    impact: "DoS via large token parsing",
    description:
      "libexpat before 2.6.0 allows a denial of service (resource consumption) because many full reparsings are needed in the case of a large token for which multiple buffer fills are needed.",
    rationale: "",
    status: "queued",
  },
  {
    id: "CVE-2023-4911",
    severity: "critical",
    pkg: "glibc",
    version: "2.35",
    fixedIn: "2.38",
    cvss: 9.8,
    vector: "Local",
    authRequired: "None",
    impact: "Privilege escalation via ld.so",
    description:
      "A buffer overflow in the GNU C Library's dynamic loader ld.so when processing the GLIBC_TUNABLES environment variable could allow a local attacker to gain root privileges.",
    rationale: "",
    status: "queued",
  },
  {
    id: "CVE-2024-1086",
    severity: "critical",
    pkg: "linux-kernel",
    version: "6.1.0",
    fixedIn: "6.1.76",
    cvss: 9.8,
    vector: "Local",
    authRequired: "None",
    impact: "Use-after-free in netfilter",
    description:
      "A use-after-free vulnerability in the Linux kernel's netfilter nf_tables component can be exploited by a local attacker to achieve privilege escalation to root.",
    rationale: "",
    status: "rejected",
  },
  {
    id: "CVE-2024-28182",
    severity: "medium",
    pkg: "nghttp2",
    version: "1.52.0",
    fixedIn: "1.61.0",
    cvss: 5.3,
    vector: "Network",
    authRequired: "None",
    impact: "DoS via CONTINUATION frames",
    description:
      "nghttp2 library is vulnerable to denial of service due to insufficient limitation of the number of CONTINUATION frames in an HTTP/2 HEADERS frame.",
    rationale: "",
    status: "queued",
  },
];

export const MOCK_AGENT_STEPS: AgentStep[] = [
  {
    id: "ingest",
    title: "Parsed CVE from Trivy scan",
    desc: "nghttp2 1.52.0 · CVSS 7.5 · Network vector · DoS impact",
    chips: [{ label: "parse_trivy_json", variant: "done" }],
    state: "done",
  },
  {
    id: "rag",
    title: "Found 2 prior decisions in memory",
    desc: "CLOUD-199 accepted this CVE (92% match). CLOUD-188 accepted a related HTTP/2 DoS (74%).",
    chips: [
      { label: "◈ query_memory", variant: "rag" },
      { label: "2 hits", variant: "done" },
    ],
    state: "done",
  },
  {
    id: "context",
    title: "Verified controls in CLOUD-247 config",
    desc: "WAF rate-limit rule active. IBM CIS proxy confirmed upstream of affected container.",
    chips: [
      { label: "get_cloud_config", variant: "tool" },
      { label: "search_cis_policy", variant: "tool" },
    ],
    state: "done",
  },
  {
    id: "draft",
    title: "Drafting rationale with Granite",
    desc: "Streaming response — grounded against verified controls and memory match.",
    chips: [
      { label: "granite_generate", variant: "llm" },
      { label: "streaming…", variant: "stream" },
    ],
    state: "active",
  },
];

export const MOCK_STATS: RunStats = {
  total: 8,
  approved: 2,
  rejected: 1,
  avgSynthesisS: 18,
  ragHits: 2,
  tokensUsed: 4820,
};
