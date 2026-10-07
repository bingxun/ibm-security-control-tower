"""
Seed the RAG store on Fly.io with historical CVE decisions.
Runs a complete scan + auto-approves all CVEs to build a rich memory store.

Usage:
    python scripts/seed_rag.py [--url https://ct-api-d7c679.fly.dev]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
import urllib.error

# ── CLI ────────────────────────────────────────────────────────────────────

parser = argparse.ArgumentParser()
parser.add_argument("--url", default="https://ct-api-d7c679.fly.dev")
args = parser.parse_args()
BASE = args.url.rstrip("/")

# ── Historical scan payloads ───────────────────────────────────────────────
# Each entry is a realistic historical scan from a different project.

SCANS = [
    {
        "imageRef": "icr.io/prod/payment-service:v2.1.4",
        "projectId": "CLOUD-101",
        "cisProfile": "CIS Docker Benchmark v1.6",
        "severityThreshold": "high",
        "scanner": "trivy",
        "autoApproveBelow": "none",
        "trivyJson": {
            "Results": [{
                "Target": "icr.io/prod/payment-service:v2.1.4",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2021-44228",
                        "PkgName": "log4j-core",
                        "InstalledVersion": "2.14.1",
                        "FixedVersion": "2.17.1",
                        "Severity": "CRITICAL",
                        "Title": "Log4Shell — RCE via JNDI lookup",
                        "Description": "Apache Log4j2 JNDI lookups allow unauthenticated remote code execution.",
                        "CVSS": {"nvd": {"V3Score": 10.0, "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}},
                    },
                    {
                        "VulnerabilityID": "CVE-2022-22965",
                        "PkgName": "spring-webmvc",
                        "InstalledVersion": "5.3.17",
                        "FixedVersion": "5.3.18",
                        "Severity": "CRITICAL",
                        "Title": "Spring4Shell — RCE via data binding",
                        "Description": "Spring MVC ClassPathXmlApplicationContext allows RCE via a crafted SpEL expression.",
                        "CVSS": {"nvd": {"V3Score": 9.8, "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
                    },
                    {
                        "VulnerabilityID": "CVE-2022-42889",
                        "PkgName": "commons-text",
                        "InstalledVersion": "1.9",
                        "FixedVersion": "1.10.0",
                        "Severity": "CRITICAL",
                        "Title": "Text4Shell — RCE in StringSubstitutor",
                        "Description": "Apache Commons Text performs variable interpolation allowing RCE via script expressions.",
                        "CVSS": {"nvd": {"V3Score": 9.8, "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
                    },
                ],
            }],
        },
    },
    {
        "imageRef": "icr.io/prod/auth-gateway:v3.0.2",
        "projectId": "CLOUD-158",
        "cisProfile": "CIS Kubernetes Benchmark v1.8",
        "severityThreshold": "high",
        "scanner": "trivy",
        "autoApproveBelow": "none",
        "trivyJson": {
            "Results": [{
                "Target": "icr.io/prod/auth-gateway:v3.0.2",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-25690",
                        "PkgName": "apache2",
                        "InstalledVersion": "2.4.55",
                        "FixedVersion": "2.4.56",
                        "Severity": "CRITICAL",
                        "Title": "HTTP request smuggling via mod_proxy",
                        "Description": "Improper handling of HTTP header folding in mod_proxy enables request smuggling.",
                        "CVSS": {"nvd": {"V3Score": 9.8, "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
                    },
                    {
                        "VulnerabilityID": "CVE-2023-0464",
                        "PkgName": "openssl",
                        "InstalledVersion": "3.0.7",
                        "FixedVersion": "3.0.9",
                        "Severity": "HIGH",
                        "Title": "X.509 certificate verification DoS",
                        "Description": "Excessive recursion in X.509 policy chain validation can lead to denial-of-service.",
                        "CVSS": {"nvd": {"V3Score": 7.5, "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}},
                    },
                ],
            }],
        },
    },
    {
        "imageRef": "icr.io/prod/data-pipeline:v1.8.0",
        "projectId": "CLOUD-199",
        "cisProfile": "NIST SP 800-190",
        "severityThreshold": "high",
        "scanner": "trivy",
        "autoApproveBelow": "none",
        "trivyJson": {
            "Results": [{
                "Target": "icr.io/prod/data-pipeline:v1.8.0",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-3094",
                        "PkgName": "xz-utils",
                        "InstalledVersion": "5.6.0",
                        "FixedVersion": "5.6.1",
                        "Severity": "CRITICAL",
                        "Title": "RCE — backdoor in build system",
                        "Description": "Malicious code in xz-utils 5.6.0 allows unauthorized remote access via SSH.",
                        "CVSS": {"nvd": {"V3Score": 10.0, "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}},
                    },
                    {
                        "VulnerabilityID": "CVE-2023-44487",
                        "PkgName": "nghttp2",
                        "InstalledVersion": "1.52.0",
                        "FixedVersion": "1.57.0",
                        "Severity": "HIGH",
                        "Title": "HTTP/2 Rapid Reset DoS",
                        "Description": "RST_STREAM flood causes unbounded CPU consumption on HTTP/2 servers.",
                        "CVSS": {"nvd": {"V3Score": 7.5, "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}},
                    },
                ],
            }],
        },
    },
]


# ── Helpers ────────────────────────────────────────────────────────────────

def _request(method: str, path: str, body: dict | None = None) -> dict:
    url = f"{BASE}{path}"
    data = json.dumps(body).encode() if body else None
    headers = {"Content-Type": "application/json"} if body else {}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode()
        print(f"  ✗ HTTP {e.code} {path}: {body_text[:200]}", file=sys.stderr)
        return {}


def _poll(run_id: str, timeout: int = 180) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = _request("GET", f"/run/{run_id}")
        status = r.get("status", "")
        print(f"    [{status}] {len(r.get('cves', []))} CVEs ...", end="\r")
        if status in ("awaiting_approval", "completed", "error"):
            print()
            return r
        time.sleep(2)
    print()
    return {}


# ── Main ───────────────────────────────────────────────────────────────────

def main() -> None:
    # Verify backend is reachable
    h = _request("GET", "/health")
    print(f"✓ Backend healthy — {h.get('rag_decisions', '?')} existing decisions\n")

    for i, scan in enumerate(SCANS, 1):
        image = scan["imageRef"]
        project = scan["projectId"]
        n_cves = len(scan["trivyJson"]["Results"][0]["Vulnerabilities"])
        print(f"[{i}/{len(SCANS)}] Scan: {image}  ({n_cves} CVEs)")

        # Start scan
        r = _request("POST", "/scan", scan)
        run_id = r.get("run_id")
        if not run_id:
            print("  ✗ No run_id returned — skipping\n")
            continue
        print(f"  run_id: {run_id}")

        # Wait for synthesis + approval gate
        run = _poll(run_id)
        if run.get("status") != "awaiting_approval":
            print(f"  ✗ Unexpected status: {run.get('status')} — skipping\n")
            continue

        cves = run.get("cves", [])
        print(f"  ✓ Synthesis done — approving {len(cves)} CVEs ...")

        # Approve all CVEs
        for cve in cves:
            payload = {
                "cve_id": cve["id"],
                "decision": "approved",
            }
            dr = _request("POST", f"/run/{run_id}/decision", payload)
            if not dr.get("ok"):
                print(f"    ✗ Decision failed for {cve['id']}")
            # Wait briefly for graph to reach next approval gate
            time.sleep(3)

        # Poll to completion
        final = _poll(run_id)
        print(f"  ✓ Run {run_id[:8]}... → {final.get('status')}\n")

    # Final stats
    h = _request("GET", "/health")
    s = _request("GET", "/stats")
    print(f"✅ Seed complete!")
    print(f"   RAG decisions: {h.get('rag_decisions')}")
    print(f"   Total scans:   {s.get('totalScans')}")
    print(f"   CVEs triaged:  {s.get('cvesTriaged')}")


if __name__ == "__main__":
    main()
