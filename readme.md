# SiegePal Offensive Runner — Developer & Operations Guide

> **Last Updated:** 2026-03-30  
> **Applies to:** SIEGE-82 (Offensive Runner System)

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [End-to-End Flow: Chat → Scan → Results](#2-end-to-end-flow)
3. [Adding a New Tool (Step-by-Step)](#3-adding-a-new-tool)
4. [Execution Modes](#4-execution-modes)
5. [Security Model](#5-security-model)
6. [Runner Lifecycle](#6-runner-lifecycle)
7. [Policy System](#7-policy-system)
8. [Manual Testing Guide](#8-manual-testing-guide)
9. [Troubleshooting](#9-troubleshooting)
10. [File Reference](#10-file-reference)

---

## 1. Architecture Overview

```
┌────────────────┐     ┌──────────────────────────┐     ┌──────────────────┐
│  Frontend      │     │  Backend (Django)         │     │  Runner (CLI)    │
│  Next.js       │────▶│  PostgreSQL + Redis       │◀────│  Customer-side   │
│  localhost:3000 │     │  Celery Workers           │     │  Python process  │
└────────────────┘     └──────────────────────────┘     └──────────────────┘
      │                         │                              │
      │ 1. User types in chat   │ 3. Signed manifest           │ 4. Runner polls
      │ 2. LLM plans job        │    queued in DB              │ 5. Validates manifest
      │ 8. Results in chat      │ 7. Result callback           │ 6. Executes tool
      │                         │                              │
```

### Components

| Component | Location | Purpose |
|-----------|----------|---------|
| **Backend API** | `src/app/agent/views_runner.py` | 27 REST endpoints (6 runner-auth, 21 admin-auth) |
| **Job Service** | `src/app/agent/services/offensive_job_service.py` | Job creation, state machine, policy enforcement |
| **Planner** | `src/app/agent/graphs/specialists/offensive_graph.py` | LangGraph node that plans jobs from chat input |
| **Result Formatter** | `src/app/agent/services/result_formatter.py` | Parses raw tool output → structured findings |
| **Tool Translators** | `src/app/agent/services/tool_translators.py` | Validates actions → CLI command specs |
| **Runner CLI** | `siegepal-runner/src/siegepal_runner/cli/main.py` | `register` + `start` commands |
| **Poller** | `siegepal-runner/src/siegepal_runner/polling/poller.py` | Main loop: poll → validate → execute → report |
| **Executors** | `siegepal-runner/src/siegepal_runner/executor/` | Mode 1 (structured), Mode 2 (semi-flexible), Mode 3 (raw) |
| **Tool Adapters** | `siegepal-runner/src/siegepal_runner/tools/` | Per-tool CLI builders + output parsers |

---

## 2. End-to-End Flow

### Chat → Scan → Results (Full Pipeline)

```
User: "Scan 10.0.0.1 for open ports"
  │
  ▼
[1] offensive_graph.py (LLM Planner)
  │  LLM picks: mode=structured, type=port_scan, target=10.0.0.1
  │
  ▼
[2] offensive_job_service.create_job()
  │  7-step validation:
  │  a) Mode validation (structured/semi_flexible/raw)
  │  b) Runner capability check
  │  c) Tool allow/block list
  │  d) Blocked flags enforcement
  │  e) Scope (CIDRs + domains)
  │  f) Dangerous pattern detection
  │  g) Build signed manifest (HMAC-SHA256)
  │
  ▼
[3] OffensiveJob saved (status=queued) in PostgreSQL
  │
  ▼
[4] Runner poller.py: POST /runner/jobs/poll/
  │  → claim_next_job() → status=claimed
  │  → Signed manifest returned
  │
  ▼
[5] Runner manifest/validator.py
  │  8-step validation:
  │  1. Schema check       5. Scope validation
  │  2. Mode allowed?      6. Dangerous patterns
  │  3. HMAC signature     7. Raw-mode sandbox check
  │  4. Runner ID match    8. Timestamp freshness
  │
  ▼
[6] Executor runs the tool
  │  Mode 1 → StructuredExecutor → NmapAdapter.build_command()
  │  Mode 2 → SemiFlexibleExecutor → tool + args validation
  │  Mode 3 → RawExecutor → ProcessSandbox (if enabled)
  │
  ▼
[7] Reporter: POST /runner/jobs/result/
  │  → submit_result() → OffensiveJobExecution created
  │  → status=completed/failed/rejected
  │
  ▼
[8] notify_job_status_task (Celery)
  │  → chat_result_callback.post_result_to_chat()
  │  → result_formatter.py parses findings
  │  → AgentMessage created in chat conversation
  │
  ▼
[9] Frontend renders Markdown findings in chat
```

---

## 3. Adding a New Tool (Step-by-Step)

### Example: Adding `nikto` (web server scanner)

#### Step 1: Create the Runner Adapter

Create `siegepal-runner/src/siegepal_runner/tools/nikto_adapter.py`:

```python
"""Nikto tool adapter - web server scanning."""
from __future__ import annotations
from typing import Any, Dict, List
import structlog

logger = structlog.get_logger(__name__)

class NiktoAdapter:
    """Translates web_scan actions into nikto commands."""
    
    name = "nikto"
    
    def build_command(self, action: Dict[str, Any]) -> List[str]:
        """Build nikto CLI args from a structured action.
        
        Expected action fields:
            target: str     - URL or IP
            ports: str      - e.g. "80,443"
            tuning: str     - nikto tuning options (optional)
        """
        params = action.get("parameters", {})
        merged = {**params, **{k: v for k, v in action.items() if k != "parameters"}}
        
        target = merged.get("target", "")
        ports = merged.get("ports", "80")
        
        cmd = ["nikto", "-h", str(target)]
        
        if ports:
            cmd.extend(["-p", str(ports)])
        
        # Machine-readable output
        cmd.extend(["-Format", "json"])
        
        return cmd
    
    def parse_output(self, stdout: str) -> Dict[str, Any]:
        """Parse nikto JSON output into structured data."""
        import json
        try:
            data = json.loads(stdout)
            return {
                "tool": "nikto",
                "vulnerabilities": data.get("vulnerabilities", []),
                "host": data.get("host", ""),
            }
        except json.JSONDecodeError:
            return {"raw_output": stdout[:5000]}
```

#### Step 2: Register in Runner `tools/__init__.py`

```python
# In siegepal-runner/src/siegepal_runner/tools/__init__.py

from .nikto_adapter import NiktoAdapter   # ADD import

_ADAPTERS: Dict[str, ToolAdapter] = {
    "port_scan": NmapAdapter(),
    "vulnerability_scan": NucleiAdapter(),
    "subdomain_enum": SubfinderAdapter(),
    "web_scan": NiktoAdapter(),            # ADD registration
}
```

#### Step 3: Register in Runner `executor/structured.py`

```python
# In siegepal-runner/src/siegepal_runner/executor/structured.py

_ACTION_MAP = {
    "port_scan": "siegepal_runner.tools.nmap_adapter",
    "vulnerability_scan": "siegepal_runner.tools.nuclei_adapter",
    "subdomain_enum": "siegepal_runner.tools.subfinder_adapter",
    "web_scan": "siegepal_runner.tools.nikto_adapter",     # ADD
}
```

#### Step 4: Add to Runner `executor/semi_flexible.py` (if Mode 2 allowed)

```python
# In siegepal-runner/src/siegepal_runner/executor/semi_flexible.py

DEFAULT_ALLOWED_TOOLS: Set[str] = {
    "nmap",
    "nuclei",
    "subfinder",
    "nikto",       # ADD
}
```

#### Step 5: Add Backend Tool Translator

Create or add to `src/app/agent/services/tool_translators.py`:

```python
# Add translation function
def translate_nikto(action: Dict[str, Any]) -> CommandSpec:
    """Translate a structured nikto action into a CommandSpec."""
    params = action.get("parameters", {})
    target = params.get("target") or action.get("target", "")
    ports = params.get("ports", "80")
    
    if not target:
        raise TranslationError("nikto requires a target", "missing_target")
    
    cmd = ["nikto", "-h", target]
    if ports:
        cmd.extend(["-p", str(ports)])
    cmd.extend(["-Format", "json"])
    
    return CommandSpec(tool="nikto", args=cmd, target=target)

# Register in TOOL_TRANSLATORS
TOOL_TRANSLATORS = {
    "nmap": translate_nmap,
    "nuclei": translate_nuclei,
    "subfinder": translate_subfinder,
    "nikto": translate_nikto,          # ADD
}

# Register in ACTION_TYPE_TO_TOOL
ACTION_TYPE_TO_TOOL = {
    ...existing entries...
    "web_scan": "nikto",               # ADD
    "nikto_scan": "nikto",             # ADD alias
}
```

#### Step 6: Add Backend Result Parser

Add to `src/app/agent/services/result_formatter.py`:

```python
def parse_nikto_findings(stdout: str, findings_json=None) -> List[Finding]:
    """Parse nikto output into Finding objects."""
    findings = []
    try:
        data = json.loads(stdout)
        for vuln in data.get("vulnerabilities", []):
            findings.append(Finding(
                title=f"Web Vuln: {vuln.get('id', 'Unknown')}",
                severity=vuln.get("severity", "info"),
                detail=vuln.get("msg", ""),
                source="nikto",
            ))
    except (json.JSONDecodeError, KeyError):
        if stdout.strip():
            findings.append(Finding(
                title="Nikto scan output",
                severity="info",
                detail=stdout[:3000],
                source="nikto",
            ))
    return findings

# Register in _TOOL_PARSERS
_TOOL_PARSERS = {
    ...existing entries...
    "nikto": parse_nikto_findings,
    "web_scan": parse_nikto_findings,  # action_type alias
}
```

#### Step 7: Update Planner Prompt (Optional but Recommended)

In `src/app/agent/graphs/specialists/offensive_graph.py`, update the system prompt to tell the LLM about the new tool:

```python
OFFENSIVE_PLANNER_SYSTEM_PROMPT = """
...
Available tools:
- port_scan (nmap) — port/service scanning
- vulnerability_scan (nuclei) — CVE detection
- subdomain_enum (subfinder) — subdomain discovery
- web_scan (nikto) — web server vulnerability scanning   ← ADD
...
"""
```

#### Step 8: Update Runner `capabilities` in Registration

In `siegepal-runner/src/siegepal_runner/auth/client.py`:

```python
payload = {
    "registration_token": registration_token,
    "hostname": platform.node(),
    "os_info": f"{platform.system()} {platform.release()}",
    "capabilities": ["nmap", "nuclei", "subfinder", "nikto"],  # ADD
    "version": "0.1.0",
}
```

#### Checklist Summary

| # | Location | Action |
|---|----------|--------|
| 1 | Runner `tools/nikto_adapter.py` | Create adapter with `build_command()` + `parse_output()` |
| 2 | Runner `tools/__init__.py` | Import + register in `_ADAPTERS` |
| 3 | Runner `executor/structured.py` | Add to `_ACTION_MAP` |
| 4 | Runner `executor/semi_flexible.py` | Add to `DEFAULT_ALLOWED_TOOLS` |
| 5 | Backend `tool_translators.py` | Add translator fn + register in both maps |
| 6 | Backend `result_formatter.py` | Add parser fn + register in `_TOOL_PARSERS` |
| 7 | Backend `offensive_graph.py` | Update planner system prompt |
| 8 | Runner `auth/client.py` | Add to `capabilities` list |

---

## 4. Execution Modes

### Mode 1: Structured (Safest)

```json
{
  "mode": "structured",
  "action": {
    "type": "port_scan",
    "target": "10.0.0.1",
    "parameters": {
      "ports": "22,80,443",
      "scan_type": "connect"
    }
  }
}
```

- Action type routed to a known adapter
- CLI args built by the adapter (no user-supplied commands)
- No approval required by default

### Mode 2: Semi-Flexible

```json
{
  "mode": "semi_flexible",
  "action": {
    "tool": "nmap",
    "args": ["-sV", "-p", "1-1024"],
    "target": "10.0.0.1"
  }
}
```

- User specifies tool + custom args
- Tool must be in `DEFAULT_ALLOWED_TOOLS`
- Args checked against `BLOCKED_ARGS` (prefix matching)
- May require approval depending on policy

### Mode 3: Raw (Most Dangerous)

```json
{
  "mode": "raw",
  "action": {
    "command": "nmap -sS -T4 -A 10.0.0.1"
  }
}
```

- Full shell command execution
- **Always requires approval** (`approval_required=True`)
- Runs inside `ProcessSandbox` (if enabled):
  - Resource limits (CPU time, memory, file size, open files)
  - Temp directory isolation
  - Environment variable scrubbing
- Frontend shows an acknowledgment modal before submission

---

## 5. Security Model

### Authentication Layers

| Endpoint Type | Auth Method | Details |
|---------------|-------------|---------|
| Runner endpoints (`/runner/*`) | Runner JWT | HMAC-signed, short-lived (1h), auto-refresh |
| Admin endpoints (`/runner/admin/*`) | Firebase + RBAC | User token + organization role check |

### Token Flow

```
Registration Token (one-time) → Register → Access JWT (1h) + Refresh Token
                                             │                    │
                                             ▼                    ▼
                                          Auto-refresh         Rotated on
                                          before expiry        each refresh
```

### Manifest Signing

Every job manifest is signed with HMAC-SHA256 before being sent to the runner:

```python
# Backend signs:
signature = hmac.new(MANIFEST_SECRET, canonical_json, sha256).hexdigest()

# Runner verifies:
hmac.compare_digest(expected, computed)  # timing-safe
```

### Policy Enforcement (7 Steps)

The backend validates every job at creation time:

1. **Mode check** — Is the requested mode allowed by the runner policy?
2. **Capability check** — Does the runner have the required capability?
3. **Tool allow/block** — Is the tool in `allowed_tools`? Not in `blocked_tools`?
4. **Blocked flags** — Do any args match `blocked_flags`? (prefix matching)
5. **Scope check** — Is the target within allowed CIDRs/domains?
6. **Dangerous patterns** — Does the command contain risky strings? (`rm -rf`, `mkfs`, pipes to shells, etc.)
7. **Manifest signing** — Sign the validated manifest for the runner

---

## 6. Runner Lifecycle

### Registration

```bash
# 1. Admin creates runner in UI (gets registration token)
# 2. Customer runs on their machine (URL = backend, same as NEXT_PUBLIC_BACKEND_URL):
siegepal-runner register --token <TOKEN> --url $NEXT_PUBLIC_BACKEND_URL
# Production: siegepal-runner register --token <TOKEN> --url https://api.siegepal.com
# Local dev:  siegepal-runner register --token <TOKEN> --url http://localhost:8000

# 3. Runner is now registered (credentials stored encrypted in ~/.siegepal-runner/)
```

### Start

```bash
siegepal-runner start --config ~/.siegepal-runner/config.yaml
```

The runner starts:
- **Polling loop** — `POST /runner/jobs/poll/` every 10-60s (exponential backoff)
- **Heartbeat** — `POST /runner/heartbeat/` every 30s with system metrics
- Auto-refresh JWT when approaching expiry
- Graceful shutdown on SIGINT/SIGTERM

### Status Flow

```
(created) → pending → online → offline → revoked
                │          │         │
                │          ▼         │
                │      (scanning)    │
                │          │         │
                ▼          ▼         ▼
             (deactivated by admin)
```

---

## 7. Policy System

Runner policies control what the runner can do. Set via the admin UI (Scope & Modes tab).

```json
{
  "allowed_modes": ["structured", "semi_flexible"],
  "allowed_tools": ["nmap", "nuclei"],
  "blocked_tools": ["metasploit"],
  "blocked_flags": ["--exec", "--script", "-iL"],
  "capabilities": ["scanning", "enumeration"],
  "scope_defaults": {
    "cidrs": ["10.0.0.0/8", "192.168.0.0/16"],
    "domains": ["*.example.com", "test.internal"]
  },
  "approval_rules": {
    "semi_flexible": "auto",
    "raw": "manual"
  }
}
```

### Policy Validation Rules

- `allowed_tools` and `blocked_tools` **cannot overlap** (contradictory policy detection)
- Blocked flags use **prefix matching**: `--exec` blocks `--exec=payload`
- Domain matching requires **exact or subdomain**: `example.com` matches `sub.example.com` but NOT `evil-example.com`
- CIDRs use proper `ipaddress.ip_network` parsing (no string fallback)

---

## 8. Manual Testing Guide

### Prerequisites

```bash
# Terminal 1: Backend
cd siegepal-backend/src && docker compose up -d

# Terminal 2: Frontend
cd siegepal-frontend && npm run dev -- -H 127.0.0.1 -p 3000

# Terminal 3: Runner
cd siegepal-runner && .venv/bin/siegepal-runner start --config ~/.siegepal-runner/config.yaml
```

### Test 1: Runner Registration

1. Open browser → `http://localhost:3000/settings/runners`
2. Click **"Register New Runner"**
3. Fill in: Name = `test-runner`, Environment = `development`
4. Click **Create** → Copy the registration token
5. In Terminal 3 (use the backend URL — same as `NEXT_PUBLIC_BACKEND_URL`):
   ```bash
   siegepal-runner register --token <PASTE_TOKEN> --url $NEXT_PUBLIC_BACKEND_URL
   # e.g.: siegepal-runner register --token <PASTE_TOKEN> --url http://localhost:8000
   ```
6. **Expected**: `✓ Registered successfully!` + Runner shows "online" in UI

### Test 2: Heartbeat Check

1. Wait 30 seconds after registering
2. In the UI Runners page, verify "Last Heartbeat" updates
3. Check backend logs:
   ```bash
   docker compose logs web --since 1m | grep heartbeat
   ```
4. **Expected**: `POST /agent/runner/heartbeat/ HTTP/1.1" 200 OK`

### Test 3: Mode 1 — Structured Port Scan

1. Go to Chat → Select a conversation
2. Make sure the runner is selected (chat dropdown or auto-assigned)
3. Type: `Scan 10.0.0.1 for open ports`
4. **Expected flow**:
   - Job appears in Settings → Runners → Jobs tab (status: queued → claimed → running → completed)
   - Chat shows formatted findings with port/state/service table
5. **Verify** formatted result appears (not raw XML)

### Test 4: Mode 2 — Semi-Flexible

1. In Chat, type: `Run nmap -sV -p 80,443 against 10.0.0.1`
2. **Expected**: Job created in `semi_flexible` mode
3. Check the jobs list → mode should show `semi_flexible`
4. **Verify** the runner log shows `Semi-flexible exec, tool=nmap`

### Test 5: Mode 3 — Raw Command (Approval Required)

1. In Chat, type: `Run this exact command: nmap -sS -T4 -A 10.0.0.1`
   (The phrase "exact command" triggers **raw** mode in the planner)
2. **Expected**: Frontend shows acknowledgment modal → User confirms
3. Job is created with `approval_required=true`, status = `pending`
4. Go to Settings → Runners → Jobs → Click the pending job
5. **Expected**: See amber banner with ⏳ icon and **Approve** / **Deny** buttons
6. Click **Approve** → Job transitions to `queued` → runner picks it up
7. Click **Deny** on a different pending job → Status changes to `rejected`

### Test 6: Policy Enforcement — Blocked Tool

1. Go to Settings → Runners → Select runner → Scope & Modes tab
2. Add `nmap` to **Blocked Tools**
3. In Chat, try: `Run nmap scan on 10.0.0.1`
4. **Expected**: Error message: "Tool 'nmap' is blocked by runner policy"

### Test 7: Policy Enforcement — Scope Violation

1. In Scope & Modes tab, set Allowed CIDRs to `10.0.0.0/8`
2. In Chat, try: `Scan 192.168.1.1 for ports`
3. **Expected**: Error: "Target '192.168.1.1' is outside the runner's configured scope"

### Test 8: Policy Enforcement — Blocked Flags

1. In Scope & Modes tab, add `--exec` to Blocked Flags
2. In Chat, try a scan with `--exec` arguments
3. **Expected**: Error: "Flag '--exec' is blocked by runner policy"

### Test 9: Token Refresh

1. Start the runner and let it run for > 55 minutes (or manually expire the token)
2. Watch the runner logs for `Access token refreshed`
3. Backend logs should show `POST /agent/runner/token/refresh/ HTTP/1.1" 200 OK`
4. **Expected**: Seamless continuation — no 401 errors

### Test 10: CSV Audit Export

1. Go to Settings → Runners → Audit History tab
2. Wait for audit events to load
3. Click **Export CSV**
4. **Expected**: Browser downloads a `.csv` file with all visible audit events
5. Open the CSV → verify columns: Timestamp, Event Type, Runner, IP, Details

### Test 11: Runner Deactivation/Revocation

1. Go to Settings → Runners → Click a runner → Details
2. Click **Deactivate** → Status changes to `offline`
3. **Expected**: Runner's heartbeat/poll gets 403 on next attempt
4. Reactivate, then try **Revoke** → Status changes to `revoked`
5. **Expected**: Runner permanently unable to connect (must re-register)

### Test 12: Tenant Isolation

1. Create two organizations (org-A, org-B) with one runner each
2. Create a job in org-A
3. **Expected**: org-B's runner cannot claim or see org-A's job
4. Verify via admin API: `GET /runner/admin/jobs/` only shows same-org jobs

---

## 9. Troubleshooting

### Runner: "Token refresh failed (401): Invalid refresh token"

**Cause**: The refresh token in `~/.siegepal-runner/credentials.enc` doesn't match the hash in the database. This happens after `docker compose down -v` (DB wipe) or manual token rotation.

**Fix**: Re-register the runner:
```bash
# 1. Create a new registration token in the UI
# 2. Re-register (use backend URL = NEXT_PUBLIC_BACKEND_URL):
siegepal-runner register --token <NEW_TOKEN> --url $NEXT_PUBLIC_BACKEND_URL
# e.g.: siegepal-runner register --token <NEW_TOKEN> --url http://localhost:8000
```

### Runner: "Authentication permanently failed after 5 consecutive attempts"

**Cause**: The runner record was deleted from the database. After 5 failed refresh attempts, the runner stops automatically.

**Fix**: Same as above — re-register.

### Backend: "column 'is_archived' does not exist"

**Cause**: Missing migration. Run:
```bash
docker compose exec web python manage.py migrate
```

### Chat: Raw XML appearing instead of formatted findings

**Cause**: The result formatter doesn't recognize the action type.

**Fix**: Ensure the action type is registered in `_TOOL_PARSERS` in `result_formatter.py` (both the tool name AND the action_type alias).

### Job stuck in "queued" forever

**Causes**:
1. No runner is online → Check runner status in UI
2. Runner capabilities don't match → Check runner policy
3. Runner is polling but not claiming → Check backend logs for claim errors

---

## 10. File Reference

### Backend (siegepal-backend)

| File | Purpose |
|------|---------|
| `agent/views_runner.py` | All 27 REST endpoints |
| `agent/services/offensive_job_service.py` | Job creation, state machine, policy |
| `agent/services/runner_management_service.py` | Runner CRUD, policy, token management |
| `agent/services/result_formatter.py` | Tool output → structured findings |
| `agent/services/tool_translators.py` | Action → CLI command validation |
| `agent/services/manifest_signing.py` | HMAC-SHA256 manifest signing |
| `agent/services/chat_result_callback.py` | Post results to chat conversation |
| `agent/services/scope_validator.py` | Target scope validation |
| `agent/graphs/specialists/offensive_graph.py` | LangGraph offensive planner |
| `agent/decorators/runner_auth.py` | JWT auth + permission decorators |
| `agent/tasks/offensive_tasks.py` | Celery tasks (expiry, health, notifications) |
| `agent/models/offensive_*.py` | ORM models (Runner, Job, Execution, Audit) |
| `agent/serializers_runner.py` | DRF serializers for all endpoints |
| `siege/security/runner_auth.py` | JWT generation/verification, token hashing |
| `agent/tests/test_offensive_*.py` | 212 automated tests |

### Runner (siegepal-runner)

| File | Purpose |
|------|---------|
| `cli/main.py` | CLI commands (register, start, status) |
| `auth/client.py` | HTTP auth client (register, refresh, request) |
| `auth/credential_store.py` | Fernet-encrypted credential storage |
| `config.py` | YAML configuration loading |
| `polling/poller.py` | Main polling loop |
| `polling/heartbeat.py` | Periodic heartbeat sender |
| `polling/reporter.py` | Result submission |
| `executor/engine.py` | Execution mode router |
| `executor/base.py` | Base executor (subprocess runner, sandbox) |
| `executor/structured.py` | Mode 1 executor |
| `executor/semi_flexible.py` | Mode 2 executor |
| `executor/raw.py` | Mode 3 executor |
| `manifest/validator.py` | 8-step manifest validation |
| `sandbox/process_sandbox.py` | Resource limits, env scrubbing |
| `tools/__init__.py` | Adapter registry |
| `tools/nmap_adapter.py` | Reference adapter implementation |
| `tools/nuclei_adapter.py` | Nuclei adapter |
| `tools/subfinder_adapter.py` | Subfinder adapter |

### Frontend (siegepal-frontend)

| File | Purpose |
|------|---------|
| `components/pages/settings/runners/types.ts` | TypeScript types |
| `components/pages/settings/runners/api.ts` | API client functions |
| `components/pages/settings/runners/hooks.ts` | SWR hooks |
| `components/pages/settings/runners/constants.ts` | Status labels, colors |
| `components/pages/settings/runners/components/job-detail-panel.tsx` | Job detail with Approve/Deny |
| `components/pages/settings/runners/components/audit-history-tab.tsx` | Audit log + CSV export |
| `components/pages/settings/runners/runners-page-client.tsx` | Main page shell |
