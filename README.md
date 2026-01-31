# ROADMAP.md — Enterprise Detection Coverage (Tier-1 / Tier-2 / Tier-3)
**Author:** Ala Dabat  
**WORK IN PROGRESS**
**Platform:** Microsoft Defender XDR (MDE Advanced Hunting) + Microsoft Sentinel (where noted)  
**Method:** Minimum Truth → Reinforcement (Convergence) → Noise Suppression → Scoring/Confidence → SOC Directives  
**Principle:** Cluster techniques into **Composite Ecosystems**, not 1:1 “atomic rules”.

---

## How to read this roadmap
### Tiers (what “Tier-1/2/3” mean in *this* framework)
- **Tier-1 (Baseline Control Plane)**  
  Must-have coverage for any enterprise. High-signal, bounded joins, operationally deployable, low-noise by design.
- **Tier-2 (Composite Attack Ecosystems)**  
  Multi-signal correlation (“Convergence layer”) + prevalence scoring + “cousin” coverage. Built for L2/L3 hunting + incident stitching.
- **Tier-3 (Threat-Specific / Research Parking Bay)**  
  Campaign/exploit families (React2Shell, EtherRAT, SilverFox/ValleyRAT, etc.). These evolve; keep as POC until validated.

### Status labels
- **✅ PRODUCTION** = already deployable (or already in Production-READY repo)
- **🧪 POC** = exists but not production-hardened; requires decomposition/tuning
- **🧱 MONOLITH** = intentionally brittle “ecosystem model”; used to derive deployable composites
- **⬜ PLANNED** = not yet implemented

---

## Global program standards (applies to every rule)
### Minimum required fields in every detection output
- `Time`, `DeviceName`, `AccountName`, `AttackStage`, `RiskScore`, `Severity`, `Confidence`
- `EvidenceKeys` (SHA256, RemoteIP/Url, PipeName, RegistryKey, TaskName, ServiceName, etc.)
- `HuntingDirectives` (SOC-ready next actions)

### Noise suppression primitives (use consistently)
- **Org Prevalence:** file hash / pipe name / domain / commandline rarity
- **Safe vendor + safe path anchors**
- **Known admin tooling allowlist** (tight + audited)
- **Role-aware suppression** (servers/dev boxes vs user endpoints) where possible

### Cousin Rule doctrine
For each ecosystem, build the *paired* detection in the adjacent **noise domain**:
- same attacker goal, different execution surface  
- separate truth anchor  
- separate noise strategy  
- correlation happens at the incident/story level, not by mixing anchors

---

# TIER-1 — Baseline Coverage (Enterprise Must-Have)
These are the “foundation sensors”. They should exist even if Tier-2/3 doesn’t.

## TA0001 Initial Access
| Composite Ecosystem | Minimum Truth | Cousins | Telemetry | Status |
|---|---|---|---|---|
| Phishing Click-Through / BEC Surfacing | URL click + risky destination OR mailbox rule/persistence | SafeLinks vs non-SafeLinks variants | EmailEvents/UrlClickEvents (MDE), Sentinel mail logs |  POC (present in POC repo) |
| Internet-Facing Exposure / Exploit Surfacing | device/service exposed + exploit-ish behaviour indicators | web app RCE “post-exploit” pivot | DeviceNetworkEvents + device inventory |  POC (present in POC repo) |

## TA0002 Execution
| Composite Ecosystem | Minimum Truth | Cousins | Telemetry | Status |
|---|---|---|---|---|
| LOLBIN Proxy Execution Baseline | signed LOLBIN used with suspicious execution primitive | task-spawned LOLBIN cousin | DeviceProcessEvents |  POC (multiple packs exist) |
| PowerShell Execution Baseline | PowerShell with high-risk primitives (enc/iex/download) | AMSI bypass cousin | DeviceProcessEvents + AMSI telemetry | ✅ (PS cradle rules exist in Production-READY; AMSI bypass POC exists) |

## TA0003 Persistence
| Composite Ecosystem | Minimum Truth | Cousins | Telemetry | Status |
|---|---|---|---|---|
| Registry Autoruns Persistence | autorun key write | hijack/interception cousins (IFEO/COM/AppInit/Winlogon) | DeviceRegistryEvents |  POC (present) |
| Scheduled Task Persistence | TaskCache write OR task XML drop | “no schtasks.exe” svchost/taskeng cousin | Registry + File + Process | ✅ (task + cousin work exists) |
| WMI Persistence | WMI permanent subscription artefacts | WMI consumer execution cousin | WMI tables / DeviceEvents | ✅ (WMI L2 rules exist in Production-READY) |

## TA0004 Privilege Escalation
| Composite Ecosystem | Minimum Truth | Cousins | Telemetry | Status |
|---|---|---|---|---|
| BYOVD / LOLDriver Escalation | driver/service install + untrusted driver load | staged/delayed driver cousins | DeviceEvents + registry/service |  POC (present) |
| Token / Identity privilege shift | privileged token use / app role assignment | service principal backdoor cousin | Entra logs + cloud audit | ✅ (Service_Principal_Backdoor exists) |

## TA0005 Defense Evasion
| Composite Ecosystem | Minimum Truth | Cousins | Telemetry | Status |
|---|---|---|---|---|
| Obfuscation / Masquerade Baseline | suspicious rename/path mismatch + execution | polymorphic loader cousin | File + Process |  POC (present) |
| EDR Tamper / Degrade | security control changed or disabled | driver-based EDR tamper cousin | DeviceEvents/DeviceInfo |  POC (present) |

## TA0006 Credential Access
| Composite Ecosystem | Minimum Truth | Cousins | Telemetry | Status |
|---|---|---|---|---|
| LSASS Access / Dump | LSASS read/open OR dump primitive | comsvcs/werfault/procdump cousins | Process + memory access telemetry | ✅ (Composite LSASS rules exist) |
| Kerberoasting | TGS anomalies / weak enc usage | endpoint heuristic cousin | Identity logs + endpoint signals |  POC (present) |
| Secrets Discovery (files) | credential keyword file access | browser stores / unsafe stores cousin | File events |  POC (present) |

## TA0007 Discovery
| Composite Ecosystem | Minimum Truth | Cousins | Telemetry | Status |
|---|---|---|---|---|
| AD/Host Recon Baseline | recon tool/process patterns | Kerberos service recon cousin | Process + Network | 🧪 POC (present) |

## TA0008 Lateral Movement
| Composite Ecosystem | Minimum Truth | Cousins | Telemetry | Status |
|---|---|---|---|---|
| SMB Service Lateral | inbound SMB/RPC + `services.exe` execution chain | scheduled task surface cousin | Network + Process + (optional service install) | ✅ (SMB_Service_Execution_Org_Prev exists) |
| WMI Remote Exec | remote process created via WMI | DCOM/WinRM cousins | Process + WMI / auth | ✅ (WMI remote creation exists) |
| RDP Follow-on | suspicious drop then RDP use | interactive logon cousin | File + Logon |  POC (present) |

## TA0011 Command & Control
| Composite Ecosystem | Minimum Truth | Cousins | Telemetry | Status |
|---|---|---|---|---|
| Named Pipe C2 / Lateral Mesh | named pipe deviation + rarity + context | SMB pipe + service install cousins | DeviceEvents + Network + (Sentinel 7045 optional) |  Advanced POC (present) |
| HTTPS Beaconing (Jitter) | repeated small HTTPS + interval/jitter pattern | browser-like suppression cousin | DeviceNetworkEvents |  POC (present) |
| Suspicious Outbound / TOR | rare dest + risky infra | miner C2 cousin | Network + TI feeds optional |  POC (present) |
| Blockchain RPC C2 (Web3 abuse) | RPC provider comms + beacon-like pattern + non-dev host | EtherRAT ecosystem cousin | DeviceNetworkEvents + process context |  POC (present) |

## TA0010 Exfiltration
| Composite Ecosystem | Minimum Truth | Cousins | Telemetry | Status |
|---|---|---|---|---|
| Clipboard / Staging Exfil | clipboard events + suspicious chain | archive tooling cousin | Clipboard + Process |  POC (present) |
| SMB Exfil (critical shares) | critical share access + abnormal actor | admin share cousin | Network + auth |  POC (present) |

## TA0040 Impact
| Composite Ecosystem | Minimum Truth | Cousins | Telemetry | Status |
|---|---|---|---|---|
| Ransomware Precursor | encryption-like file ops + defense evasion | shadow copy delete cousin | File + Process | ⬜ PLANNED |

---

# TIER-2 — Composite Attack Ecosystems (Convergence + Cousins)
Tier-2 is where you operationalise “attack architecture” without shipping monoliths.

## 1) Ingress + Tool Transfer Ecosystem
**Goal:** detect staged ingress (download → drop → execute), not just “PowerShell bad”.
- **Minimum Truth anchors:** suspicious file ingress OR known staging primitive execution  
- **Reinforcement:** Mark-of-the-Web / uncommon parent / rarity / immediate child execution
- **Noise suppression:** safe vendor update chains, common installers, enterprise software baselines

**Planned composites**
- ✅ `Ingress_Tool_Transfer_Enhanced` (or equivalent)  
- 🧪 LOLBIN ingress pack decomposition (certutil/bitsadmin/mshta/rundll32 families)
- Cousin: “Ingress from Office/Browsers” vs “Ingress from RMM/admin tooling”

## 2) SMB Lateral Movement Ecosystem (Primary + Cousins)
- ✅ **Primary:** SMB + `services.exe` execution composite (with OrgPrevalence)  
- 🧪 **Cousin A:** SMB + `svchost.exe (Schedule)` execution + TaskCache/Task drops  
- ⬜ **Cousin B:** SMB + WMIExec/DCOMExec/WinRM surface (separate anchors, separate noise gates)

## 3) Identity Abuse Ecosystem (OAuth / Tokens / Service Principals)
- ✅ OAuth consent abuse (grant truth + baseline deviation)
- ✅ OAuth token anomaly / token theft patterns
- ✅ service principal backdoor patterns
- Cousins:
  - ⬜ “Token replay / session theft” correlation with device context
  - ⬜ “App consent + mailbox rules” cross-plane persistence (if telemetry available)

## 4) Credential Access Ecosystem (LSASS + Kerberos + NTDS)
- ✅ LSASS composite (access truth + reinforcement + scoring)
- ✅/ NTDS composite variants
-  Kerberoasting variants (Sentinel-only vs MDE-only)
- Cousins:
  - ⬜ DCSync / replication abuse (directory/audit plane)
  - ⬜ DPAPI / browser credential store theft (endpoint plane)

## 5) C2 Ecosystem (Hard Mode: Noise Domain)
You don’t “win” C2 by timing alone. Convergence lives in **cross-signal agreement**.

**Tier-2 C2 design rule:**  
> Timing is *one* feature. Convergence is when timing + rarity + process context + infra context agree.

Planned composites
-  Named Pipe C2 + Lateral correlation (rarity + SMB + service context)
-  HTTPS jitter beaconing (interval/jitter + low bytes + non-browser penalty + prevalence)
-  Blockchain RPC C2 (RPC providers + beacon-like + non-dev host + suspicious process)

Cousins
-  “Same destination across many hosts” (botnet-like) vs “single-host rare beacon”
-  “C2 over legitimate app (browser/webview)” separate anchor + heavier suppression

---

# TIER-3 — Threat / Exploit Packs (Keep as POC until proven)
These stay as “research parked” until you’ve validated noise + mapped to Tier-2.

| Threat Pack | Why it exists | Output expectation | Status |
|---|---|---|---|
| EtherRAT (Web3/RPC C2) | modern C2 channel abuse | RPC-beacon + process context + dev suppression | 🧪 POC present |
| SilverFox / ValleyRAT | real-world loader + BYOVD adjacency | chain modelling + decomposed prod rules | 🧪 POC present |
| WebRCE / React2Shell class | exploit-to-shell pipelines | post-exploit behaviours → Tier-2 ingress/execution | 🧪 POC present |
| Stego-loader | niche loader behaviour | staged artefacts + memory indicators | 🧪 POC present |

---

# “Cousin Rule” Matrix (Enterprise Roadmap View)
This is the high-level pairing table you use to ensure ecosystem completeness.

| Ecosystem | Primary Composite (truth anchor) | Cousin Composite (adjacent noise domain) |
|---|---|---|
| SMB Lateral | SMB + `services.exe` child exec | SMB + `svchost/taskeng` scheduled exec |
| Scheduled Tasks | `schtasks.exe` create/exec truth | TaskCache/Task XML truth (no CLI) |
| LOLBIN Exec | LOLBIN proxy exec truth | task-spawned LOLBIN / WMI-spawned LOLBIN |
| Identity Abuse | consent grant truth | token replay truth / CA bypass truth |
| C2 | named pipe deviation truth | HTTPS jitter truth / blockchain RPC truth |
| Credential Access | LSASS access truth | Kerberos/NTDS truth / DPAPI truth |

---

# Delivery Plan (what to build next, in the right order)
### Phase 1 — Finish Tier-1 coverage gaps (fast wins)
1) Ransomware precursor baseline (Impact)  
2) AD discovery baseline hardening  
3) Exfil baselines (clipboard + SMB critical shares)  

### Phase 2 — Stabilise Tier-2 ecosystems (production reality)
1) SMB scheduled-task cousin (svchost schedule surface)  
2) C2 prevalence scoring standardisation (pipes/domains/remote IP)  
3) Identity cousins (token replay/session theft)

### Phase 3 — Promote Tier-3 to Tier-2 selectively
Only promote if:
- anchor is stable
- reinforcement is available in default telemetry
- you can express noise suppression structurally (not “allowlist forever”)

---

# Appendix — Telemetry map (minimum)
- Endpoint: `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceEvents`
- Identity (as available): `SigninLogs`, Entra audit logs, CloudAppEvents
- Sentinel-only optional: `SecurityEvent` (e.g., 7045 service installs)

---

## End state definition (what “complete baseline” means)
You are “baseline complete” when:
- every MITRE tactic has at least **one Tier-1 truth anchor**
- every high-value ecosystem has at least **one cousin rule**
- Tier-2 ecosystems are the “story builders” (incident correlation), not monolith alerts
- Tier-3 stays research unless it earns promotion
