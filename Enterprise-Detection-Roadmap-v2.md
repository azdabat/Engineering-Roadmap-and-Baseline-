# Enterprise Detection Engineering Roadmap  
## Microsoft Sentinel + Microsoft Defender for Endpoint (MDE)  
### Composite Threat Hunting Framework (Minimum Truth → Reinforcement → Cousins → Scoring)

**Author:** Ala Dabat  
**Platform Scope:** Microsoft Sentinel • Microsoft Defender XDR • MDE Advanced Hunting  
**Objective:** Build a complete enterprise-grade detection baseline using **behaviour-first composite engineering**, not brittle IOC spam.

---

# 1. Roadmap Philosophy (Microsoft-Native)

This roadmap is structured around two realities:

## MITRE ATT&CK Completeness (Enterprise Expectation)
Leadership expects full baseline coverage across all ATT&CK tactics.

## Composite Ecosystem Engineering (Operational Reality)
Hunters do not deploy 200 isolated alerts.

Instead, we build **Composite Ecosystem Modules**:

- One Minimum Truth anchor  
- Reinforcement convergence joins  
- Noise suppression gates  
- Org prevalence scoring  
- Cousin execution surfaces  
- SOC-ready analyst directives  

---

# 2. Tier Model (Deployment Strategy)

| Tier | Meaning | Deployment |
|------|--------|-----------|
| **Tier-1** | Mandatory enterprise baseline composites | Always-on detection backbone |
| **Tier-2** | Reinforced cousins + higher-fidelity convergence | Escalation + advanced hunting |
| **Tier-3** | Actor-specific / exploit ecosystems (research POC) | Parked for threat-driven activation |

---

# 3. Enterprise Baseline Roadmap (Microsoft Sentinel/MDE)

---

# TA0001 — Initial Access

## Ecosystem: Phishing → Token → Cloud Entry

| Composite Rule | Minimum Truth Anchor | Cousin Expansion | Status |
|--------------|----------------------|------------------|--------|
| **SafeLinks_ClickThrough + Payload Execution** | User clicks malicious URL + process spawn | Attachment-based cousin | ⚠️ Partial |
| **OAuth Consent Grant Abuse** | Consent granted to abnormal AppId | Token replay cousin | ✅ Complete |
| **External Attachment Delivery Chain** | Email → macro/script execution | HTML smuggling cousin | 🔜 TODO |

**Tier-1 Requirement:** Identity + email entry coverage is mandatory in Microsoft enterprises.

---

# TA0002 — Execution

## Ecosystem: LOLBins + Script Execution Surfaces

| Composite Rule | Truth Anchor | Cousin Surface | Status |
|--------------|-------------|---------------|--------|
| **PowerShell Download + Execution Composite** | Encoded/obfuscated PS + network retrieval | mshta/certutil cousin | ⚠️ Partial |
| **Rundll32 Proxy Execution Core** | rundll32 abnormal export/script execution | regsvr32 cousin | ✅ Built |
| **Rare LOLBin Execution Pack** | Low-prevalence LOLBin execution | WMI-spawn cousin | 🧪 POC |

**Tier-1 Baseline:** Proxy execution coverage is non-negotiable.

---

# TA0003 — Persistence

## Ecosystem: Registry + TaskCache + Service Persistence

| Composite Rule | Truth Anchor | Cousin Needed | Status |
|--------------|-------------|--------------|--------|
| **RunKey Persistence Composite** | Run/RunOnce ValueSet + suspicious payload | ActiveSetup cousin | ✅ Built |
| **TaskCache Silent Persistence** | TaskCache registry blob write | XML drop cousin | ⚠️ Partial |
| **Service Install Persistence** | New service creation + unsigned binary | Driver service cousin | 🔜 TODO |
| **WMI Event Subscription Persistence** | FilterConsumer binding | Permanent WMI cousin | 🔜 MUST BUILD |

**Tier-1 Requirement:** Persistence must cover Registry + Tasks + Services + WMI.

---

# TA0004 — Privilege Escalation

## Ecosystem: Driver Abuse + Token Escalation

| Composite Rule | Truth Anchor | Cousin Expansion | Status |
|--------------|-------------|------------------|--------|
| **LOLDriver / BYOVD Composite** | Known vulnerable driver load + service staging | Delayed-load cousin | ⚠️ Partial |
| **SilverFox/ValleyRAT BYOVD Chain** | Signed loader → sideload → driver registration → DriverLoadEvent | Full ecosystem | 🧪 Tier-3 |
| **WSL Privilege Boundary Abuse** | wsl.exe abnormal root-level behaviour | Container escape cousin | ⚠️ Partial |

**Tier-2 Priority:** BYOVD is now a 2025+ enterprise escalation staple.

---

# TA0005 — Defense Evasion

## Ecosystem: Obfuscation + EDR Tamper + Living-off-Signed

| Composite Rule | Truth Anchor | Cousin Needed | Status |
|--------------|-------------|--------------|--------|
| **AMSI Bypass + Script Obfuscation** | AMSI tamper indicators + encoded execution | ETW bypass cousin | 🧪 POC |
| **EDR Driver Tamper Behaviour** | Kernel driver manipulation attempts | Sensor disable cousin | ⚠️ Partial |
| **Masquerading + Untrusted Execution** | Execution from writable masquerade paths | Signed binary abuse cousin | 🔜 TODO |

---

# TA0006 — Credential Access

## Ecosystem: LSASS + NTDS + Kerberos Theft

| Composite Rule | Truth Anchor | Cousin Surface | Status |
|--------------|-------------|--------------|--------|
| **LSASS Access / Dump Attempts** | Handle access + dump primitives | Silent minidump cousin | ⚠️ Partial |
| **NTDS.dit Extraction Composite** | Shadow copy + NTDS file interaction | DC sync cousin | ⚠️ Partial |
| **Kerberoasting Composite** | Abnormal TGS request volume/anomaly | AS-REP roast cousin | ⚠️ Partial |

**Tier-1 Must-Have:** Credential theft is core enterprise coverage.

---

# TA0007 — Discovery

## Ecosystem: Recon + AD Enumeration

| Composite Rule | Truth Anchor | Cousin Needed | Status |
|--------------|-------------|--------------|--------|
| **AD Recon Command Execution** | nltest/net/user/domain enum patterns | LDAP query cousin | 🔜 TODO |
| **Kerberos Service Recon (Port 88)** | Endpoint Kerberos scanning behaviour | BloodHound cousin | ⚠️ Partial |

---

# TA0008 — Lateral Movement

## Ecosystem: SMB + Remote Exec + Cousin Surfaces

| Composite Rule | Minimum Truth Anchor | Cousin Expansion | Status |
|--------------|----------------------|------------------|--------|
| **SMB Service Execution Composite** | services.exe spawning uncommon child + inbound SMB | Scheduled Task cousin | ✅ Complete |
| **Scheduled Task Remote Exec Cousin** | svchost(Schedule) spawn + TaskCache artefact | WMIExec cousin | ⚠️ POC |
| **WMI Remote Execution Cousin** | Remote process via WMI telemetry | WinRM cousin | 🔜 TODO |
| **RDP Following Suspicious Drop** | File drop → RDP session correlation | Admin tool cousin | ⚠️ Partial |

**Tier-1 Requirement:** SMB lateral movement is one of the highest value composites.

---

# TA0010 — Exfiltration

## Ecosystem: Data Staging + Clipboard + Unusual Transfers

| Composite Rule | Truth Anchor | Cousin Needed | Status |
|--------------|-------------|--------------|--------|
| **Clipboard Data Exfil Behaviour** | Clipboard → outbound transfer chain | Browser extension cousin | 🧪 POC |
| **NTDS Staging + Outbound Transfer** | Sensitive file staging + rare outbound | Cloud sync cousin | 🔜 TODO |

---

# TA0011 — Command & Control

## Ecosystem: Named Pipes + Beaconing + EtherRAT Blockchain C2

| Composite Rule | Truth Anchor | Reinforcement | Status |
|--------------|-------------|--------------|--------|
| **Named Pipe C2 Composite (High Value)** | Rare pipe creation + suspicious parent | SMB + service convergence | 🧪 Advanced POC |
| **Suspicious Outbound Connection Composite** | Rare outbound IP + low prevalence | New ASN cousin | ⚠️ Partial |
| **EtherRAT Blockchain RPC C2** | Beaconing to blockchain RPC infra | Non-dev host + loader chain | 🧪 Tier-3 |
| **DNS Tunnel Cousin (Missing Baseline)** | Abnormal DNS volume/entropy | Required enterprise cousin | 🔜 MUST BUILD |

**Tier-2 Priority:** C2 is noisy — must rely on prevalence + convergence.

---

# TA0040 — Impact

## Ecosystem: Ransomware + Destructive Behaviour

| Composite Rule | Truth Anchor | Cousin Needed | Status |
|--------------|-------------|--------------|--------|
| **Mass File Encryption Behaviour** | File rewrite velocity + entropy | Shadow deletion cousin | 🔜 TODO |
| **Service Stop + Backup Destruction** | vssadmin + backup deletion chain | Hyper-V cousin | 🔜 TODO |

---

# 4. Current State Summary

## Tier-1 Backbone (Enterprise Mandatory)

✅ SMB Service Lateral Execution  
✅ Registry Persistence Core  
✅ OAuth Consent Abuse  
✅ Rundll32 Proxy Execution  

## Tier-2 Expansion (Next Build Priority)

🔜 WMI + WinRM lateral cousins  
🔜 DNS tunneling baseline  
🔜 Service persistence + driver cousin  
🔜 Full LSASS + NTDS composite hardening  

## Tier-3 Actor Ecosystems (Parked POC)

🧪 SilverFox / ValleyRAT BYOVD Chain  
🧪 EtherRAT Blockchain C2  
🧪 React2Shell / WebRCE ecosystems  
🧪 Polymorphic + Stego loaders  

---

# 5. Engineering Lifecycle (Detection-as-Code)

All composites follow:

1. Minimum Truth Anchor  
2. Reinforcement Joins  
3. Noise Suppression Gates  
4. Org Prevalence Scoring  
5. MITRE Mapping  
6. SOC Directive Output  
7. ADX Pressure Testing  
8. Promotion Gate → Tier-1 Deployable Rule

---

# END STATE VISION

A complete Microsoft-native detection program where:

- Tier-1 provides enterprise backbone  
- Tier-2 provides convergence escalation  
- Tier-3 provides emerging threat agility  

**Composite detection is not alert spam.  
It is engineered defensive depth.**

---
