# Detection Coverage Heatmap & Engineering Backlog
**Framework:** Minimum Truth → Composite → Reinforcement → Novel Threat Absorption  
**Author:** Ala Dabat

This repository is not a collection of random hunts.  
It is a structured detection coverage program built around **Attack Surface Ecosystems**.

We do not build detections by MITRE tactic.  
We build by **Truth Domain + Ecosystem Boundary**, then mature each ecosystem in layers.

---

## Coverage Heatmap (Tier-1 Enterprise Attack Ecosystems)

# ✅ Coverage Heatmap — Enterprise Attack Ecosystems (Composite Framework)

This repository is structured as a **detection coverage architecture**, not a flat MITRE checklist.

Rules are grouped by **Attack Surface Ecosystem**, using the doctrine:

> **Minimum Truth → Reinforcement → Noise Suppression → Composite Confidence**

We classify maturity into three operational tiers:

- **Tier-1** = Baseline enterprise coverage (must exist everywhere)
- **Tier-2** = Advanced composite correlation (higher fidelity, contextual joins)
- **Tier-3** = Novel / research threats (POCs, emerging attacker tradecraft)

---

## 🟩 Tier-1 Baseline Pack (Enterprise Mandatory Ecosystems)

These are the **minimum required behavioural ecosystems** for any regulated enterprise (finance, insurance, gov).

> Always-on coverage. High-value truths. SOC-safe baselines.

| Ecosystem | Minimum Truth Sensor (Baseline) | Composite Hunt Built | Reinforcement Tuned | Atomic Validated | Maturity |
|----------|--------------------------------|----------------------|---------------------|------------------|----------|
| **PowerShell Execution & Abuse** | Script execution + encoded/runtime intent | ✅ Yes | ⚠️ Partial | ⚠️ In Progress | MED |
| **Registry Autoruns (Run/RunOnce)** | RegistryValueSet on logon trigger keys | ✅ Yes | ✅ Strong | ✅ Tested | HIGH |
| **Scheduled Tasks (CLI Creation)** | `schtasks.exe /create` process truth | ✅ Yes | ✅ Strong | ✅ Tested | HIGH |
| **Scheduled Tasks (Silent TaskCache)** | TaskCache persistence without schtasks.exe | ✅ Yes | ⚠️ Needs Noise Calibration | ⚠️ In Progress | MED |
| **Service Persistence (ImagePath)** | Service registry ImagePath modification | ⚠️ Partial | ❌ Not Tuned | ❌ Not Yet | LOW |
| **Credential Access (LSASS Surface)** | LSASS access/dump behavioural truth | ✅ Yes | ⚠️ Partial | ⚠️ In Progress | MED |
| **NTDS / SAM Extraction** | Hive/NTDS interaction truth | ✅ Yes | ⚠️ Partial | ❌ Not Yet | MED |
| **LOLBins Proxy Execution Core** | Signed binary misuse surface | ✅ Yes | ⚠️ Needs Baselines | ❌ Not Yet | MED |
| **Cloud Identity Persistence (OAuth Consent)** | High-risk scope grant baseline truth | ✅ Yes | ✅ Strong | ⚠️ Tenant Validation Needed | HIGH |

---

## 🟨 Tier-2 Composite Correlation Pack (Senior Threat Hunting Layer)

Tier-2 introduces:

- Multi-surface joins  
- Prevalence reinforcement  
- Kill-chain convergence  
- Noise suppression through context  

These are **SOC-safe composites** built on Tier-1 truths.

| Ecosystem | Minimum Truth Anchor | Composite Reinforcement Layer | Status | Maturity |
|----------|----------------------|------------------------------|--------|----------|
| **Registry Hijacks (IFEO/COM/AppInit)** | Execution interception registry truth | Writable DLL + rare writer + untrusted signer | ⚠️ Partial | MED |
| **WMI Persistence + Execution** | Subscription + anomalous consumer truth | Parent lineage break + script consumer scoring | ✅ Built | HIGH |
| **Lateral Movement (SMB Service Exec / PsExec)** | Remote service creation truth | File drop + inbound 445 + rare service binary | ⚠️ Partial | MED |
| **Defense Evasion (Signed LOLBin Chains)** | Trusted parent → LOLBin baseline | Injection + ghost module + beacon reinforcement | ⚠️ POC → Composite | MED |
| **Session / Token Misuse (Post-Consent)** | Token replay baseline truth | ASN+UA divergence + weak auth reinforcement | ✅ Built | HIGH |
| **Ingress Tool Transfer** | Writable staging drop truth | Followed by execution + outbound comms | ⚠️ In Progress | MED |
| **Shadow Copy Destruction (Ransomware Prep)** | vssadmin/wmic delete truth | Multi-tool convergence scoring | ❌ Missing | LOW |
| **Archive Staging + Exfil Prep** | 7z/rar bulk staging truth | Large volume + outbound correlation | ❌ Missing | LOW |

---

## 🟥 Tier-3 Research & Novel Threat Ecosystems (POC + Emerging Tradecraft)

Tier-3 covers:

- Emerging malware ecosystems  
- Patch-resistant persistence chains  
- Novel attacker innovation  

These are not always-on detections yet — they are **attack research sensors**.

| Threat Ecosystem | Research Truth Anchor | Status | Notes |
|-----------------|----------------------|--------|------|
| **React2Shell / IIS Exploit Chains** | Web process → CLR abuse → injection | ✅ Modelled | Requires telemetry hardening |
| **EtherRAT / Blockchain C2** | RPC beaconing + low-prevalence infra | ✅ Documented | Network correlation expansion needed |
| **SilverFox / ValleyRAT BYOVD** | Signed loader → sideload → driver load truth | ⚠️ Advanced Composite | Needs DriverLoadEvent validation |
| **Pulsar RAT Injection + Tasks** | Trusted parent → LOLBin → memory exec | 🟡 Parked POC | Awaiting confirmed ecosystem truth |
| **Kernel Driver Abuse (BYOVD)** | Driver service creation + load event | ⚠️ Partial | High impact, tuning required |
| **Supply Chain Behaviour Modelling** | Signed update → anomaly divergence | ✅ Threat Modelled | Tier-2 rule ownership pending |

---

# 🧭 Repository Architecture Alignment

This ecosystem model maps directly into the GitHub structure:

| Repository | Role in Framework |
|-----------|------------------|
| **Production-READY-Composite-Threat-Hunting-Rules** | Tier-1/Tier-2 deployable composites |
| **Attack-Ecosystems-and-POC** | Tier-3 novel threats + emerging tradecraft |
| **THREAT-MODELLING-SOP-Behavioural-Patch-Resistant-TTPs** | Architectural doctrine + design rules |

---

# 🚀 Operational Roadmap

1. **Lock Tier-1 Baselines** (enterprise mandatory truths)  
2. **Expand Tier-2 Correlation** (joins, prevalence, convergence scoring)  
3. **Maintain Tier-3 Research** (future threat ecosystems + innovation)  
4. **Incidents stitch the narrative** — composites remain clean sensors  

> **The rule is the sensor. The incident is the attack story.**
|

---

## Engineering Backlog (Next Highest-Value Gaps)

### Priority 1 — Baseline Completion (Non-Negotiable Truth Sensors)
- [ ] Service Persistence Composite (T1543.003) — hardened ImagePath + signer logic  
- [ ] Task Creation Event Composite (4698) — timeline truth independent of method  
- [ ] Registry Payload Stash Detection — large script blobs in non-standard keys  

### Priority 2 — Reinforcement & Noise Convergence
- [ ] TaskCache noise suppression (browser updaters, OneDrive, Intel)  
- [ ] COM Hijack allowlists by vendor + expected DLL paths  
- [ ] LSASS dumping rarity + signer + parent convergence  

### Priority 3 — Novel Threat Absorption Layer
- [ ] Stego Loader Ecosystem → Initial Access → Script Host → C2  
- [ ] EtherRAT / Lumma tradecraft mapped onto existing PowerShell + Persistence composites  
- [ ] ClickFix / Clipboard stagers as modern Stage-0 reinforcement  

---

## Rule Architecture Standard (Mandatory)

Every Composite Hunt must output:

- **MinimumTruth** (why this attack can exist)
- **ReinforcementSignals** (why confidence increases)
- **RiskScore + Severity**
- **HunterDirective** (SOC action, not theory)

Detection rules are sensors.  
Incidents stitch sensors into narratives.

---
