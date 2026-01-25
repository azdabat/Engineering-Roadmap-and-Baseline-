# Detection Coverage Heatmap & Engineering Backlog
**Framework:** Minimum Truth → Composite → Reinforcement → Novel Threat Absorption  
**Author:** Ala Dabat

This repository is not a collection of random hunts.  
It is a structured detection coverage program built around **Attack Surface Ecosystems**.

We do not build detections by MITRE tactic.  
We build by **Truth Domain + Ecosystem Boundary**, then mature each ecosystem in layers.

---

## Coverage Heatmap (Tier-1 Enterprise Attack Ecosystems)

| Ecosystem | Minimum Truth Sensor (Baseline) | Composite Hunt Built | Reinforcement Tuned | Atomic Validated | Maturity |
|----------|--------------------------------|----------------------|---------------------|------------------|----------|
| PowerShell Intent & Runtime | ScriptBlock / Command Execution | ✅ Yes | ⚠️ Partial | ⚠️ In Progress | MED |
| Registry Persistence (Run Keys) | RegistryValueSet on Autoruns | ✅ Yes | ✅ Strong | ✅ Tested | HIGH |
| Registry Persistence (Hijacks) | COM / IFEO / AppInit Artifacts | ✅ Yes | ⚠️ Partial | ❌ Not Yet | MED |
| Scheduled Tasks (CLI) | `schtasks.exe /create` Process Truth | ✅ Yes | ✅ Strong | ✅ Tested | HIGH |
| Scheduled Tasks (Silent / TaskCache) | TaskCache Registry Truth | ✅ Yes | ⚠️ Needs Noise Convergence | ⚠️ In Progress | MED |
| Services Persistence | Service ImagePath Registry Truth | ⚠️ Partial | ❌ Not Tuned | ❌ Not Yet | LOW |
| Credential Access (LSASS) | LSASS Access / Dump Tooling | ✅ Yes | ⚠️ Partial | ⚠️ In Progress | MED |
| Credential Access (NTDS/SAM) | NTDS / Hive Interaction Truth | ✅ Yes | ⚠️ Partial | ❌ Not Yet | MED |
| LOLBin Proxy Execution | Signed Binary Misuse Surface | ✅ Yes | ⚠️ Needs Baselines | ❌ Not Yet | MED |
| Lateral Movement (SMB/WMI/DCOM) | Remote Exec Mechanism Truth | ⚠️ Partial | ❌ Not Tuned | ❌ Not Yet | LOW |
| Cloud Identity (OAuth Consent) | High-Risk Scope Grant Truth | ✅ Yes | ✅ Strong | ⚠️ Needs Tenant Validation | HIGH |

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

---# Engineering-Roadmap-and-Baseline-

