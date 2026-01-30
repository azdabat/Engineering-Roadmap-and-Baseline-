# Enterprise Detection Roadmap (Tier-1 / Tier-2 / Tier-3)
**Author:** Ala Dabat  
**Framework:** *Minimum Truth → Convergence/Reinforcement → Noise Suppression → Scoring/Confidence → SOC Directives*  
**Repos used as source-of-truth:**
- **Production rules:** `Production-READY-Composite-Threat-Hunting-Rules` 0  
- **POC / ecosystems / monoliths:** `Attack-Ecosystems-and-POC` 1  
- **Threat modelling / SOP:** `THREAT-MODELLING-SOP-Behavioural-Patch-Resistant-TTPs-` 2  

---

## Tier definitions (simple + operational)

### Tier-1 — “Enterprise Baseline Coverage”
**Goal:** cover the *unavoidable* attacker steps across MITRE with **high signal anchors** that survive tradecraft changes.  
**Design:** Minimum Truth is strong enough to run daily in a large org. Reinforcement improves confidence, but Tier-1 still works even when one enrichment signal is missing.

### Tier-2 — “Composite Ecosystem Coverage”
**Goal:** cover the *full ecosystem* around Tier-1 anchors (cousins, alternate execution paths, fileless variants, API/COM variants, correlation across tables).  
**Design:** adds more joins + prevalence + baselines + stronger suppression because noise grows.

### Tier-3 — “Campaign / Threat-Specific Modules”
**Goal:** park *named threats / exploit chains* (React2Shell, EtherRAT, SilverFox, etc.) as **POC ecosystems**, then promote pieces to Tier-2 when confirmed.  
**Design:** threat-intel driven. Not required for “baseline enterprise coverage” but becomes a multiplier.

**Status key:** ✅ Production | 🧪 POC | 🔜 Planned

---

## The “Cousin Rules” principle (why this roadmap works)
A **cousin rule** is a *parallel execution path* that attackers swap to bypass a single parent/child assumption, without changing the underlying technique.

Example (you already lived this):
- **Service Execution module:** `services.exe → suspicious child` (quiet, high fidelity)
- **Scheduled Task Execution module:** `svchost.exe (Schedule) → suspicious child` (extremely noisy, needs extra reinforcement)

**Rule of thumb:**
- If the same technique can appear under a different **system “executor”** (services vs schedule vs WMI vs WinRM), that’s a cousin.
- Cousins share the same *Minimum Truth category*, but require different suppression and reinforcement because the baseline noise is different.

---

# TIER-1 ROADMAP (must-have enterprise baseline by MITRE tactic)

> Tier-1 is your “coverage floor”: if an org only ran Tier-1, they still catch real intrusions without drowning.

## TA0002 — Execution

| Composite (Tier-1) | Minimum Truth Anchor | Reinforcement (confidence) | Cousins to plan | Status |
|---|---|---|---|---|
| **PowerShell Intent & Runtime** | PowerShell execution truth (script/command intent) | encoded/obfuscation + LOLBin chain + network + prevalence | `pwsh.exe` vs `powershell.exe`; `rundll32/mshta/wscript` launching PS | ✅/🧪 (based on your current pack) |
| **LOLBins Proxy Execution (Core pack)** | signed binary misuse event | suspicious parent + suspicious path + outbound | per-LOLBin cousins (e.g., mshta vs rundll32 vs regsvr32) | ✅/🧪 |

## TA0003 — Persistence

| Composite (Tier-1) | Minimum Truth Anchor | Reinforcement | Cousins to plan | Status |
|---|---|---|---|---|
| **Registry Persistence — Userland Autoruns** | `RegistryValueSet` in Run/RunOnce/Winlogon/ActiveSetup | danger tokens + writable path + base64 + net + rare writer | HKLM vs HKCU variants; `Explorer` vs `UserInit` triggered chains | ✅ (you have this as production-style) |
| **Registry Persistence — Hijacks/Interception** | IFEO / COM / AppInit / handler hijacks | writable DLL/EXE + scriptlet + rare/untrusted writer | CLSID hijack variants; per-app handler cousins | ✅/🧪 |
| **Scheduled Tasks (CLI)** | `schtasks.exe /create` process truth | XML drop + suspicious action + net/encoded + prevalence | `at.exe` legacy; `powershell Register-ScheduledTask` | ✅ |
| **Scheduled Tasks (Silent TaskCache)** | TaskCache registry truth | blob/net/writable + correlated exec | cousin with task creation via COM/API (no schtasks) | ✅/🧪 |
| **Services Persistence (Registry)** | Services `ImagePath`/service install truth | writable path + untrusted writer + service creation correlation | service creation via API vs sc.exe | ✅/🧪 |

> Atomic alignment examples you’re already covering strongly here: persistence and hijack execution flow families (e.g., service registry hijack patterns). 3

## TA0005 — Defense Evasion

| Composite (Tier-1) | Minimum Truth Anchor | Reinforcement | Cousins | Status |
|---|---|---|---|---|
| **Masquerade / Suspicious Path Execution** | process from user-writable path / renamed system binary | signer mismatch + prevalence + parent anomaly | per-LOLBin cousins | 🔜 |
| **Tamper / Disable Security Controls** | security product/service stop or config change | rare writer + admin context + correlated suspicious exec | GPO vs local registry vs service control | 🔜 |

## TA0006 — Credential Access

| Composite (Tier-1) | Minimum Truth Anchor | Reinforcement | Cousins | Status |
|---|---|---|---|---|
| **LSASS Access / Dump Chains** | LSASS handle access / dump tooling behaviors | suspicious parent + dump path + net + prevalence | comsvcs vs procdump vs silent dumps | ✅/🧪 |
| **NTDS/SAM Extraction** | NTDS / hive interaction truth | VSS creation + staging + exfil signals | `ntdsutil` vs `diskshadow` vs raw copy | ✅/🧪 |

## TA0007 — Discovery (baseline, low-noise variants only)

| Composite (Tier-1) | Minimum Truth Anchor | Reinforcement | Cousins | Status |
|---|---|---|---|---|
| **Discovery Burst → Follow-on** | high-risk discovery tools/commands | proximity to execution/persistence + prevalence | powershell vs native cmds | 🔜 |

## TA0008 — Lateral Movement

| Composite (Tier-1) | Minimum Truth Anchor | Reinforcement | Cousins | Status |
|---|---|---|---|---|
| **SMB + Service Execution (PsExec/Impacket)** | `services.exe` spawning uncommon child | inbound SMB/RPC + admin share drop + prevalence | **Cousin:** Scheduled Task exec via Schedule service | ✅ (you validated this) |
| **Remote Exec (WMI/DCOM/WinRM)** | remote execution mechanism truth | parent chain + network + target process | WMI cousin variants | 🔜/🧪 |

## TA0011 — Command & Control (baseline “must-have”)

| Composite (Tier-1) | Minimum Truth Anchor | Reinforcement | Cousins | Status |
|---|---|---|---|---|
| **HTTPS Jitter Beaconing (low CPU)** | repeated 443 connections to same IP + timing pattern | payload sizing + prevalence + process context | browser-like masquerade cousins | 🧪 |
| **Named Pipe C2 (core)** | named pipe creation/connection truth | SMB pipe correlation + service correlation + rarity | mojo masquerade + fork-n-run + epmapper deception | 🧪 (advanced POC) |

> Atomic baseline philosophy: Tier-1 picks the “most reusable” technique families that are repeatedly validated in Atomic Red Team style testing (execution/persistence/cred access/hijack flows). 4

---

# TIER-2 ROADMAP (ecosystem + cousins + higher-fidelity composites)

> Tier-2 is where you “close the bypasses” and add engineered suppression so the rules survive a real enterprise.

## Lateral Movement Ecosystem (your strongest differentiator)
**Tier-2 Modules**
1) **SMB + Service Exec (services.exe module)**  
- Minimum Truth: `services.exe` spawning uncommon child  
- Reinforcement: inbound 445/135 + admin share drops + prevalence  
- **Noise suppression:** common service children, allow management initiators  
- ✅ Production

2) **SMB + Scheduled Task Exec (Schedule svchost cousin module)**  
- Minimum Truth: `svchost.exe (Schedule) → suspicious child`  
- Reinforcement required (because noise is extreme): inbound SMB/RPC + TaskCache artifacts + task/XML drops + danger tokens + prevalence  
- 🧪 POC (keep it POC until you’re happy with suppression)

3) **Remote Exec cousins** (planned)
- WMIExec/DCOMExec/WinRM variants
- Minimum Truth: remote exec mechanism truth (process + network + auth pattern)
- Reinforcement: same “inbound + execution” story, but different executor/process anchors
- 🔜

## Persistence Ecosystem (already well-built)
- Autoruns (Tier-1) → add cousins (per-key variants, per-writer variants)
- TaskCache (Tier-1/POC) → add correlation to schedule exec + dropper chain
- Services (Tier-1/partial) → add service install telemetry + signer validation + prevalence weighting

## C2 Ecosystem (hardest, keep it engineered)
Tier-2 is where you stop thinking “beaconing alone” and start thinking “convergence lives elsewhere”:
- prevalence rarity (org + host spread)
- process ancestry (initial access → execution → persistence → C2)
- multiple orthogonal signals (pipe + SMB + service creation, etc.)

---

# TIER-3 ROADMAP (threat/campaign ecosystems — keep as POC)
These remain in **Attack-Ecosystems-and-POC** until confirmed + repeatable, then you promote building blocks into Tier-2. 5

| Threat / Ecosystem | Why it’s Tier-3 | What gets promoted to Tier-2 | Status |
|---|---|---|---|
| **React2Shell** | exploit chain specific | the reusable “web-spawn → LOLBin → payload staging” modules | 🧪 |
| **EtherRAT / Blockchain RPC C2** | niche infra + noisy baseline | “unusual RPC provider + process context + prevalence + beaconing shape” | 🧪 |
| **SilverFox / ValleyRAT (sideload + BYOVD)** | campaign/tooling specific | generic “signed loader → untrusted module load → service/driver install → driver load truth” | 🧪 (adjacent to your existing SilverFox work) |
| **Pulsar / scheduled task + .NET injection patterns** | chain specific | the “Schedule cousin module” + memory injection telemetry layer | 🧪 |

---

# “Cousin Map” (what cousin rules you still need)

> This is your **engineering to-do list**: same ecosystem, different executor/noise profile.

| Ecosystem | Primary rule (anchor) | Cousin rule(s) to build | Why cousin exists |
|---|---|---|---|
| Lateral Movement | **SMB + Service Exec** (`services.exe`) | **SMB + Schedule Exec** (`svchost Schedule`) | attacker swaps service exec for scheduled task exec |
| Scheduled Tasks | **CLI create** (`schtasks.exe`) | **Silent TaskCache** (COM/API) | attacker avoids `schtasks.exe` entirely |
| Persistence (Registry) | Autoruns | Winlogon / Active Setup / Policies variants | same persistence goal, different key paths |
| C2 | HTTPS jitter beacon | Named pipe C2 correlation | attackers hide in 443 noise; convergence shifts to execution/persistence signals |
| Execution | PowerShell intent | LOLBin execution cousins | attackers swap initial executor to bypass allowlists |

---

# Promotion Gates (how a POC becomes Production)
A rule moves up tiers only when it passes your framework gates:

1) **Minimum Truth is stable** (won’t disappear with minor attacker changes)  
2) **Reinforcement is additive** (doesn’t redefine truth; increases confidence)  
3) **Noise suppression is structural** (not endless allowlists)  
4) **Scoring behaves in both directions**  
   - rare = prioritise  
   - widespread = deprioritise (but don’t blind yourself)  
5) **Cousin coverage confirmed** (at least one bypass path accounted for)  
6) **ADX/Atomic validation** (POC evidence captured, test notes exist)  

---

# What you should do next (roadmap execution order)
If you want the fastest “enterprise grade” jump:

1) **Lock Tier-1** (finish the baseline floor)
   - Services persistence tuning (bring to HIGH maturity)
   - Credential access (LSASS/NTDS) harden + validate
   - One baseline C2 (HTTPS jitter) with prevalence and suppression

2) **Finish the lateral movement cousin pair**
   - keep `services.exe` rule aggressive (high fidelity)
   - keep `svchost Schedule` rule conservative (correlated + suppressed)

3) **Keep Tier-3 as POC parking**
   - React2Shell / EtherRAT / Pulsar / SilverFox stay as ecosystems
   - only promote reusable modules upward

---

## Notes (so you don’t overthink Tier-1 vs Tier-2)
- Tier-1 is “I can run this every day and not regret it.”
- Tier-2 is “I closed the bypasses and built cousins.”
- Tier-3 is “I can track named threats, but I won’t pretend it’s baseline.”

That’s the whole system.
```6
