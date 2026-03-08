<p align="center">
  <img src="docs/banner.svg" alt="CrowdStrike Falcon Deployment Validation Scanner" width="900"/>
</p>
<p align="center"><strong>Validate your CrowdStrike Falcon EDR deployment for policy gaps, dangerous exclusions, and detection coverage</strong></p>
<p align="center">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/dependencies-zero-brightgreen?style=flat-square"/>
  <img src="https://img.shields.io/badge/checks-40%2B-e8272c?style=flat-square"/>
  <img src="https://img.shields.io/badge/MITRE_ATT%26CK-mapped-ff4d4d?style=flat-square"/>
</p>

---

## Why This Exists

CrowdStrike Falcon is powerful, but misconfiguration is the #1 cause of EDR failures. Common issues include prevention policies left in detect-only mode, overly broad exclusions on temp folders and LOLBins, sensors in RFM with degraded protection, and unassigned policies leaving hosts unprotected. This scanner audits your Falcon configuration exports to find these gaps before attackers do.

## Modules (10)

| # | Module | Key | Checks | Focus |
|---|--------|-----|--------|-------|
| 1 | 🛡️ **Prevention Policy** | `prevention` | 10 | NGAV, ML levels, behavioral IOAs, exploit mitigations, ransomware, scripts, detect-vs-prevent, coverage |
| 2 | 🔄 **Sensor Updates** | `updates` | 4 | Auto-update, pinned versions, version sprawl, uninstall protection |
| 3 | 🔧 **Response Policy** | `response` | 2 | RTR enabled, unrestricted custom scripts |
| 4 | 🔌 **Device Control** | `device` | 2 | USB policies, default allow |
| 5 | ⚠️ **Exclusion Audit** | `exclusions` | 7 | **Dangerous paths** (Temp, AppData, LOLBins), global scope, wildcards, SV exclusions, process exclusions |
| 6 | 💚 **Sensor Health** | `sensors` | 4 | Offline sensors, RFM hosts, stale agents, OS distribution |
| 7 | 👤 **Admin Security** | `admin` | 4 | Admin sprawl, MFA gaps, API scope, RBAC |
| 8 | 🎯 **Custom IOAs** | `ioas` | 2 | Custom IOA rules exist/enabled |
| 9 | 🔥 **Firewall Policy** | `firewall` | 1 | Falcon Firewall configured |
| 10 | 🗺️ **MITRE ATT&CK** | `mitre` | 1 | Top 10 technique coverage vs policy settings |

## Quick Start

```bash
python cs_scanner.py --data-dir ./sample_data --output report.html
python cs_scanner.py --data-dir ./exports --modules prevention exclusions sensors
python cs_scanner.py --data-dir ./exports --severity HIGH
```

### Exporting Falcon Configs
Use the CrowdStrike Falcon API (FalconPy) to export:
```python
from falconpy import PreventionPolicy, SensorUpdatePolicy, HostGroup, Hosts
# Export prevention policies, sensor policies, hosts, exclusions
```
Or manually export JSON from the Falcon console.

## Key Detection Categories

The **Exclusion Audit** (Module 5) is the most critical module — it checks for:
- **Dangerous paths**: C:\Windows\Temp, AppData\Local\Temp, /tmp, C:\ProgramData, entire drives
- **Executable exclusions**: *.exe, *.dll, *.ps1, *.bat — should NEVER be excluded
- **LOLBin process exclusions**: powershell.exe, cmd.exe, mshta.exe, certutil.exe, wscript.exe
- **Global scope**: Exclusions applied to ALL hosts instead of specific groups
- **Sensor Visibility exclusions**: Complete telemetry blind spots (worse than ML exclusions)

## References
- [CrowdStrike — Recommended Prevention Settings](https://falcon.crowdstrike.com)
- [CrowdStrike — Exclusion Best Practices](https://falcon.crowdstrike.com)
- [CrowdStrike — Falcon IT Admin Guide](https://cyberphilearn.com/crowdstrike-falcon-it-admin-guide-2026/)
- [MITRE ATT&CK — Enterprise](https://attack.mitre.org)
- [CrowdStrike — FalconPy SDK](https://www.falconpy.io)

## License
MIT
