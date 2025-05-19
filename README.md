# Threat Hunt Report: Suspicious User Account Creation
- [Scenario Creation](https://github.com/huyrocks123/threat-hunting-scenario-task-scheduler/blob/main/threat-hunting-scenario-unauthorized-task-scheduler-persistence-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Scenario

The Security Operations Center (SOC) received an alert about potential unauthorized user account creation on a corporate endpoint. Anomalies in user account management activities raised suspicion of a malicious actor attempting to create backdoor accounts or escalate privileges through built-in Windows commands.

The goal was to detect, analyze, and confirm unauthorized or suspicious local user account creations or modifications, which may indicate persistence or privilege escalation attempts by an attacker.

### High-Level TOR-Related IoC Discovery Plan

- **Check DeviceProcessEvents** for suspicious usage of net user and net localgroup commands executed by cmd.exe or powershell.exe with unusual parameters.

---

## Steps Taken

### 1. Verified Suspicious net user and net localgroup Command Execution in DeviceProcessEvents

Identified execution of the command "net.exe" user hack /add run by user huy at 2025-05-18T23:59:02.2221672Z, which created a new local user account named hack on device huy. Shortly after, the command "net.exe" localgroup administrators hack /add was executed by the same user huy at 2025-05-18T23:59:18.6012983Z, adding the hack user to the local Administrators group. These actions indicate user account creation and privilege escalation consistent with known attacker persistence tactics.

**Query used to locate event:**

kql
```kql
DeviceProcessEvents
| where DeviceName == "huyt"
| where ProcessCommandLine has ("net.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

<img width="1015" alt="Screenshot 2025-05-18 at 8 27 08 PM" src="https://github.com/user-attachments/assets/270b6bd1-8cba-467f-91e9-f34286c64a36" />

---

## Chronological Event Timeline 

### 1. Local User Account Creation Command

- **Timestamp:** 2025-05-18T23:59:02.2221672Z
- **Event:** User huy executed "net user hack /add" command via powershell.exe.
- **Action:** Suspicious user account creation detected.
- **Initiating Process:** powershell.exe

### 2. User Added to Administrators Group

- **Timestamp:** 2025-05-18T23:59:18.6012983Z
- **Event:** User huy executed "net localgroup administrators hack /add" command via powershell.exe.
- **Action:** Elevated privileges for attackerAccount detected.
- **Initiating Process:** powershell.exe

---

## Summary

The investigation confirmed that user huy executed two suspicious commands on device huyt that suggest unauthorized local account creation and privilege escalation. At 2025-05-18T23:59:02.2221672Z, the command "net user hack /add" was executed, creating a new local user account named hack. Shortly after, at 2025-05-18T23:59:18.6012983Z, the command "net localgroup administrators hack /add" was executed, adding the hack user to the local Administrators group. Both commands were run via powershell.exe, indicating deliberate activity rather than standard administrative behavior. This sequence of events is aligned with known attacker techniques for establishing persistence and elevating privileges on compromised systems.

---

## Response Taken

- Log Review & Verification: Confirmed execution of account creation and privilege escalation commands through DeviceProcessEvents in Microsoft Defender for Endpoint.
- User Activity Investigation: An internal investigation was initiated to determine if the actions by user huy were authorized. This included checking recent ticketing system activity and user access approvals.
- Access Revocation: Temporarily revoked administrative privileges for the hack account and the user huy, pending investigation outcome.
- Alert Tuning & Detection Engineering: Implemented and tested new alerting rules for suspicious use of net.exe commands involving account creation and group modification.
- Endpoint Hardening: Reviewed endpoint for additional persistence mechanisms, unauthorized accounts, or signs of lateral movement.
- Audit Trail Preservation: Collected and preserved logs and event timelines for forensic purposes in case of follow-up investigation or incident escalation.
  
---


