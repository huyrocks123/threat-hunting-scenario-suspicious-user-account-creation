# Threat Event (Suspicious User Account Creation)
**Detection of Unauthorized Local User Account Creation or Modification**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Opens a command prompt or PowerShell with elevated privileges.
2. Runs net user hacker /add command to create a new user.
3. Adds the user to the local Administrators group using net localgroup administrators hacker /add.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|	https://learn.microsoft.com/en-us/defender-xdr/deviceprocessevents-table |
| **Purpose**| 	To detect execution of suspicious net user or net localgroup commands. |

---

## Related Queries:
```kql
// Detect 'net user' and 'net localgroup' commands used for account creation or modification
DeviceProcessEvents
| where DeviceName == "huyt"
| where FileName in ("cmd.exe", "powershell.exe")
| where ProcessCommandLine has_any ("net user", "net localgroup")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

---

## Created By:
- **Author Name**: Huy Tang
- **Author Contact**: https://www.linkedin.com/in/huy-t-892a51317/
- **Date**: May 18, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | May 18, 2025  | Huy Tang  
