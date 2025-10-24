# SIEM Setup and Detection Lab

## Objective
Deploy a functional Security Information and Event Management (SIEM) environment using Splunk Enterprise on Windows Server 2022, integrate native Windows logs and Sysmon telemetry, and develop baseline detection searches for authentication failures, PowerShell activity, and network connections.

## Topology or Environment
- Host: Windows Server 2022 VM (e.g., SPLUNK-VM)
- Tools: Splunk Enterprise 9.x, Sysmon v15.15
- Data Sources: Windows Security, System, Application Event Logs; Sysmon Operational Log
- Network: Bridged adapter; Splunk Web accessible from host via `http://<VM-IP>:8000`

---

## Configuration Steps

### Step 1 – Install Splunk Enterprise
- Installed Splunk Enterprise on Windows Server 2022 VM.
- Verified Splunk Web accessibility at `http://localhost:8000`.
- Enabled automatic service start on boot.

Artifacts:
- ![Splunk Home](./screenshots/splunk_home_2025-10-23.png)
- ![Server Settings](./screenshots/server_settings_2025-10-23.png)

### Step 2 – Enable Windows Event Log Ingestion
- Configured inputs for Security, System, and Application logs via `inputs.conf`.
- Verified ingestion with:
```
index=main sourcetype=WinEventLog:* earliest=-15m
```
- Configuration file: [config/inputs.conf](./config/inputs.conf)

Artifacts:
- ![Data Inputs](./screenshots/data_inputs_2025-10-23.png)
- ![WinEventLog Search](./screenshots/wineventlog_search_2025-10-23.png)

### Step 3 – Install and Integrate Sysmon
- Installed Sysmon using a baseline configuration (e.g., SwiftOnSecurity).
- Registered the Sysmon event manifest to create `Microsoft-Windows-Sysmon/Operational`.
- Verified Event IDs 1 (Process Create) and 3 (Network Connect) in Event Viewer and Splunk.
- Configuration file: [config/sysmonconfig.xml](./config/sysmonconfig.xml)

Artifacts:
- ![Sysmon in Event Viewer](./screenshots/sysmon_eventviewer_2025-10-23.png)
- ![Sysmon Search in Splunk](./screenshots/sysmon_search_2025-10-23.png)

---

## Verification and Testing
Confirm the following searches return results in Splunk.

Windows Event Logs:
```
index=main sourcetype=WinEventLog:* earliest=-15m
```

Sysmon Process Create (Event ID 1):
```
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-15m
```

Sysmon Network Connect (Event ID 3):
```
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 earliest=-15m
```

---

## Detection Searches and Reporting

### 1. Failed Logon Analysis (Security Event ID 4625 / 4624)
Purpose: Detect failed authentication attempts by account and source; correlate failed attempts followed by a success.

SPL files:
- [queries/failed_logons_by_account.splunkql.txt](./queries/failed_logons_by_account.splunkql.txt)
- [queries/failed_then_success_correlation.splunkql.txt](./queries/failed_then_success_correlation.splunkql.txt)

Screenshots:
- ![Failed Logons Search](./screenshots/failed_logons_search.png)
- ![Failed Then Success Search](./screenshots/failed_then_success_search.png)

### 2. Suspicious PowerShell Execution (Sysmon Event ID 1)
Purpose: Identify PowerShell processes and flag encoded command usage.

SPL used for screenshot:
```
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*powershell.exe*"
| eval Encoded=if(match(CommandLine,"-enc"),"Yes","No")
| table _time Computer User Image CommandLine Encoded
| sort - _time
```

Saved as: [queries/powershell_suspicious_activity.splunkql.txt](./queries/powershell_suspicious_activity.splunkql.txt)

Screenshot:
- ![PowerShell Suspicious Search](./screenshots/powershell_suspicious_search.png)

### 3. Sysmon Network Connections (Event ID 3)
Purpose: Display outbound network activity by process and destination IP; highlight non-RFC1918 destinations.

Primary SPL:
```
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 earliest=-1h
| stats count by Image, DestinationIp, DestinationPort, Protocol, User
| sort - count
```

Saved as: [queries/sysmon_networkconnections.splunkql.txt](./queries/sysmon_networkconnections.splunkql.txt)

Screenshot:
- ![Sysmon Network Connections](./screenshots/sysmon_networkconnections_search.png)

---

## Analysis
- Splunk aggregates Windows and Sysmon telemetry for host and network visibility.
- 4625/4624 correlation surfaces probable brute-force attempts.
- Sysmon Event IDs 1 and 3 provide process lineage and outbound connection context.
- PowerShell detection flags encoded or potentially obfuscated script execution.
- Network connection review highlights external destinations that may indicate command-and-control or exfiltration.

---

## Troubleshooting Notes
- The “Local event log collection” GUI link in Splunk may be deprecated; configure inputs via `inputs.conf`.
- Sysmon event manifest may require manual registration:
```
.\Sysmon64.exe -m
```
- ICMP (ping) does not generate Event ID 3. Use a TCP/UDP action (for example, `Invoke-WebRequest https://www.google.com`) to produce network connection events.
- Ensure Splunkd runs as Local System to read Windows Event Logs.

---

## Deliverables
- Splunk configuration: [config/inputs.conf](./config/inputs.conf)
- Sysmon configuration: [config/sysmonconfig.xml](./config/sysmonconfig.xml)
- Queries (SPL): files under [queries/](./queries/)
- Screenshots: files under [screenshots/](./screenshots/)
- Optional exports (CSV): files under [exports/](./exports/)

---

## References
- Splunk Enterprise documentation
- Sysmon (Sysinternals) documentation
- Community Sysmon configuration (e.g., SwiftOnSecurity sysmon-config)
