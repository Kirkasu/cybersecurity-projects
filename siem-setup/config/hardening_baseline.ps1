# Windows Hardening Baseline for SIEM Host
# Disables guest, renames admin, applies password policies, enables auditing and firewall.

net user Guest /active:no
wmic useraccount where "name='Administrator'" rename "SecAdmin"
net accounts /minpwlen:12 /maxpwage:45 /lockoutthreshold:3 /lockoutwindow:15 /lockoutduration:15
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
New-NetFirewallRule -DisplayName "Allow Splunk Web" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow
AuditPol /set /category:"Logon/Logoff" /success:enable /failure:enable
AuditPol /set /category:"Account Logon" /success:enable /failure:enable
AuditPol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
