# XPOSE SECURITY — OPSEC PROCEDURES
## Operational Security Guidelines voor Red Team Operators

**Classificatie:** STRIKT VERTROUWELIJK  
**Versie:** 1.0 | Januari 2026

---

# 1. OPSEC FUNDAMENTALS

## 1.1 Core Principles

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    THE 5 RULES OF RED TEAM OPSEC                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. ASSUME YOU'RE BEING WATCHED                                             │
│     → All network traffic is logged                                        │
│     → EDR is capturing everything                                          │
│     → Blue team may be observing                                           │
│                                                                             │
│  2. MINIMIZE FOOTPRINT                                                      │
│     → Only actions necessary for objective                                 │
│     → No unnecessary enumeration                                           │
│     → Clean up when possible                                               │
│                                                                             │
│  3. BLEND IN                                                                │
│     → Use tools/techniques common in environment                           │
│     → Match timing to business hours                                       │
│     → Mimic legitimate user behavior                                       │
│                                                                             │
│  4. COMPARTMENTALIZE                                                        │
│     → Different infrastructure per engagement                              │
│     → No cross-contamination of data                                       │
│     → Isolate high-risk activities                                         │
│                                                                             │
│  5. DOCUMENT EVERYTHING                                                     │
│     → Every action timestamped                                             │
│     → Full audit trail                                                     │
│     → Evidence for reporting AND deconfliction                             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

> **📘 UITLEG:**
> OPSEC (Operational Security) beschermt:
> - De engagement (niet gedetecteerd worden)
> - De operator (geen persoonlijke exposure)
> - Het bedrijf (geen reputatieschade)
> - De client (geen data leaks)

---

# 2. INFRASTRUCTURE OPSEC

## 2.1 Server Setup

```bash
# Server OPSEC Checklist

# 1. Anonymous provisioning
☐ Server via crypto betaald
☐ Geen persoonlijke info bij registratie
☐ Fake bedrijfsnaam indien nodig

# 2. Network isolation
☐ Dedicated VPN voor admin access
☐ SSH key-only, non-standard port
☐ Firewall: default deny

# 3. Logging hygiene
☐ Bash history disabled
export HISTSIZE=0
export HISTFILESIZE=0
unset HISTFILE

# 4. Timezone
☐ Server timezone ≠ operator timezone
sudo timedatectl set-timezone UTC

# 5. Automatic destruction
☐ Dead man's switch (optional)
☐ Easy destroy procedure ready
```

> **📘 UITLEG:**
> **Server OPSEC doelen:**
> - Niet traceerbaar naar operator/bedrijf
> - Moeilijk te forensisch analyseren
> - Snel te vernietigen indien nodig

---

## 2.2 Domain OPSEC

```yaml
Domain Registration:
  Registrar: Privacy-focused (Njalla, Porkbun)
  WhoisGuard: ENABLED
  Registration Info: Generic/Anonymous
  Payment: Crypto or prepaid card
  
Domain Aging:
  Minimum Age: 30 dagen voor engagement
  Categorization: Submit to Bluecoat/Symantec 2 weken voor engagement
  Content: Placeholder business website
  
Domain Naming:
  Good Examples:
    - cdn-static-content.com
    - api-analytics-service.com
    - cloud-telemetry-data.net
  
  Bad Examples:
    - xpose-c2-server.com (obvious)
    - hack-target-corp.com (obvious)
    - totally-legitimate.com (suspicious)
```

> **📘 UITLEG:**
> **Domain OPSEC:**
> - Nieuwe domeinen worden vaak geblokkeerd
> - Categorisatie maakt domain "trusted"
> - Generic namen vallen minder op in logs

---

# 3. COMMUNICATION OPSEC

## 3.1 Internal Team Communication

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ APPROVED COMMUNICATION CHANNELS                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│ ENCRYPTED MESSAGING (Team Communication):                                   │
│ ✓ Signal — Primary, disappearing messages ON                               │
│ ✓ Wire — Alternative, EU-based                                             │
│ ✗ WhatsApp — Metadata verzameling                                          │
│ ✗ Telegram — Encryption niet default                                       │
│ ✗ Slack — Logs, niet E2E encrypted                                         │
│                                                                             │
│ ENCRYPTED EMAIL:                                                            │
│ ✓ ProtonMail — E2E encrypted                                               │
│ ✓ Tutanota — E2E encrypted                                                 │
│ ✗ Gmail — Not encrypted, scanned                                           │
│                                                                             │
│ FILE SHARING:                                                               │
│ ✓ Tresorit — Zero-knowledge encrypted                                      │
│ ✓ SpiderOak — Zero-knowledge encrypted                                     │
│ ✗ Dropbox — Not E2E encrypted                                              │
│ ✗ Google Drive — Not E2E encrypted                                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 3.2 Client Communication Rules

```markdown
# CLIENT COMMUNICATION OPSEC

DO:
✓ Use client's preferred secure channel
✓ Encrypt all reports before sending
✓ Use codenames for engagement (not client name)
✓ Verify recipient before sending sensitive info
✓ Delete communications after engagement

DON'T:
✗ Send credentials via unencrypted email
✗ Discuss specifics on phone/SMS
✗ Use client's real name in infrastructure
✗ Share findings with unauthorized parties
✗ Store client data on personal devices
```

---

# 4. OPERATIONAL OPSEC

## 4.1 Pre-Engagement Checklist

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ PRE-ENGAGEMENT OPSEC CHECKLIST                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│ INFRASTRUCTURE:                                                             │
│ ☐ Fresh VPS deployed (no reuse from other engagements)                     │
│ ☐ Domains aged and categorized                                             │
│ ☐ SSL certificates valid                                                   │
│ ☐ C2 profiles match target environment                                     │
│ ☐ Redirectors configured and tested                                        │
│                                                                             │
│ OPERATOR WORKSTATION:                                                       │
│ ☐ Clean VM/container for engagement                                        │
│ ☐ No personal accounts logged in                                           │
│ ☐ VPN to infrastructure active                                             │
│ ☐ Browser fingerprint checked                                              │
│                                                                             │
│ DOCUMENTATION:                                                              │
│ ☐ ROE signed and accessible                                                │
│ ☐ Get out of jail letter ready (if physical)                               │
│ ☐ Emergency contacts saved                                                 │
│ ☐ Logging enabled for all activities                                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 4.2 During Operations

### Beacon OPSEC

```yaml
Beacon Configuration:
  Sleep Time:
    Initial Foothold: 60-300 seconds
    Long-term: 3600+ seconds (1 hour)
    Active Operations: 10-30 seconds
  
  Jitter:
    Minimum: 25%
    Recommended: 40-50%
  
  User-Agent:
    Match: Target's browser statistics
    Update: If target environment changes
  
  Working Hours:
    Default: 08:00 - 18:00 target timezone
    Reason: Beacon activity during business hours is normal

Process Injection:
  Preferred Targets:
    - svchost.exe (many instances, normal)
    - RuntimeBroker.exe (common)
    - explorer.exe (user context)
  
  Avoid:
    - Unique processes (forensically interesting)
    - Security software processes
    - System critical processes
```

> **📘 UITLEG:**
> **Beacon OPSEC:**
> - Hoge jitter voorkomt pattern detection
> - Sleep during off-hours voorkomt alerts
> - Process injection in common processes = blend in

### Activity OPSEC

```markdown
# OPERATIONAL ACTIVITY GUIDELINES

RECONNAISSANCE:
✓ DO: Use target's own tools (net, nltest, dsquery)
✗ DON'T: Upload BloodHound.exe to disk (use in-memory)
✗ DON'T: Scan entire network at once (spread over time)

CREDENTIAL ACCESS:
✓ DO: Wait for high-value target before Mimikatz
✓ DO: Use comsvcs.dll method (native, less detected)
✗ DON'T: Run Mimikatz on first compromised host
✗ DON'T: DCSync immediately after getting DA (wait, validate)

LATERAL MOVEMENT:
✓ DO: Use legitimate admin tools (RDP, WMI, PowerShell remoting)
✓ DO: Move during business hours
✗ DON'T: PSExec to 50 hosts at once
✗ DON'T: Use same technique repeatedly

DATA EXFILTRATION:
✓ DO: Small amounts, encrypted, over HTTPS
✓ DO: Use legitimate cloud services (blends in)
✗ DON'T: Large transfers in one go
✗ DON'T: Use obviously suspicious domains
```

## 4.3 Post-Engagement

```bash
# POST-ENGAGEMENT CLEANUP

# 1. Remove all persistence
☐ Delete scheduled tasks created
☐ Remove registry modifications
☐ Delete dropped files
☐ Remove created accounts
☐ Document all cleanup actions

# 2. Verify removal
☐ Re-enumerate to confirm no artifacts
☐ Check common persistence locations
☐ Validate with BloodHound (no new paths)

# 3. Infrastructure
☐ Export all logs
☐ Backup any needed data (encrypted)
☐ Destroy all servers: terraform destroy
☐ Domains: park or release

# 4. Local cleanup
☐ Delete engagement VM/container
☐ Secure wipe of any local data
☐ Clear browser history if used

# 5. Documentation
☐ Full activity log preserved
☐ Evidence screenshots backed up
☐ Report drafted
```

---

# 5. PERSONAL OPSEC

## 5.1 Operator Identity Protection

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ PERSONAL OPSEC RULES                                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│ NEVER:                                                                      │
│ • Use personal email for infrastructure                                    │
│ • Use personal phone number for registration                               │
│ • Access infrastructure from home IP without VPN                           │
│ • Mix personal and engagement activities on same device                    │
│ • Discuss engagement details on social media                               │
│ • Store client data on personal devices                                    │
│                                                                             │
│ ALWAYS:                                                                     │
│ • Use dedicated engagement VM/device                                       │
│ • Access through VPN/Tor                                                   │
│ • Use separate browser profile                                             │
│ • Use pseudonymous accounts for tool downloads                             │
│ • Separate work and personal activities                                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 5.2 Workstation Setup

```bash
# SECURE OPERATOR WORKSTATION

# Dedicated engagement VM
# OS: Kali Linux or Ubuntu + tools
# Snapshot: Clean state before each engagement

# Network isolation
# All traffic through VPN to infrastructure
# No direct internet access

# Browser hardening
# Separate Firefox profile per engagement
# uBlock Origin
# User-agent spoofing
# Canvas/WebGL fingerprint protection

# Credential management
# KeePassXC for all engagement passwords
# Different password per engagement
# 2FA where possible

# Encrypted storage
# LUKS full disk encryption
# Veracrypt container for client data
```

---

# 6. INCIDENT RESPONSE (OPSEC FAILURES)

## 6.1 If Detected by Blue Team

```markdown
# DETECTION RESPONSE PROTOCOL

IMMEDIATE (First 5 minutes):
1. STOP all active operations
2. Document current state
3. Note detection indicators
4. Assess: Is this a drill or real detection?

IF ENGAGEMENT CONTINUES (test detection):
1. Note detection method
2. Continue per ROE
3. Document for report

IF ENGAGEMENT PAUSES:
1. Contact client emergency number
2. Provide situation summary
3. Await instructions
4. Preserve all logs

IF ENGAGEMENT TERMINATES:
1. Document everything
2. Begin cleanup (per ROE)
3. Preserve evidence for report
4. Debrief with team
```

## 6.2 If Contacted by Authorities

```markdown
# LAW ENFORCEMENT CONTACT PROTOCOL

IMMEDIATE:
1. Remain calm and professional
2. Do NOT delete anything
3. Do NOT lie

VERIFY:
1. Request identification
2. Note badge numbers, names
3. Ask what this is regarding

COMMUNICATE:
1. "I may be involved in authorized security testing"
2. "I have documentation authorizing this activity"
3. "I'd like to contact my employer before proceeding"
4. "I'd like to have legal counsel present"

PROVIDE (if applicable):
1. Get Out of Jail letter
2. Emergency contact for client
3. Your identification

DO NOT:
✗ Admit to anything beyond "authorized testing"
✗ Provide technical details without legal counsel
✗ Allow access to devices without warrant
✗ Discuss other engagements/clients
```

---

# 7. OPSEC CHECKLIST SUMMARY

```
═══════════════════════════════════════════════════════════════════════════════
                    OPSEC QUICK REFERENCE CARD
═══════════════════════════════════════════════════════════════════════════════

PRE-ENGAGEMENT:
☐ Fresh infrastructure deployed
☐ Domains aged and categorized  
☐ ROE and authorization ready
☐ Clean operator VM prepared
☐ Logging configured

DURING ENGAGEMENT:
☐ VPN active at all times
☐ Beacon jitter > 25%
☐ Activity during business hours
☐ Using native tools where possible
☐ Documentation ongoing

COMMUNICATION:
☐ Signal for team chat
☐ ProtonMail for email
☐ Encrypted file sharing
☐ No client names in logs

POST-ENGAGEMENT:
☐ All persistence removed
☐ Infrastructure destroyed
☐ Local data wiped
☐ Logs backed up encrypted

EMERGENCY:
☐ Stop operations immediately
☐ Contact client emergency contact
☐ Preserve evidence
☐ Await instructions

═══════════════════════════════════════════════════════════════════════════════
```

---

**EINDE OPSEC PROCEDURES**

