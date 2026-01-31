# Reconnaissance - Fase 1

## Passive Reconnaissance

### DNS Enumeration
```bash
# Subdomain enumeration
subfinder -d target.com -all -o subdomains.txt
amass enum -passive -d target.com -o amass_passive.txt

# DNS records
dig target.com ANY +noall +answer
dig target.com MX +short
dig target.com TXT +short
host -t ns target.com

# Zone transfer attempt
dig axfr @ns1.target.com target.com
```

### WHOIS & Historical Data
```bash
whois target.com
# Historical DNS
curl "https://securitytrails.com/domain/target.com/dns"
```

### Certificate Transparency
```bash
# CT logs voor subdomain discovery
curl "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u
```

### Google Dorking
```
site:target.com filetype:pdf
site:target.com filetype:xlsx
site:target.com inurl:admin
site:target.com intitle:"index of"
site:target.com ext:sql | ext:db | ext:log
site:target.com intext:"password" | intext:"credential"
"target.com" site:pastebin.com
"target.com" site:github.com
```

### Shodan/Censys
```bash
shodan search hostname:target.com
shodan host 1.2.3.4

# Censys
censys search "target.com"
```

## Active Reconnaissance

### Port Scanning
```bash
# Quick scan
nmap -sS -sV -O -T4 -p- --min-rate=1000 target.com -oA nmap_full

# Stealth scan
nmap -sS -sV -Pn -T2 --scan-delay 1s target.com

# UDP scan (top ports)
nmap -sU --top-ports 100 target.com

# Version detection
nmap -sV --version-intensity 5 -p 22,80,443,445 target.com
```

### Web Application Discovery
```bash
# Directory brute forcing
feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,asp,aspx,jsp -t 50

# Technology fingerprinting
whatweb -a 3 https://target.com
wappalyzer https://target.com

# WAF detection
wafw00f https://target.com
```

### Virtual Host Discovery
```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://target.com -H "Host: FUZZ.target.com" -mc 200,301,302,403
```

## Output Prioritization

Na recon, prioriteer targets op:
1. **Kritische services**: SSH, RDP, SMB, databases
2. **Webapplicaties**: Login pages, admin panels, APIs
3. **Legacy systems**: Oude software versies
4. **Misconfiguraties**: Open directories, default credentials
