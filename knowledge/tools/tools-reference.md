# Tools Reference

## Reconnaissance Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| subfinder | Subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| amass | Attack surface mapping | `go install github.com/owasp-amass/amass/v4/...@master` |
| nmap | Port scanning | `apt install nmap` |
| masscan | Fast port scanning | `apt install masscan` |
| nuclei | Vulnerability scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |

## Web Testing Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| feroxbuster | Directory bruteforcing | `cargo install feroxbuster` |
| ffuf | Fuzzing | `go install github.com/ffuf/ffuf/v2@latest` |
| burpsuite | Web proxy | Download from PortSwigger |
| sqlmap | SQL injection | `pip install sqlmap` |
| wpscan | WordPress scanning | `gem install wpscan` |

## Exploitation Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| metasploit | Exploitation framework | `apt install metasploit-framework` |
| cobalt-strike | C2 framework | Commercial |
| sliver | C2 framework | `go install github.com/BishopFox/sliver@latest` |
| impacket | Windows network tools | `pip install impacket` |

## Post-Exploitation Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| mimikatz | Credential extraction | Built-in with CS/Sliver |
| bloodhound | AD enumeration | `apt install bloodhound` |
| crackmapexec | SMB enumeration | `pip install crackmapexec` |
| evil-winrm | WinRM shell | `gem install evil-winrm` |

## OSINT Tools

| Tool | Purpose | API Key Required |
|------|---------|------------------|
| Shodan | Internet scanning | Yes |
| Hunter.io | Email discovery | Yes |
| SecurityTrails | DNS history | Yes |
| BuiltWith | Tech fingerprinting | No |
| LinkedIn | Employee discovery | No |
