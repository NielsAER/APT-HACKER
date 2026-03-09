# ─────────────────────────────────────────────────────────────────────────────
#  GMAIL APP PASSWORD — SMTP email sending route
#
#  No OAuth, no extra packages beyond the standard library.
#
#  Setup (one-time):
#    1. Google Account → Security → 2-Step Verification (must be ON)
#    2. Google Account → Security → App Passwords
#    3. Select app: "Mail", device: "Other" → generate 16-char password
#    4. Add to your .env:
#         GMAIL_ADDRESS=you@gmail.com
#         GMAIL_APP_PASSWORD=xxxx xxxx xxxx xxxx
#
#  Usage in existing code:
#    Call send_email() directly, or hit POST /api/email/send
# ─────────────────────────────────────────────────────────────────────────────

import os
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text      import MIMEText
from email.mime.base      import MIMEBase
from email                import encoders

from flask import request, jsonify


# ── Config ────────────────────────────────────────────────────────────────────

GMAIL_ADDRESS      = os.environ.get("GMAIL_ADDRESS", "")
GMAIL_APP_PASSWORD = os.environ.get("GMAIL_APP_PASSWORD", "").replace(" ", "")  # strip spaces


# ── Core send function (reusable anywhere in your app) ────────────────────────

def send_email(
    to:          str,
    subject:     str,
    html_body:   str,
    from_name:   str  = None,
    reply_to:    str  = None,
    attachments: list = None,   # list of {"filename": str, "data": bytes}
) -> dict:
    """
    Send an email via Gmail SMTP using an App Password.

    Returns {"success": True} or {"success": False, "error": str}
    """
    if not GMAIL_ADDRESS or not GMAIL_APP_PASSWORD:
        return {"success": False, "error": "GMAIL_ADDRESS / GMAIL_APP_PASSWORD not configured"}

    display_from = f"{from_name} <{GMAIL_ADDRESS}>" if from_name else GMAIL_ADDRESS

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = display_from
    msg["To"]      = to
    if reply_to:
        msg["Reply-To"] = reply_to

    msg.attach(MIMEText(html_body, "html"))

    # Optional attachments
    for att in (attachments or []):
        part = MIMEBase("application", "octet-stream")
        part.set_payload(att["data"])
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f'attachment; filename="{att["filename"]}"')
        msg.attach(part)

    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=ctx) as server:
            server.login(GMAIL_ADDRESS, GMAIL_APP_PASSWORD)
            server.sendmail(GMAIL_ADDRESS, to, msg.as_string())
        return {"success": True}
    except smtplib.SMTPAuthenticationError:
        return {"success": False, "error": "Authentication failed — check GMAIL_ADDRESS and GMAIL_APP_PASSWORD"}
    except smtplib.SMTPRecipientsRefused:
        return {"success": False, "error": f"Recipient refused: {to}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── API route ─────────────────────────────────────────────────────────────────

@app.route("/api/email/send", methods=["POST"])
def send_email_route():
    """
    POST /api/email/send
    {
        "to":          "target@example.com",
        "subject":     "Subject line",
        "html":        "<p>Email body HTML</p>",
        "from_name":   "Sarah Johnson",      // optional display name
        "reply_to":    "other@example.com"   // optional
    }
    """
    data = request.json or {}

    to      = (data.get("to") or "").strip()
    subject = (data.get("subject") or "").strip()
    html    = (data.get("html") or "").strip()

    if not to or not subject or not html:
        return jsonify({"error": "to, subject, and html are required"}), 400

    result = send_email(
        to        = to,
        subject   = subject,
        html_body = html,
        from_name = data.get("from_name"),
        reply_to  = data.get("reply_to"),
    )

    if result["success"]:
        return jsonify({"success": True, "message": f"Email sent to {to}"})
    else:
        return jsonify({"error": result["error"]}), 500


@app.route("/api/email/test", methods=["POST"])
def test_email_config():
    """
    POST /api/email/test  — sends a test email to the configured Gmail address itself.
    Useful to verify App Password works before sending to real targets.
    """
    if not GMAIL_ADDRESS or not GMAIL_APP_PASSWORD:
        return jsonify({"error": "GMAIL_ADDRESS / GMAIL_APP_PASSWORD not set"}), 503

    result = send_email(
        to        = GMAIL_ADDRESS,
        subject   = "[XPOSE APT] SMTP Test",
        html_body = "<p>SMTP is working correctly via Gmail App Password.</p>",
        from_name = "XPOSE APT AI",
    )

    if result["success"]:
        return jsonify({"success": True, "message": f"Test email sent to {GMAIL_ADDRESS}"})
    else:
        return jsonify({"error": result["error"]}), 500


# ── Health check addition ─────────────────────────────────────────────────────
# Add "email_configured" to your existing /api/health response:
#
#   "email_configured": bool(GMAIL_ADDRESS and GMAIL_APP_PASSWORD)