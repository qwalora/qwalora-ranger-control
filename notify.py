"""Best-effort email notifications.

Sends over SMTP when configured, and is a safe no-op otherwise, so the portal
runs identically with or without mail set up (like the Ludus broker's mock mode).
Never raises into the caller: a notification must never break a promotion or a
report decision.

Env:
    SMTP_HOST, SMTP_PORT (default 587), SMTP_USER, SMTP_PASS
    SMTP_FROM        (default: SMTP_USER)
    SMTP_STARTTLS=1  (default on)
    NOTIFY_EMAIL=0   to disable email even when SMTP is set
"""
import os
import smtplib
import ssl
from email.message import EmailMessage


def enabled():
    return (os.environ.get("NOTIFY_EMAIL", "1") == "1"
            and bool(os.environ.get("SMTP_HOST")))


def send_email(to_addr, subject, body):
    """Return True if sent, False if skipped or failed. Never raises."""
    if not enabled() or not to_addr:
        return False
    host = os.environ["SMTP_HOST"]
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER")
    pwd = os.environ.get("SMTP_PASS")
    sender = os.environ.get("SMTP_FROM") or user or "no-reply@qwalora.com"
    try:
        msg = EmailMessage()
        msg["From"] = sender
        msg["To"] = to_addr
        msg["Subject"] = subject
        msg.set_content(body)
        with smtplib.SMTP(host, port, timeout=10) as s:
            if os.environ.get("SMTP_STARTTLS", "1") == "1":
                s.starttls(context=ssl.create_default_context())
            if user and pwd:
                s.login(user, pwd)
            s.send_message(msg)
        return True
    except Exception:  # noqa: BLE001
        return False
