"""Email alert helper."""

import smtplib
from email.message import EmailMessage

from settings import get_setting


def send_email_alert(subject, body, recipients):
    smtp_server = get_setting("smtp_server", "smtp.gmail.com")
    smtp_port = int(get_setting("smtp_port", "587"))
    smtp_email = get_setting("smtp_email", "")
    smtp_password = get_setting("smtp_password", "")

    if not smtp_email or not smtp_password:
        return {
            "sent": False,
            "reason": "SMTP credentials are not configured.",
        }

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = smtp_email
    message["To"] = ", ".join(recipients)
    message.set_content(body)

    with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as server:
        server.starttls()
        server.login(smtp_email, smtp_password)
        server.send_message(message)

    return {"sent": True, "recipients": recipients}