"""
Alerting Service
================

Sends scan result notifications via two channels:
  - Slack   : Posts a formatted message to a Slack Incoming Webhook URL.
  - Email   : Sends an HTML email via SMTP using Python's stdlib smtplib,
              wrapped in asyncio.to_thread so it doesn't block the event loop.

Both channels are optional. If the required config is not set, the function
logs a debug message and returns silently — it never raises or crashes the
caller.

Configuration (via .env):
  SLACK_WEBHOOK_URL   — Slack Incoming Webhook URL. Create one at:
                        https://api.slack.com/messaging/webhooks
  SMTP_HOST           — SMTP server hostname (e.g. smtp.gmail.com)
  SMTP_PORT           — SMTP server port (587 for STARTTLS, 465 for SSL)
  SMTP_USERNAME       — SMTP login username / email address
  SMTP_PASSWORD       — SMTP login password or app password
  SMTP_FROM_EMAIL     — The From: address shown in the email
  SMTP_USE_SSL        — Set to true for port 465 (SMTP_SSL).
                        Defaults to false (STARTTLS on port 587).

When to call these:
  - After a website scan completes for an authenticated user (scan.py)
  - When the background scheduler detects a score regression (scheduler.py)
"""

import asyncio
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import httpx

from app.config import settings

logger = logging.getLogger(__name__)


async def send_slack_alert(title: str, message: str, color: str = "#e53e3e") -> None:
    """
    POST a notification to the configured Slack Incoming Webhook URL.

    Parameters
    ----------
    title   : Short heading for the Slack attachment.
    message : Body text shown under the heading.
    color   : Left-border colour of the Slack attachment block.
              Use "#e53e3e" for regressions/critical, "#38a169" for clean scans.

    If SLACK_WEBHOOK_URL is not set in config, this is a no-op.
    """
    if not settings.slack_webhook_url:
        logger.debug("Slack alerting skipped — SLACK_WEBHOOK_URL not configured.")
        return

    payload = {
        "attachments": [
            {
                "color": color,
                "title": title,
                "text": message,
                "footer": "SecureLens AI",
            }
        ]
    }

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                settings.slack_webhook_url,
                json=payload,
                timeout=10.0,
            )
            if resp.status_code != 200:
                logger.warning(
                    f"Slack webhook returned unexpected status {resp.status_code}: {resp.text[:200]}"
                )
            else:
                logger.debug("Slack alert sent.")
    except Exception as e:
        logger.warning(f"Slack alert failed: {e}")


async def send_email_alert(to_email: str, subject: str, html_body: str) -> None:
    """
    Send an HTML email via SMTP.

    Runs the blocking smtplib call in a thread via asyncio.to_thread so it
    does not hold the event loop. Supports both STARTTLS (port 587, default)
    and SMTP_SSL (port 465, set SMTP_USE_SSL=true).

    If any SMTP setting is missing, this is a no-op.
    """
    required = [
        settings.smtp_host,
        settings.smtp_port,
        settings.smtp_username,
        settings.smtp_password,
        settings.smtp_from_email,
    ]
    if not all(required):
        logger.debug("Email alerting skipped — SMTP settings not fully configured.")
        return

    def _send_blocking() -> None:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = settings.smtp_from_email
        msg["To"] = to_email
        msg.attach(MIMEText(html_body, "html"))

        if settings.smtp_use_ssl:
            with smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port) as smtp:
                smtp.login(settings.smtp_username, settings.smtp_password)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as smtp:
                smtp.starttls()
                smtp.login(settings.smtp_username, settings.smtp_password)
                smtp.send_message(msg)

    try:
        await asyncio.to_thread(_send_blocking)
        logger.debug(f"Email alert sent to {to_email}.")
    except Exception as e:
        logger.warning(f"Email alert to {to_email} failed: {e}")


def build_scan_email_body(url: str, score: int, issue_count: int) -> str:
    """
    Render a simple HTML email body for a completed scan notification.
    Kept minimal to maximise email client compatibility.
    """
    score_color = "#e53e3e" if score < 50 else "#dd6b20" if score < 75 else "#38a169"
    return f"""
<html>
<body style="font-family: Arial, sans-serif; color: #2d3748; max-width: 600px; margin: 0 auto;">
  <h2 style="color: #1a202c;">SecureLens Scan Complete</h2>
  <p>A security scan has been completed for:</p>
  <p style="font-size: 16px;"><strong>{url}</strong></p>
  <table style="border-collapse: collapse; width: 100%;">
    <tr>
      <td style="padding: 8px; border: 1px solid #e2e8f0;">Security Score</td>
      <td style="padding: 8px; border: 1px solid #e2e8f0; color: {score_color};">
        <strong>{score}/100</strong>
      </td>
    </tr>
    <tr>
      <td style="padding: 8px; border: 1px solid #e2e8f0;">Issues Found</td>
      <td style="padding: 8px; border: 1px solid #e2e8f0;">{issue_count}</td>
    </tr>
  </table>
  <p style="margin-top: 20px; color: #718096; font-size: 12px;">
    Sent by SecureLens AI &mdash; automated security monitoring
  </p>
</body>
</html>
"""


def build_regression_email_body(url: str, old_score: int, new_score: int) -> str:
    """Render an HTML email body for a scheduled scan score regression alert."""
    delta = new_score - old_score
    return f"""
<html>
<body style="font-family: Arial, sans-serif; color: #2d3748; max-width: 600px; margin: 0 auto;">
  <h2 style="color: #c53030;">Security Score Regression Detected</h2>
  <p>A scheduled scan detected a score drop for:</p>
  <p style="font-size: 16px;"><strong>{url}</strong></p>
  <table style="border-collapse: collapse; width: 100%;">
    <tr>
      <td style="padding: 8px; border: 1px solid #e2e8f0;">Previous Score</td>
      <td style="padding: 8px; border: 1px solid #e2e8f0;">{old_score}/100</td>
    </tr>
    <tr>
      <td style="padding: 8px; border: 1px solid #e2e8f0;">New Score</td>
      <td style="padding: 8px; border: 1px solid #e2e8f0; color: #c53030;">
        <strong>{new_score}/100 ({delta:+d})</strong>
      </td>
    </tr>
  </table>
  <p style="margin-top: 16px;">
    Log in to SecureLens to review the new findings and take action.
  </p>
  <p style="margin-top: 20px; color: #718096; font-size: 12px;">
    Sent by SecureLens AI &mdash; automated security monitoring
  </p>
</body>
</html>
"""
