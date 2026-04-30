"""打包与邮件：ZIP 打包 + SMTP 邮件发送"""

import os
import smtplib
import zipfile
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders

from config import CFG, ORG_NAME, log


def package_event(event_dir, seq_str):
    """将事件目录打包为 zip"""
    zip_path = f"{event_dir}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(event_dir):
            for f in files:
                full = os.path.join(root, f)
                arcname = os.path.relpath(full, os.path.dirname(event_dir))
                zf.write(full, arcname)
    log(f"  已打包: {os.path.basename(zip_path)}")
    return zip_path


def send_email(zip_path, event_title, seq_str):
    """发送上报邮件"""
    email_cfg = CFG["email"]
    if not email_cfg.get("enabled"):
        log("邮件发送已禁用，跳过")
        return

    msg = MIMEMultipart()
    msg["From"] = email_cfg["sender"]
    msg["To"] = ", ".join(email_cfg["recipients"])
    msg["Cc"] = ", ".join(email_cfg["cc"])
    msg["Subject"] = f"安全事件上报-{seq_str} {event_title}"

    body = (f"各位领导/同事好：\n\n"
            f"附件为{ORG_NAME}安全事件上报材料（{seq_str}）。\n"
            f"事件概要：{event_title}\n\n"
            f"请查阅，谢谢。")
    msg.attach(MIMEText(body, "plain", "utf-8"))

    with open(zip_path, "rb") as f:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f"attachment; filename={os.path.basename(zip_path)}")
        msg.attach(part)

    try:
        if email_cfg["smtp_port"] == 465:
            server = smtplib.SMTP_SSL(email_cfg["smtp_host"], email_cfg["smtp_port"])
        else:
            server = smtplib.SMTP(email_cfg["smtp_host"], email_cfg["smtp_port"])
        server.login(email_cfg["sender"], email_cfg["sender_password"])
        all_recipients = email_cfg["recipients"] + email_cfg["cc"]
        server.sendmail(email_cfg["sender"], all_recipients, msg.as_string())
        server.quit()
        log(f"  邮件已发送")
    except Exception as e:
        log(f"  邮件发送失败: {e}")
