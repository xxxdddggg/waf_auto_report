"""API 层：登录、拉取日志、下载日志、IP/ID 持久化"""

import base64
import json
import os
import re
import time

import requests
import urllib3

from config import (
    WAF_HOST, WAF_USER, WAF_PASS,
    REPORTED_IPS_FILE,
    ATTACK_CLASS_MAP, DEFAULT_CLASS,
    FILTER_WEBSITE_NAME,
    log, translate_attack_type, translate_risk_level,
)

urllib3.disable_warnings()

session = requests.Session()
session.verify = False


# ------------------------------------------------------------------
# API 登录
# ------------------------------------------------------------------
def api_login():
    """通过 API 登录 WAF（RSA 加密密码）"""
    log("正在登录WAF...")

    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5

    pub_key_str = """-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzm1pGNxmHuVDR1+pvgwJ
VrV8Sip0zIYfreyIJenZW+fjS9WX92ITam0RA9raePHZMWx1vBf8HlQMkTVf7aE3
B18D4PBoYUxni47jUsjFoYgYCGHtIeEpqi1Zm4BprVpHLWd2ce8eDoXiSCcVMdm8
zQXyHna8e7zFxIo03KJWMz65r/4P9TKc24Lu0FaVA4n0GIkW8Rh5pLo6bGtyD3eL
J8fPJqeUhorwSYJnJ+fqrQ+pS8lhm37QA6FUGZBjvyjr1h+IP6oMrbYiGdRxRDsj
fb0+q8DxAMyGvhf/ZJ/X2w4FjbSrmKvRo3alQEHk+Vv9uFFGs8yQ3gQpie5WJjCJ
KQIDAQAB
-----END RSA PUBLIC KEY-----"""

    key = RSA.import_key(pub_key_str)
    cipher = PKCS1_v1_5.new(key)
    encrypted = base64.b64encode(cipher.encrypt(WAF_PASS.encode())).decode()

    session.get(f"{WAF_HOST}/api/CSRFTokenAPI", verify=False)
    csrf_token = session.cookies.get("csrftoken", "")

    r = session.post(
        f"{WAF_HOST}/api/LoginAPI",
        json={"username": WAF_USER, "password": encrypted},
        headers={
            "X-CSRFToken": csrf_token,
            "Referer": f"{WAF_HOST}/",
            "Origin": WAF_HOST,
        },
        verify=False,
    )

    if r.status_code == 200 and r.json().get("err") is None:
        log("API 登录成功")
        return True
    else:
        log(f"API 登录失败: {r.text}")
        return False


# ------------------------------------------------------------------
# 已上报 IP 持久化
# ------------------------------------------------------------------
def load_reported_ips():
    if os.path.exists(REPORTED_IPS_FILE):
        with open(REPORTED_IPS_FILE, "r") as f:
            return set(line.strip() for line in f if line.strip())
    return set()


def save_reported_ips(ips):
    with open(REPORTED_IPS_FILE, "a", encoding="utf-8") as f:
        for ip in ips:
            f.write(ip + "\n")


# ------------------------------------------------------------------
# 拉取攻击日志
# ------------------------------------------------------------------
def fetch_attack_logs(hours=1, seconds=None, max_pages=30, timeout=180):
    """
    拉取攻击日志。seconds 优先于 hours。
    使用 AdvancedFilter API 在服务端过滤，只返回真正的攻击日志。
    """
    if seconds is not None:
        cutoff = int(time.time()) - seconds
        log(f"正在拉取近 {seconds} 秒攻击日志...")
    else:
        cutoff = int(time.time()) - hours * 3600
        log(f"正在拉取近 {hours} 小时攻击日志...")

    # 构建高级筛选条件：排除非攻击、排除无威胁、排除放行
    conditions = ["attack_type != 非攻击", "risk_level != 无威胁", "action != 放行"]
    if FILTER_WEBSITE_NAME:
        site_uuid = _resolve_site_uuid()
        if site_uuid:
            conditions.insert(0, f"site_uuid = {site_uuid}")
        else:
            log(f"  警告: 未找到站点 '{FILTER_WEBSITE_NAME}'，不筛选站点")
    filter_body = " AND ".join(conditions)

    all_logs = []
    start_time = time.time()

    page = 1
    while page <= max_pages:
        if time.time() - start_time > timeout:
            log(f"  拉取超时({timeout}s)，已获取 {len(all_logs)} 条")
            break

        params = {
            "count": 100,
            "target": "log:detect_log:optim_limit",
            "body": filter_body,
            "current_page": 0,
            "target_page": page,
        }
        try:
            r = session.get(f"{WAF_HOST}/api/AdvancedFilter", params=params,
                            verify=False, timeout=15)
        except Exception as e:
            log(f"  API请求异常: {e}")
            break
        items = r.json().get("data", {}).get("items", [])

        if not items:
            break

        for item in items:
            ts = int(item.get("timestamp", 0))
            if ts < cutoff:
                break
            all_logs.append(item)

        if len(items) < 100:
            break
        page += 1
        time.sleep(0.3)

    log(f"共拉取 {len(all_logs)} 条有效攻击日志")
    return all_logs


def _resolve_site_uuid():
    """通过 AdvancedFilterEditorConfig API 查找 site_uuid"""
    try:
        r = session.get(
            f"{WAF_HOST}/api/AdvancedFilterEditorConfig",
            params={"target": "log:detect_log"},
            verify=False, timeout=10,
        )
        fields = r.json().get("data", {}).get("fields", {})
        options = fields.get("site_uuid", {}).get("options", {})
        for uid, name in options.items():
            if name == FILTER_WEBSITE_NAME:
                return uid
    except Exception:
        pass
    return None


# ------------------------------------------------------------------
# 按源 IP 分组
# ------------------------------------------------------------------
def group_by_ip(logs):
    groups = {}
    for item in logs:
        ip = item.get("src_ip", "unknown")
        if ip not in groups:
            groups[ip] = item
    log(f"共 {len(groups)} 个独立攻击IP")
    return groups


# ------------------------------------------------------------------
# 下载日志 zip
# ------------------------------------------------------------------
def api_download_log(event_ids, save_path):
    """通过 API 下载日志 zip"""
    log("  创建日志下载任务...")
    payload = {
        "event_id__in": event_ids,
        "scope": "log:detect_log",
        "custom": [
            "event_id", "action", "website", "website_name", "src_ip", "attack_type",
            "risk_level", "timestamp", "src_port", "dst_ip", "dst_port", "http_host_port",
            "req_start_time", "req_end_time", "req_detect_time", "method", "status_code",
            "country", "province", "req_header", "req_body", "req_location", "req_payload",
            "payload", "scheme", "url_path", "host", "rule_id", "module", "risk_level_num",
            "reason", "human_timestamp", "upstream_addr", "req_payload_explain_detail",
            "effective", "x_forwarded_for"
        ]
    }

    csrf_token = session.cookies.get("csrftoken", "")
    r = session.post(
        f"{WAF_HOST}/api/FilterDownloadAPI?format=json",
        json=payload,
        headers={
            "X-CSRFToken": csrf_token,
            "Referer": f"{WAF_HOST}/",
            "Origin": WAF_HOST,
        },
        verify=False,
    )
    result = r.json()
    msg_text = result.get("msg", {}).get("text", "")
    match = re.search(r'(?:ID\s*为\s*|Task id is\s*)(\d+)', msg_text)
    if not match:
        log(f"  下载任务创建失败: {msg_text}")
        return False

    task_id = match.group(1)
    log(f"  任务ID: {task_id}，等待生成...")

    for _ in range(15):
        time.sleep(2)
        r = session.get(f"{WAF_HOST}/api/DownloadTaskLogAPI?id={task_id}", stream=True)
        ct = r.headers.get("Content-Type", "")
        if r.status_code == 200 and "json" not in ct.lower() and len(r.content) > 100:
            with open(save_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
            log(f"  日志已下载: {os.path.basename(save_path)}")
            return True

    log("  下载超时")
    return False
