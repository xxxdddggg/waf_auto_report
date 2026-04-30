"""配置加载、常量定义、翻译映射"""

import os
from datetime import datetime

import yaml

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_DIR, "config.yaml")

# ------------------------------------------------------------------
# 攻击类型 英文 → 中文
# ------------------------------------------------------------------
ATTACK_TYPE_ZH = {
    "Info Leak": "信息泄露",
    "SQL Injection": "SQL 注入",
    "XSS": "XSS",
    "Command Injection": "命令注入",
    "Code Injection": "代码注入",
    "Path Traversal": "路径遍历",
    "File Inclusion": "文件包含",
    "RFI": "远程文件包含",
    "LFI": "本地文件包含",
    "Scanner": "扫描",
    "Scan": "扫描",
    "Nuclei": "扫描",
    "DoS": "拒绝服务",
    "Trojan": "木马",
    "Backdoor": "后门",
    "Malicious Code": "恶意代码",
    "Unauthorized Access": "未授权访问",
    "SSRF": "SSRF",
    "RCE": "远程代码执行",
    "Bot": "恶意爬虫",
    "CPP": "CC攻击",
    "HTTP Flood": "HTTP泛洪",
}

# 风险等级 英文 → 中文
RISK_LEVEL_ZH = {
    "Low": "低危", "Medium": "中危", "High": "高危", "Critical": "严重",
    "low": "低危", "medium": "中危", "high": "高危", "critical": "严重",
}


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


CFG = load_config()

WAF_HOST = CFG["waf"]["base_url"]
WAF_USER = CFG["waf"]["username"]
WAF_PASS = CFG["waf"]["password"]
HEADLESS = CFG["waf"]["headless"]
SLOW_MO = CFG["waf"]["slow_mo"]
SCREENSHOT_TIMEOUT = CFG["waf"]["screenshot_timeout"]
FILTER_WEBSITE_NAME = CFG["waf"].get("website_name", "")

OUTPUT_DIR = CFG["output"]["base_dir"]
TEMPLATE_XLSX = CFG["output"]["template_excel"]
ORG_NAME = CFG["output"]["org_name"]
PREFIX = CFG["output"]["prefix"]

REPORTED_IPS_FILE = os.path.join(SCRIPT_DIR, "reported_ips.txt")

# 攻击类型 → 事件分类映射（从 config.yaml 加载）
ATTACK_CLASS_MAP = {}
for _k, _v in CFG.get("classification", {}).items():
    if _k != "_default":
        ATTACK_CLASS_MAP[_k] = (_v[0], _v[1])
DEFAULT_CLASS = tuple(CFG["classification"]["_default"][:2])


# ------------------------------------------------------------------
# 工具函数
# ------------------------------------------------------------------
def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


def translate_attack_type(at):
    if not at:
        return "未知"
    if any('一' <= c <= '鿿' for c in at):
        return at
    return ATTACK_TYPE_ZH.get(at, at)


def translate_risk_level(rl):
    if not rl:
        return ""
    if any('一' <= c <= '鿿' for c in rl):
        return rl
    return RISK_LEVEL_ZH.get(rl, rl)
