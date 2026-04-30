"""主流程：WAF 安全事件自动上报入口"""

import os
import shutil
from datetime import datetime

from config import (
    OUTPUT_DIR, ORG_NAME, PREFIX,
    log, translate_attack_type, translate_risk_level,
)
from api import (
    api_login, fetch_attack_logs, group_by_ip,
    api_download_log, load_reported_ips, save_reported_ips,
)
from screenshot import take_alert_screenshots
from excel import fill_excel
from packaging import package_event, send_email


def main():
    print("=" * 55)
    print(f"  {ORG_NAME} - WAF 安全事件自动上报")
    print("=" * 55)

    # 1. API 登录
    if not api_login():
        return

    # 2. 拉取攻击日志
    #正式用：
    all_logs = fetch_attack_logs(hours=1)
    # all_logs = fetch_attack_logs(seconds=100)
    if not all_logs:

        log("近1小时无攻击日志，退出。")
        return

    # 3. 按IP分组，过滤已上报IP
    reported_ips = load_reported_ips()
    raw_groups = group_by_ip(all_logs)
    groups = {}
    for ip, rep in raw_groups.items():
        if ip in reported_ips:
            log(f"  跳过已上报IP: {ip}")
            continue
        groups[ip] = rep

    if not groups:
        log("所有攻击IP均已上报过，无新事件。")
        return

    group_list = list(groups.items())

    date_str = datetime.now().strftime("%m%d")

    # 计算起始序号：当天已有目录中取最大序号 +1
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    date_prefix = f"{PREFIX}-{date_str}"
    max_seq = 0
    for d in os.listdir(OUTPUT_DIR):
        if d.startswith(date_prefix):
            parts = d.rsplit("-", 1)
            if len(parts) == 2 and parts[1].isdigit():
                max_seq = max(max_seq, int(parts[1]))
    start_seq = max_seq + 1

    # 4. 逐个处理每个IP事件
    events_for_screenshot = []
    new_reported_ips = []

    for idx, (ip, rep) in enumerate(group_list):
        seq = start_seq + idx
        seq_str_padded = str(seq).zfill(3)
        seq_plain = str(seq)

        event_name = f"{PREFIX}-{date_str}-{seq_str_padded}"
        event_dir = os.path.join(OUTPUT_DIR, event_name)

        folder_seq = os.path.join(event_dir, seq_plain)
        folder_log = os.path.join(event_dir, f"{seq_plain}_log")
        folder_pic = os.path.join(event_dir, f"{seq_plain}_picture")

        os.makedirs(folder_seq, exist_ok=True)
        os.makedirs(folder_log, exist_ok=True)
        os.makedirs(folder_pic, exist_ok=True)

        attack_type = translate_attack_type(rep.get("attack_type"))
        risk_level = translate_risk_level(rep.get("risk_level"))
        log(f"\n[事件 {seq_str_padded}] IP: {ip} | "
            f"攻击类型: {attack_type} | 风险: {risk_level}")

        # 填写 Excel
        xlsx_out = os.path.join(folder_seq, "安全事件汇总.xlsx")
        fill_excel(rep, seq, xlsx_out)
        shutil.copy2(xlsx_out, os.path.join(event_dir, "安全事件汇总.xlsx"))
        log("  Excel 已填写")

        # 下载日志
        tmp_log = os.path.join(folder_log, "detect_log.zip")
        api_download_log([rep.get("event_id")], tmp_log)

        # 记录待截图事件
        events_for_screenshot.append(
            (event_dir, seq_plain, seq_str_padded, rep.get("event_id"), ip, rep)
        )
        new_reported_ips.append(ip)

    # 5. 批量截图
    log("\n--- 开始截图 ---")
    take_alert_screenshots(events_for_screenshot)

    # 6. 打包 + 发邮件
    log("\n--- 打包 & 上报 ---")
    for idx, (ip, rep) in enumerate(group_list):
        seq = start_seq + idx
        seq_str_padded = str(seq).zfill(3)

        event_name = f"{PREFIX}-{date_str}-{seq_str_padded}"
        event_dir = os.path.join(OUTPUT_DIR, event_name)

        zip_path = package_event(event_dir, seq_str_padded)

        attack_type = translate_attack_type(rep.get("attack_type", "未知"))
        event_title = f"{ORG_NAME}受到{attack_type}攻击"
        send_email(zip_path, event_title, seq_str_padded)

    # 7. 记录已上报IP
    save_reported_ips(new_reported_ips)

    print("\n" + "=" * 55)
    print(f"  完成！共生成 {len(group_list)} 个事件包")
    print(f"  输出目录: {os.path.abspath(OUTPUT_DIR)}")
    print("=" * 55)


if __name__ == "__main__":
    main()
