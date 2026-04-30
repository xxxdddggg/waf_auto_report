"""浏览器截图：Playwright 打开 WAF 详情页并截取完整长图"""

import os
from io import BytesIO

from PIL import Image
from playwright.sync_api import sync_playwright, TimeoutError as PwTimeout

from api import session
from config import (
    WAF_HOST, WAF_USER, WAF_PASS,
    HEADLESS, SLOW_MO, SCREENSHOT_TIMEOUT,
    log,
)


def _inject_cookies_to_context(context):
    """把 requests session 的 cookie 注入到 Playwright context"""
    cookies = []
    for c in session.cookies:
        cookies.append({
            "name": c.name,
            "value": c.value,
            "domain": c.domain,
            "path": c.path,
            "secure": c.secure,
        })
    context.add_cookies(cookies)


def _ui_login(page):
    """通过 UI 表单登录 WAF（SafeLine 自定义组件）"""
    for i in range(page.locator('input.el-input__inner[type="text"]').count()):
        el = page.locator('input.el-input__inner[type="text"]').nth(i)
        if el.is_visible() and el.get_attribute('placeholder'):
            el.fill(WAF_USER)
            break
    for i in range(page.locator('input.el-input__inner[type="password"]').count()):
        el = page.locator('input.el-input__inner[type="password"]').nth(i)
        if el.is_visible():
            el.fill(WAF_PASS)
            break
    for i in range(page.locator('button').count()):
        btn = page.locator('button').nth(i)
        if btn.is_visible() and '录' in btn.inner_text():
            btn.click()
            break
    page.wait_for_load_state("networkidle", timeout=15000)


def _find_scroll_container(page):
    """找到可滚动容器的信息"""
    return page.evaluate("""() => {
        const all = document.querySelectorAll('*');
        for (const el of all) {
            const style = getComputedStyle(el);
            if ((style.overflowY === 'auto' || style.overflowY === 'scroll')
                && el.scrollHeight > el.clientHeight + 50
                && el.clientWidth > 500) {
                const rect = el.getBoundingClientRect();
                return {
                    found: true,
                    scrollHeight: el.scrollHeight,
                    clientHeight: el.clientHeight,
                    top: Math.round(rect.top),
                    left: Math.round(rect.left),
                    width: Math.round(rect.width),
                    height: Math.round(rect.height),
                };
            }
        }
        return { found: false };
    }""")


def _scroll_container_to(page, pos):
    """将可滚动容器滚动到指定位置"""
    page.evaluate(f"""() => {{
        const all = document.querySelectorAll('*');
        for (const el of all) {{
            const style = getComputedStyle(el);
            if ((style.overflowY === 'auto' || style.overflowY === 'scroll')
                && el.scrollHeight > el.clientHeight + 50 && el.clientWidth > 500) {{
                el.scrollTop = {pos};
                break;
            }}
        }}
    }}""")
    page.wait_for_timeout(300)


def _take_long_screenshot(page, output_path):
    """
    滚动拼接截取详情页完整长图。

    修复逻辑：
    - 第一屏截取 [0, c_top + view_h] 的完整视口（含顶部导航）
    - 后续每屏只截取容器内新增的内容区域：
        crop_top    = c_top
        crop_bottom = c_top + actual_step   # actual_step = 本次实际滚动量
    - 这样每段图片高度严格等于实际滚动距离，不产生重叠也不遗漏
    """
    info = _find_scroll_container(page)

    if not info.get('found'):
        # 没有可滚动容器，直接截全屏
        buf = page.screenshot(type="png")
        with open(output_path, "wb") as f:
            f.write(buf)
        return

    total_h  = info['scrollHeight']
    view_h   = info['clientHeight']
    c_top    = info['top']
    max_scroll = total_h - view_h

    # ── 第一屏：滚到顶，截完整视口（导航栏 + 内容顶部）──
    _scroll_container_to(page, 0)
    buf = page.screenshot(type="png")
    first_img = Image.open(BytesIO(buf))
    # 第一屏保留到容器底部（c_top + view_h）
    first_bottom = min(c_top + view_h, first_img.height)
    pieces = [first_img.crop((0, 0, first_img.width, first_bottom))]

    # ── 后续分段滚动，每次只取新增内容 ──
    prev_scroll = 0
    while prev_scroll < max_scroll:
        next_scroll = min(prev_scroll + view_h, max_scroll)
        actual_step = next_scroll - prev_scroll   # 本次真实滚动量

        _scroll_container_to(page, next_scroll)
        buf = page.screenshot(type="png")
        img = Image.open(BytesIO(buf))

        # 容器内新增内容：从 c_top 开始，高度 = actual_step
        crop_top    = c_top
        crop_bottom = min(c_top + actual_step, img.height)

        if crop_bottom > crop_top:
            pieces.append(img.crop((0, crop_top, img.width, crop_bottom)))

        prev_scroll = next_scroll

    # ── 拼接所有分段 ──
    total_width  = pieces[0].width
    total_height = sum(p.height for p in pieces)
    result = Image.new('RGB', (total_width, total_height))
    y = 0
    for piece in pieces:
        result.paste(piece, (0, y))
        y += piece.height

    result.save(output_path)


def take_alert_screenshots(events_data):
    """
    用 Playwright 打开 WAF 详情页，截取完整长截图。
    events_data: list of (event_dir, seq_plain, seq_padded, event_id, ip, log_item)
    返回: dict { seq_padded: [pic_path] }
    """
    screenshots = {}
    if not events_data:
        return screenshots

    log("启动浏览器进行告警截图...")
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=HEADLESS, slow_mo=SLOW_MO,
            args=["--start-maximized"],
        )
        context = browser.new_context(
            ignore_https_errors=True,
            no_viewport=True,
        )

        page = context.new_page()
        page.goto(f"{WAF_HOST}/", wait_until="domcontentloaded", timeout=30000)
        _inject_cookies_to_context(context)
        page.reload(wait_until="networkidle", timeout=15000)
        page.wait_for_timeout(1500)

        # 检测是否需要 UI 登录
        needs_login = False
        for i in range(page.locator('input.el-input__inner[type="text"]').count()):
            el = page.locator('input.el-input__inner[type="text"]').nth(i)
            if el.is_visible() and el.get_attribute('placeholder'):
                needs_login = True
                break

        if needs_login:
            log("  Cookie 未生效，走 UI 登录...")
            _ui_login(page)
            log("  UI 登录完成")
        else:
            log("  Cookie 登录态有效，直接进入")

        # 逐个截图
        for event_dir, seq_plain, seq_padded, event_id, ip, log_item in events_data:
            pic_dir = os.path.join(event_dir, f"{seq_plain}_picture")
            os.makedirs(pic_dir, exist_ok=True)
            pics = []

            try:
                detail_url = f"{WAF_HOST}/log/detect_log/detail/?event_id={event_id}&prePath=true"
                page.goto(detail_url, wait_until="networkidle", timeout=20000)
                page.wait_for_timeout(2000)

                pic_path = os.path.join(pic_dir, "告警详情截图.png")
                _take_long_screenshot(page, pic_path)
                pics.append(pic_path)
                log(f"  [{seq_padded}] 截图完成（告警详情长图）")

            except PwTimeout:
                log(f"  [{seq_padded}] 截图超时，跳过")
            except Exception as e:
                log(f"  [{seq_padded}] 截图异常: {e}")

            screenshots[seq_padded] = pics

        browser.close()
    log("浏览器截图完成")
    return screenshots