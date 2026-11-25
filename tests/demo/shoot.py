#!/usr/bin/env python3
"""Signs in to a demo hub's web UI and saves screenshots of its pages.

    shoot.py URL USER PASSWORD OUTDIR WEB_CHAT NAS_CHAT -- TOTP-COMMAND...

TOTP-COMMAND prints a current authenticator code.
"""
import subprocess
import sys
import time

from playwright.sync_api import sync_playwright

url, user, password, out, web_chat, nas_chat = sys.argv[1:7]
totp_cmd = sys.argv[sys.argv.index("--") + 1:]


def code():
    # A fresh 30-second window, so the code is not one already used.
    time.sleep(31 - int(time.time()) % 30)
    return subprocess.check_output(totp_cmd, text=True).strip()


def sign_in(page):
    page.goto(url + "/login")
    page.fill('input[name="user"]', user)
    page.fill('input[name="password"]', password)
    page.fill('input[name="code"]', code())
    page.click('form:has(input[name="password"]) button.primary')
    page.wait_for_url(url + "/")


def shot(page, path, name, full=False, settle=1500):
    page.goto(url + path)
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(settle)
    page.screenshot(path=f"{out}/{name}.png", full_page=full)
    print("saved", name)


with sync_playwright() as p:
    browser = p.chromium.launch()
    desk = browser.new_context(viewport={"width": 1360, "height": 860},
                               device_scale_factor=2, color_scheme="light")
    page = desk.new_page()
    sign_in(page)
    shot(page, "/", "map")
    shot(page, "/spaces", "spaces")
    shot(page, f"/space/web-claude/chat/{web_chat}", "chat", settle=2500)
    shot(page, "/approvals", "approvals")
    shot(page, "/host/nas", "machine")
    shot(page, "/chats", "chats")

    dark = browser.new_context(viewport={"width": 1360, "height": 860},
                               device_scale_factor=2, color_scheme="dark",
                               storage_state=desk.storage_state())
    page = dark.new_page()
    shot(page, "/", "map-dark")

    phone = browser.new_context(viewport={"width": 390, "height": 844},
                                device_scale_factor=3, is_mobile=True, has_touch=True,
                                color_scheme="light", storage_state=desk.storage_state())
    page = phone.new_page()
    shot(page, f"/space/nas-claude/chat/{nas_chat}", "phone-approve", settle=2500)
    shot(page, "/spaces", "phone-spaces")
    browser.close()
