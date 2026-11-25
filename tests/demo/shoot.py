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


def unlock(page, chat_path):
    """Unlocks this browser for chats and approvals (password and code)."""
    page.goto(url + "/spaces")
    token = page.locator('input[name="csrf"]').first.get_attribute("value")
    r = page.request.post(url + chat_path + "/unlock",
                          form={"csrf": token, "password": password, "code": code()},
                          max_redirects=0)
    print("unlock:", r.status, r.headers.get("location", ""))


def shot(page, path, name, full=False, settle=1500, element=None, before=None):
    page.goto(url + path)
    page.wait_for_load_state("networkidle")
    if before:
        before(page)
    page.wait_for_timeout(settle)
    if element:
        page.locator(element).first.screenshot(path=f"{out}/{name}.png")
    else:
        page.screenshot(path=f"{out}/{name}.png", full_page=full)
    print("saved", name)


def fit(page):
    # A taller map than a laptop screen gives it, for the whole picture.
    page.evaluate("document.querySelector('.graph-wrap').style.height = '1150px'")
    page.wait_for_timeout(500)
    page.locator('button[data-map="fit"]').click()


with sync_playwright() as p:
    browser = p.chromium.launch()
    desk = browser.new_context(viewport={"width": 1360, "height": 860},
                               device_scale_factor=2, color_scheme="light")
    page = desk.new_page()
    sign_in(page)
    unlock(page, f"/space/web-claude/chat/{web_chat}")
    shot(page, "/", "map", element="section.graph-card", before=fit)
    shot(page, "/spaces", "spaces")
    shot(page, f"/space/web-claude/chat/{web_chat}", "chat", settle=2500)
    shot(page, "/approvals", "approvals")
    shot(page, "/host/web-01", "machine", element='section.card:has(h2:text-is("Logins"))')
    shot(page, "/chats", "chats")

    dark = browser.new_context(viewport={"width": 1360, "height": 860},
                               device_scale_factor=2, color_scheme="dark",
                               storage_state=desk.storage_state())
    page = dark.new_page()
    shot(page, "/", "map-dark", element="section.graph-card", before=fit)

    phone = browser.new_context(viewport={"width": 390, "height": 844},
                                device_scale_factor=3, is_mobile=True, has_touch=True,
                                color_scheme="light", storage_state=desk.storage_state())
    page = phone.new_page()
    shot(page, f"/space/nas-claude/chat/{nas_chat}", "phone-approve", settle=2500)
    shot(page, "/spaces", "phone-spaces")
    browser.close()
