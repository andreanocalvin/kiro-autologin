#!/usr/bin/env python3
"""
Kiro Auto-Login for 9router
────────────────────────────
Automates Kiro login via Google SSO, captures tokens, and saves to 9router DB.

Flow:
  1. Generate PKCE pair (code_verifier + code_challenge)
  2. Navigate Playwright to Kiro social login URL (Google SSO)
  3. Auto-fill Google credentials + handle consent screens
  4. Intercept kiro:// redirect → extract auth code
  5. Exchange code → tokens (accessToken, refreshToken, profileArn)
  6. Save to 9router SQLite DB (providerConnections table)

Usage:
  python kiro_autologin.py user@gmail.com:password
  python kiro_autologin.py --batch accounts.txt
  python kiro_autologin.py --batch accounts.txt --headless --concurrent 3
  python kiro_autologin.py --test user@gmail.com:password
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import re
import secrets
import sqlite3
import ssl
import sys
import time
import uuid
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode, urlparse, parse_qs

import aiohttp
from playwright.async_api import async_playwright

# ──────────────────────────── Configuration ────────────────────────────

VERSION = "1.0.0"
DEBUG_ENABLED = os.environ.get("DEBUG", "").lower() in ("1", "true", "yes")
HEADLESS = False  # overridden by --headless flag

# Kiro endpoints (reverse-engineered from 9router source)
KIRO_SOCIAL_AUTH_BASE = "https://prod.us-east-1.auth.desktop.kiro.dev"
KIRO_LOGIN_URL = f"{KIRO_SOCIAL_AUTH_BASE}/login"
KIRO_TOKEN_URL = f"{KIRO_SOCIAL_AUTH_BASE}/oauth/token"
KIRO_REFRESH_URL = f"{KIRO_SOCIAL_AUTH_BASE}/refreshToken"
KIRO_REDIRECT_URI = "kiro://kiro.kiroAgent/authenticate-success"

# 9router DB path
DB_DIR = os.path.join(os.environ.get("APPDATA", ""), "9router", "db")
DB_PATH = os.path.join(DB_DIR, "data.sqlite")

# SSL context (skip verification for token exchange)
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


# ──────────────────────────── Logging ──────────────────────────────────

def log(msg: str, level: str = "INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    prefix = {"INFO": "ℹ️", "OK": "✅", "ERR": "❌", "WARN": "⚠️", "DBG": "🔍"}.get(level, "•")
    print(f"[{ts}] {prefix}  {msg}")

def dbg(msg: str):
    if DEBUG_ENABLED:
        log(msg, "DBG")


# ──────────────────────────── PKCE ─────────────────────────────────────

def generate_pkce_pair() -> tuple[str, str]:
    """Generate PKCE code_verifier + S256 code_challenge."""
    code_verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def generate_state() -> str:
    return str(uuid.uuid4())


# ──────────────────────────── Kiro URL Builder ────────────────────────

def build_kiro_login_url(code_challenge: str, state: str, provider: str = "Google") -> str:
    """Build the Kiro social login URL with PKCE params."""
    params = {
        "idp": provider,
        "redirect_uri": KIRO_REDIRECT_URI,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    return f"{KIRO_LOGIN_URL}?{urlencode(params)}"


# ──────────────────────────── Token Exchange ───────────────────────────

async def exchange_code_for_tokens(code: str, code_verifier: str) -> dict | None:
    """Exchange the auth code for access + refresh tokens via Kiro API."""
    payload = {
        "code": code,
        "code_verifier": code_verifier,
        "redirect_uri": KIRO_REDIRECT_URI,
    }
    try:
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=_SSL_CTX)) as session:
            async with session.post(
                KIRO_TOKEN_URL,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    log(f"Token exchange failed ({resp.status}): {body[:200]}", "ERR")
                    return None
                data = await resp.json()
                return {
                    "access_token": data.get("accessToken", ""),
                    "refresh_token": data.get("refreshToken", ""),
                    "profile_arn": data.get("profileArn", ""),
                    "expires_in": data.get("expiresIn", 3600),
                }
    except Exception as e:
        log(f"Token exchange error: {e}", "ERR")
        return None


async def refresh_access_token(refresh_token: str) -> dict | None:
    """Refresh an expired access token using the refresh token."""
    payload = {"refreshToken": refresh_token}
    try:
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=_SSL_CTX)) as session:
            async with session.post(
                KIRO_REFRESH_URL,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json()
                return {
                    "access_token": data.get("accessToken", ""),
                    "refresh_token": data.get("refreshToken", refresh_token),
                    "profile_arn": data.get("profileArn", ""),
                    "expires_in": data.get("expiresIn", 3600),
                }
    except Exception:
        return None


# ──────────────────────────── JWT Helpers ──────────────────────────────

def extract_email_from_jwt(access_token: str) -> str | None:
    """Extract email from Kiro JWT access token (base64-encoded payload)."""
    try:
        parts = access_token.split(".")
        if len(parts) < 2:
            # Kiro tokens may not be standard JWT — try alternate extraction
            return None
        # Pad base64
        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        payload = json.loads(payload_bytes)
        return payload.get("email") or payload.get("sub") or payload.get("username")
    except Exception:
        return None


# ──────────────────────────── Redirect Interception ────────────────────

def extract_code_from_kiro_url(url: str) -> str | None:
    """Extract the auth code from a kiro:// redirect URL."""
    if "kiro://" not in url:
        return None
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        codes = params.get("code")
        return codes[0] if codes else None
    except Exception:
        return None


# ──────────────────────────── Dialog Auto-dismiss ─────────────────────

async def _auto_dismiss(dialog, email: str):
    """Auto-dismiss browser dialogs (alert, confirm, beforeunload)."""
    try:
        dbg(f"[{email}] Dialog ({dialog.type}): {dialog.message[:80]}")
        await dialog.dismiss()
    except Exception:
        pass


# ──────────────────────────── Private Network Blocker ─────────────────

_PRIVATE_PREFIXES = (
    "0.", "10.", "127.", "169.254.", "172.16.", "172.17.", "172.18.",
    "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
    "172.31.", "192.168.", "localhost", "[::1]", "[::]",
)

async def _block_private(route):
    """Block requests to private/local network IPs."""
    url = route.request.url
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        host = ""
    if host and any(host.startswith(p) or host == p.rstrip(".") for p in _PRIVATE_PREFIXES):
        dbg(f"[BLOCK] Private network request: {url[:80]}")
        await route.abort("blockedbyclient")
    else:
        await route.continue_()


# ──────────────────────────── Browser Automation ──────────────────────

async def automate_login(email: str, password: str, code_verifier: str, code_challenge: str, state: str) -> dict:
    """
    Launch browser → navigate to Kiro login → auto-fill Google SSO → capture kiro:// redirect.
    Returns dict with 'auth_code' on success, or 'error' on failure.
    """
    result: dict = {"auth_code": None, "error": None}
    login_url = build_kiro_login_url(code_challenge, state)

    dbg(f"[{email}] Login URL: {login_url[:120]}...")

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=HEADLESS,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
                # Block "X wants to access your local network" prompt
                "--disable-features=PrivateNetworkAccessRespectPreflightResults,"
                    "PrivateNetworkAccessSendPreflights,"
                    "BlockInsecurePrivateNetworkRequests,"
                    "PrivateNetworkAccessPromptForUnsureBlocked",
            ],
        )
        ctx = await browser.new_context(
            viewport={"width": 500, "height": 700},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
        )
        await ctx.add_init_script(
            "Object.defineProperty(navigator,'webdriver',{get:()=>undefined})"
        )

        page = await ctx.new_page()

        # Auto-dismiss all browser dialogs
        page.on("dialog", lambda d: asyncio.ensure_future(_auto_dismiss(d, email)))

        # Block private network requests
        await page.route("**/*", _block_private)

        page.set_default_timeout(30000)

        # ── Intercept kiro:// redirect via route handler ──
        async def route_handler(route):
            request_url = route.request.url
            code = extract_code_from_kiro_url(request_url)
            if code:
                dbg(f"[{email}] Captured kiro:// redirect, code={code[:20]}...")
                result["auth_code"] = code
                try:
                    await route.abort()
                except Exception:
                    pass
                return
            await route.continue_()

        await page.route("kiro://**", route_handler)

        # ── Also listen for response headers as fallback ──
        def on_response(response):
            try:
                location = response.headers.get("location", "")
                code = extract_code_from_kiro_url(location)
                if code and not result["auth_code"]:
                    dbg(f"[{email}] Captured code from response header: {code[:20]}...")
                    result["auth_code"] = code
            except Exception:
                pass

        page.on("response", on_response)

        # ── Navigate to Kiro login ──
        try:
            await page.goto(login_url, wait_until="domcontentloaded", timeout=30000)
        except Exception as e:
            log(f"[{email}] Navigation error: {e}", "WARN")

        # ── Drive Google SSO login ──
        google_ok = await _handle_google_login(page, email, password)
        if not google_ok:
            result["error"] = "google_login_failed"
            if HEADLESS:
                ss_path = f"debug_kiro_{email.split('@')[0]}.png"
                try:
                    await page.screenshot(path=ss_path)
                    dbg(f"[{email}] Saved debug screenshot: {ss_path}")
                except Exception:
                    pass
            await browser.close()
            return result

        # ── Wait for kiro:// redirect (poll page URL as fallback) ──
        for i in range(60):
            if result["auth_code"]:
                break
            await asyncio.sleep(1)

            # Check current URL
            try:
                current_url = page.url
                code = extract_code_from_kiro_url(current_url)
                if code:
                    result["auth_code"] = code
                    break
            except Exception:
                pass

            # Handle any post-login consent/welcome pages
            if i > 5:
                try:
                    await _try_dismiss_consent(page, email)
                except Exception:
                    pass

        await browser.close()

    if not result["auth_code"]:
        result["error"] = "no_auth_code_captured"

    return result


async def _handle_google_login(page, email: str, password: str) -> bool:
    """
    Auto-fill Google login pages (email → password → consent).
    Returns True if Google login completed successfully.
    """
    log(f"[{email}] Waiting for Google login pages...")

    email_submitted = False

    for i in range(90):
        await asyncio.sleep(1)

        try:
            current_url = page.url
        except Exception:
            break

        # ── Check if we left Google (redirected back to Kiro) ──
        if "accounts.google.com" not in current_url and i > 3:
            if "kiro" in current_url.lower() or "amazonaws" in current_url.lower():
                log(f"[{email}] Left Google → Kiro callback", "OK")
                return True
            if "kiro://" in current_url:
                return True

        # ── Password step (check BEFORE email to avoid re-fill bug) ──
        try:
            passwd_input = page.locator('input[name="Passwd"]').first
            if await passwd_input.is_visible(timeout=1500):
                log(f"[{email}] Password step detected")
                await passwd_input.click()
                await page.keyboard.press("Control+A")
                await page.keyboard.press("Backspace")
                await passwd_input.press_sequentially(password, delay=60)
                await asyncio.sleep(0.3)

                # Click Next button
                try:
                    next_btn = page.locator('#passwordNext button').first
                    await next_btn.click(force=True, timeout=5000)
                except Exception:
                    try:
                        await page.evaluate(
                            'document.querySelector("#passwordNext").querySelector("button").click()'
                        )
                    except Exception:
                        await page.keyboard.press("Enter")

                email_submitted = True
                log(f"[{email}] Password submitted")
                try:
                    await page.wait_for_load_state("domcontentloaded", timeout=10000)
                except Exception:
                    pass
                continue
        except Exception:
            pass

        # ── Email step ──
        if not email_submitted:
            try:
                email_input = page.locator('input#identifierId[type="email"]').first
                if await email_input.is_visible(timeout=1500):
                    log(f"[{email}] Email step detected")
                    await email_input.click()
                    await page.keyboard.press("Control+A")
                    await page.keyboard.press("Backspace")
                    await email_input.press_sequentially(email, delay=50)
                    await asyncio.sleep(0.3)

                    # Click Next
                    try:
                        next_btn = page.locator('#identifierNext button').first
                        await next_btn.click(force=True, timeout=5000)
                    except Exception:
                        try:
                            await page.evaluate(
                                'document.querySelector("#identifierNext").querySelector("button").click()'
                            )
                        except Exception:
                            await page.keyboard.press("Enter")

                    email_submitted = True
                    log(f"[{email}] Email submitted")
                    continue
            except Exception:
                pass

        # ── Consent / Speedbump / Welcome pages ──
        try:
            dismissed = await _try_dismiss_consent(page, email)
            if dismissed:
                continue
        except Exception:
            pass

        # ── Account chooser ──
        try:
            account = page.locator('[data-identifier]').first
            if await account.is_visible(timeout=1000):
                log(f"[{email}] Account chooser detected, clicking...")
                await account.click()
                continue
        except Exception:
            pass

    return email_submitted  # True if at least email was submitted


async def _try_dismiss_consent(page, email: str) -> bool:
    """Try to dismiss Google consent/speedbump/welcome pages. Returns True if dismissed."""
    # Method 1: Known element IDs/names (language-agnostic)
    known_selectors = [
        '#confirm',
        '#submit_approve_access',
        '#approve_button',
        'button[name="confirm"]',
        'button[name="continue"]',
        'button[name="approve"]',
        'button[name="accept"]',
        '#gaplustosNext button',
        '#gaplustosNext button[jsname="LgbsSe"]',
    ]

    for sel in known_selectors:
        try:
            el = page.locator(sel).first
            if await el.is_visible(timeout=800):
                await el.click(force=True, timeout=5000)
                dbg(f"[{email}] Clicked consent: {sel}")
                return True
        except Exception:
            continue

    # Method 2: JS-based multi-language button text matching
    try:
        clicked = await page.evaluate("""() => {
            const consentTexts = [
                'i understand', 'i agree', 'agree', 'allow', 'continue', 'next',
                'approve', 'confirm', 'accept', 'got it', 'accept all', 'done',
                'i accept', 'accept & continue',
                'saya mengerti', 'saya setuju', 'setuju', 'lanjutkan', 'terima',
                'izinkan', 'konfirmasi', 'mengerti',
            ];
            const buttons = document.querySelectorAll(
                'button, div[role="button"], a[role="button"], ' +
                '[jsname="LgbsSe"], [jsname="V67aGc"]'
            );
            for (const btn of buttons) {
                const text = (btn.textContent || '').trim().toLowerCase();
                const ariaLabel = (btn.getAttribute('aria-label') || '').toLowerCase();
                for (const t of consentTexts) {
                    if (text === t || text.includes(t) || ariaLabel.includes(t)) {
                        // Click parent button if this is a span
                        const target = btn.closest('button') || btn;
                        target.click();
                        return target.textContent?.trim() || 'clicked';
                    }
                }
            }
            return null;
        }""")
        if clicked:
            dbg(f"[{email}] Clicked consent via JS: '{clicked}'")
            return True
    except Exception:
        pass

    return False


# ──────────────────────────── 9router DB ──────────────────────────────

def get_existing_kiro_emails() -> set[str]:
    """Read existing Kiro emails from 9router DB for dedup."""
    emails = set()
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "SELECT LOWER(email) FROM providerConnections "
            "WHERE provider='kiro' AND email IS NOT NULL"
        )
        for row in c.fetchall():
            if row[0]:
                emails.add(row[0])
        conn.close()
    except Exception as e:
        log(f"Could not read existing connections: {e}", "WARN")
    return emails


def save_to_9router_db(
    email: str,
    access_token: str,
    refresh_token: str,
    profile_arn: str,
    expires_in: int,
    auth_method: str = "google",
) -> bool:
    """Insert or update a Kiro connection in 9router DB."""
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(seconds=expires_in)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    now_iso = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    data = {
        "accessToken": access_token,
        "refreshToken": refresh_token,
        "expiresAt": expires_at,
        "expiresIn": expires_in,
        "testStatus": "active",
        "providerSpecificData": {
            "profileArn": profile_arn,
            "authMethod": auth_method,
            "provider": auth_method.capitalize() if auth_method else "Google",
        },
    }
    data_json = json.dumps(data)

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Check for existing connection
        c.execute(
            "SELECT id FROM providerConnections WHERE provider='kiro' AND email=?",
            (email,),
        )
        existing = c.fetchone()

        if existing:
            # UPDATE existing
            c.execute(
                "UPDATE providerConnections SET data=?, name=?, updatedAt=?, isActive=1 WHERE id=?",
                (data_json, email, now_iso, existing[0]),
            )
            conn.commit()
            conn.close()
            log(f"[{email}] Updated existing Kiro connection", "OK")
            return True
        else:
            # INSERT new
            c.execute(
                "SELECT COALESCE(MAX(priority),0)+1 FROM providerConnections WHERE provider='kiro'"
            )
            next_priority = c.fetchone()[0]

            new_id = str(uuid.uuid4())
            c.execute(
                "INSERT INTO providerConnections "
                "(id, provider, authType, name, email, priority, isActive, data, createdAt, updatedAt) "
                "VALUES (?, 'kiro', 'oauth', ?, ?, ?, 1, ?, ?, ?)",
                (new_id, email, email, next_priority, data_json, now_iso, now_iso),
            )
            conn.commit()
            conn.close()
            log(f"[{email}] Created new Kiro connection (priority={next_priority})", "OK")
            return True

    except Exception as e:
        log(f"[{email}] DB save failed: {e}", "ERR")
        return False


# ──────────────────────────── Account Processor ──────────────────────

async def process_account(email: str, password: str, test_only: bool = False) -> dict:
    """Full flow for a single account: login → token exchange → save."""
    start_time = time.time()
    log(f"[{email}] Starting Kiro login flow...")

    # Step 1: Generate PKCE
    code_verifier, code_challenge = generate_pkce_pair()
    state = generate_state()

    # Step 2: Browser automation
    browser_result = await automate_login(email, password, code_verifier, code_challenge, state)

    if browser_result.get("error"):
        elapsed = time.time() - start_time
        log(f"[{email}] Login failed: {browser_result['error']} ({elapsed:.1f}s)", "ERR")
        return {"success": False, "email": email, "error": browser_result["error"]}

    auth_code = browser_result["auth_code"]
    log(f"[{email}] Auth code captured: {auth_code[:20]}...")

    # Step 3: Exchange code for tokens
    log(f"[{email}] Exchanging code for tokens...")
    tokens = await exchange_code_for_tokens(auth_code, code_verifier)

    if not tokens or not tokens.get("access_token"):
        elapsed = time.time() - start_time
        log(f"[{email}] Token exchange failed ({elapsed:.1f}s)", "ERR")
        return {"success": False, "email": email, "error": "token_exchange_failed"}

    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]
    profile_arn = tokens["profile_arn"]
    expires_in = tokens["expires_in"]

    log(f"[{email}] Tokens received (expires in {expires_in}s)")

    # Step 4: Extract email from JWT (if possible)
    jwt_email = extract_email_from_jwt(access_token)
    if jwt_email:
        dbg(f"[{email}] JWT email: {jwt_email}")

    # Step 5: Save to DB (unless test mode)
    if test_only:
        elapsed = time.time() - start_time
        log(f"[{email}] Test mode — skipping DB save ({elapsed:.1f}s)", "OK")
        return {
            "success": True,
            "email": email,
            "access_token": access_token[:20] + "...",
            "refresh_token": refresh_token[:20] + "...",
            "profile_arn": profile_arn[:40] + "..." if profile_arn else "",
            "expires_in": expires_in,
            "elapsed": elapsed,
        }

    db_ok = save_to_9router_db(
        email=email,
        access_token=access_token,
        refresh_token=refresh_token,
        profile_arn=profile_arn,
        expires_in=expires_in,
        auth_method="google",
    )

    elapsed = time.time() - start_time
    if db_ok:
        log(f"[{email}] Done in {elapsed:.1f}s", "OK")
        return {
            "success": True,
            "email": email,
            "profile_arn": profile_arn,
            "expires_in": expires_in,
            "elapsed": elapsed,
        }
    else:
        return {"success": False, "email": email, "error": "db_save_failed", "elapsed": elapsed}


# ──────────────────────────── Batch Processing ────────────────────────

async def run_batch(accounts: list[tuple[str, str]], test_only: bool = False, concurrent: int = 1):
    """Process multiple accounts with semaphore-based concurrency."""
    sem = asyncio.Semaphore(concurrent)
    results = []

    async def _run(email: str, password: str):
        async with sem:
            return await process_account(email, password, test_only)

    tasks = [_run(email, pw) for email, pw in accounts]
    gathered = await asyncio.gather(*tasks, return_exceptions=True)

    for i, r in enumerate(gathered):
        if isinstance(r, Exception):
            email = accounts[i][0]
            results.append({"success": False, "email": email, "error": str(r)})
        else:
            results.append(r)

    return results


# ──────────────────────────── CLI ─────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Kiro Auto-Login for 9router",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python kiro_autologin.py user@gmail.com:password
  python kiro_autologin.py --batch accounts.txt
  python kiro_autologin.py --batch accounts.txt --headless --concurrent 3
  python kiro_autologin.py --test user@gmail.com:password
""",
    )
    parser.add_argument("accounts", nargs="*", help="email:password pairs")
    parser.add_argument("--batch", "-b", help="Read accounts from file (one email:password per line)")
    parser.add_argument("--test", "-t", action="store_true", help="Test mode: don't save to DB")
    parser.add_argument("--headless", action="store_true", help="Run browser in headless mode")
    parser.add_argument("--concurrent", "-c", type=int, default=1, help="Concurrent browser sessions")
    parser.add_argument("--debug", "-d", action="store_true", help="Enable debug output")
    parser.add_argument("--no-skip-existing", action="store_true", help="Re-login existing accounts")
    return parser.parse_args()


# ──────────────────────────── Main ────────────────────────────────────

async def async_main():
    global HEADLESS, DEBUG_ENABLED

    args = parse_args()

    if args.debug:
        DEBUG_ENABLED = True
    if args.headless:
        HEADLESS = True

    log(f"Kiro Auto-Login v{VERSION}")
    log(f"Headless: {HEADLESS} | Concurrent: {args.concurrent} | Test: {args.test}")

    # ── Validate environment ──
    if not os.path.exists(DB_PATH) and not args.test:
        log(f"9router DB not found at: {DB_PATH}", "ERR")
        log("Make sure 9router is installed and has been started at least once.", "ERR")
        sys.exit(1)

    # ── Collect accounts ──
    accounts: list[tuple[str, str]] = []

    # From positional args
    for acc in (args.accounts or []):
        if ":" in acc:
            parts = acc.split(":", 1)
            accounts.append((parts[0].strip(), parts[1].strip()))

    # From batch file
    if args.batch:
        batch_path = args.batch
        if not os.path.exists(batch_path):
            log(f"Batch file not found: {batch_path}", "ERR")
            sys.exit(1)
        with open(batch_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" in line:
                    parts = line.split(":", 1)
                    accounts.append((parts[0].strip(), parts[1].strip()))

    if not accounts:
        log("No accounts provided. Use: python kiro_autologin.py email:password", "ERR")
        sys.exit(1)

    log(f"Accounts loaded: {len(accounts)}")

    # ── Skip existing accounts ──
    if not args.test and not args.no_skip_existing:
        existing = get_existing_kiro_emails()
        if existing:
            original_count = len(accounts)
            accounts = [(e, p) for e, p in accounts if e.lower() not in existing]
            skipped = original_count - len(accounts)
            if skipped > 0:
                log(f"Skipped {skipped} existing accounts (use --no-skip-existing to override)")
            if not accounts:
                log("All accounts already exist in DB. Nothing to do.", "WARN")
                sys.exit(0)

    # ── Process ──
    if len(accounts) == 1:
        results = [await process_account(accounts[0][0], accounts[0][1], args.test)]
    else:
        results = await run_batch(accounts, args.test, args.concurrent)

    # ── Summary ──
    success = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]

    print()
    log("=" * 50)
    log(f"SUMMARY: {len(success)} ✅  |  {len(failed)} ❌  |  {len(results)} total")
    log("=" * 50)

    for r in success:
        elapsed = r.get("elapsed", 0)
        log(f"  ✅ {r['email']} ({elapsed:.1f}s)")

    for r in failed:
        log(f"  ❌ {r['email']} — {r.get('error', 'unknown')}")

    if failed:
        sys.exit(1)


def main():
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
