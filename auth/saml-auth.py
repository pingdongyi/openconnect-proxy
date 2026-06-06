#!/usr/bin/env python3
"""Provider-based SAML/OAuth auth engine for OpenConnect VPN.

Reads a declarative YAML provider config (Microsoft, Okta, or custom) and
drives headless Chromium through the login flow to extract session cookies.

Env vars:
    VPN_URL             - VPN gateway URL (required)
    VPN_USER            - IdP username (required)
    VPN_PASSWORD        - IdP password (required)
    VPN_TOTP_SECRET     - TOTP secret for MFA auto-fill (optional)
    VPN_PROTOCOL        - anyconnect (default) or globalprotect
    VPN_AUTHGROUP       - AnyConnect tunnel group / connection profile (optional)
    VPN_AUTH_PROVIDER   - Built-in preset: microsoft, okta, generic (default: microsoft)
    VPN_AUTH_CONFIG     - Path to custom provider YAML (overrides VPN_AUTH_PROVIDER)
    AUTH_OUTPUT_FILE    - Write cookie JSON to this path (default: /auth/cookie.json)
    AUTH_TIMEOUT        - Override provider timeout in seconds
    AUTH_DEBUG          - Set to 1 for debug screenshots and verbose logging
"""

import json
import http.cookiejar
import os
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml
from playwright.sync_api import sync_playwright


ANYCONNECT_VERSION = "4.7.00136"
ANYCONNECT_USER_AGENT = "AnyConnect"


def log(msg):
    print(f"[saml-auth] {msg}", file=sys.stderr)


def debug(msg):
    if os.environ.get("AUTH_DEBUG") == "1":
        print(f"[saml-auth][DEBUG] {msg}", file=sys.stderr)


def get_totp_code(secret):
    import pyotp

    return pyotp.TOTP(secret).now()


def load_provider(provider_name, custom_path=None):
    if custom_path and os.path.isfile(custom_path):
        log(f"Loading custom provider config: {custom_path}")
        with open(custom_path) as f:
            return yaml.safe_load(f)

    providers_dir = Path(__file__).parent / "providers"
    path = providers_dir / f"{provider_name}.yaml"
    if not path.exists():
        log(f"Provider '{provider_name}' not found, falling back to 'generic'")
        path = providers_dir / "generic.yaml"
    log(f"Using provider: {path.stem}")
    with open(path) as f:
        return yaml.safe_load(f)


def build_anyconnect_init_payload(vpn_url, auth_group):
    root = ET.Element(
        "config-auth",
        {"client": "vpn", "type": "init", "aggregate-auth-version": "2"},
    )
    version = ET.SubElement(root, "version", {"who": "vpn"})
    version.text = ANYCONNECT_VERSION
    ET.SubElement(root, "device-id").text = "linux-64"
    ET.SubElement(root, "group-select").text = auth_group or ""
    ET.SubElement(root, "group-access").text = vpn_url
    capabilities = ET.SubElement(root, "capabilities")
    ET.SubElement(capabilities, "auth-method").text = "single-sign-on-v2"
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def find_xml_text(root, tag_name):
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] == tag_name and element.text:
            return element.text.strip()
    return None


def normalize_vpn_url(vpn_url):
    parsed = urllib.parse.urlparse(
        vpn_url if "://" in vpn_url else f"https://{vpn_url}"
    )
    return urllib.parse.urlunparse(parsed._replace(fragment=""))


def create_anyconnect_opener(ignore_tls_errors=False):
    cookie_jar = http.cookiejar.CookieJar()
    handlers = [urllib.request.HTTPCookieProcessor(cookie_jar)]
    if ignore_tls_errors:
        handlers.append(
            urllib.request.HTTPSHandler(context=ssl._create_unverified_context())
        )
    return urllib.request.build_opener(*handlers)


def get_actual_url(opener, vpn_url):
    request_url = normalize_vpn_url(vpn_url)
    parsed = urllib.parse.urlparse(request_url)
    request = urllib.request.Request(
        request_url,
        headers={
            "Host": parsed.netloc,
            "User-Agent": ANYCONNECT_USER_AGENT,
        },
        method="GET",
    )
    try:
        with opener.open(request, timeout=60) as response:
            return response.geturl()
    except Exception as exc:
        raise RuntimeError(
            f"Could not resolve AnyConnect gateway URL from {request_url}: {exc}"
        ) from exc


def initialize_anyconnect_auth(vpn_url, auth_group=None, ignore_tls_errors=False):
    opener = create_anyconnect_opener(ignore_tls_errors)
    target_url = get_actual_url(opener, vpn_url)
    debug(f"Resolved AnyConnect gateway URL: {target_url}")
    request = urllib.request.Request(
        target_url,
        data=build_anyconnect_init_payload(target_url, auth_group),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": ANYCONNECT_USER_AGENT,
        },
        method="POST",
    )
    try:
        with opener.open(request, timeout=60) as response:
            response_root = ET.fromstring(response.read())
    except Exception as exc:
        if os.environ.get("AUTH_DEBUG") == "1" and hasattr(exc, "read"):
            try:
                debug(f"AnyConnect init error response: {exc.read().decode(errors='replace')}")
            except Exception:
                pass
        raise RuntimeError(
            f"AnyConnect authentication initialization failed for {target_url}: {exc}"
        ) from exc

    sso_login = find_xml_text(response_root, "sso-v2-login")
    if not sso_login:
        raise RuntimeError(
            "AnyConnect authentication response did not contain sso-v2-login"
        )

    return {
        "target_url": target_url,
        "opener": opener,
        "saml_url": urllib.parse.urljoin(target_url, sso_login),
        "tunnel_group": find_xml_text(response_root, "tunnel-group") or "",
        "aggauth_handle": find_xml_text(response_root, "aggauth-handle") or "",
        "config_hash": find_xml_text(response_root, "config-hash") or "",
        "token_cookie_name": find_xml_text(
            response_root, "sso-v2-token-cookie-name"
        ),
    }


def build_saml_url(
    vpn_url, protocol, provider, auth_group=None, ignore_tls_errors=False
):
    parsed = urllib.parse.urlparse(
        vpn_url if "://" in vpn_url else f"https://{vpn_url}"
    )
    if protocol == "anyconnect":
        return initialize_anyconnect_auth(
            vpn_url, auth_group, ignore_tls_errors
        )["saml_url"]

    base = f"{parsed.scheme}://{parsed.netloc}"
    saml_paths = provider.get("saml_paths", {})
    path = saml_paths.get(protocol, saml_paths.get("anyconnect", "/"))
    return f"{base}{path}"


def build_anyconnect_confirmation_payload(auth_init, sso_token):
    root = ET.Element(
        "config-auth",
        {"client": "vpn", "type": "auth-reply", "aggregate-auth-version": "2"},
    )
    version = ET.SubElement(root, "version", {"who": "vpn"})
    version.text = ANYCONNECT_VERSION
    ET.SubElement(root, "device-id").text = "linux-64"
    ET.SubElement(root, "session-token")
    ET.SubElement(root, "session-id")
    capabilities = ET.SubElement(root, "capabilities")
    ET.SubElement(capabilities, "auth-method").text = "single-sign-on-v2"
    opaque = ET.SubElement(root, "opaque", {"is-for": "sg"})
    ET.SubElement(opaque, "tunnel-group").text = auth_init["tunnel_group"]
    ET.SubElement(opaque, "aggauth-handle").text = auth_init["aggauth_handle"]
    ET.SubElement(opaque, "auth-method").text = "single-sign-on-v2"
    ET.SubElement(opaque, "config-hash").text = auth_init["config_hash"]
    auth = ET.SubElement(root, "auth")
    ET.SubElement(auth, "sso-token").text = sso_token
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def confirm_anyconnect_auth(auth_init, sso_token, ignore_tls_errors=False):
    request = urllib.request.Request(
        auth_init["target_url"],
        data=build_anyconnect_confirmation_payload(auth_init, sso_token),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": ANYCONNECT_USER_AGENT,
        },
        method="POST",
    )
    opener = auth_init.get("opener")
    if opener is None:
        opener = create_anyconnect_opener(ignore_tls_errors)

    try:
        with opener.open(request, timeout=60) as response:
            response_root = ET.fromstring(response.read())
    except Exception as exc:
        raise RuntimeError(
            f"AnyConnect authentication confirmation failed: {exc}"
        ) from exc

    session_token = find_xml_text(response_root, "session-token")
    server_cert_hash = find_xml_text(response_root, "server-cert-hash")
    if not session_token:
        raise RuntimeError(
            "AnyConnect authentication confirmation did not return a session-token"
        )
    return session_token, server_cert_hash


def find_field(page, field_cfg):
    """Find a visible input field using IDs, labels, types, attrs, and scoring."""
    # 1) Try explicit IDs
    for element_id in field_cfg.get("ids", []):
        for frame in page.frames:
            try:
                loc = frame.locator(f"#{element_id}")
                if loc.count() > 0 and loc.first.is_visible():
                    debug(f"Found field by ID: #{element_id}")
                    return loc.first
            except Exception:
                continue

    # 2) Try explicit attribute selectors
    for attr_sel in field_cfg.get("attrs", []):
        for frame in page.frames:
            try:
                loc = frame.locator(f"input[{attr_sel}]")
                if loc.count() > 0 and loc.first.is_visible():
                    debug(f"Found field by attr: input[{attr_sel}]")
                    return loc.first
            except Exception:
                continue

    # 3) Try labels
    for label in field_cfg.get("labels", []):
        pattern = re.compile(re.escape(label), re.IGNORECASE)
        for frame in page.frames:
            try:
                loc = frame.get_by_label(pattern)
                if loc.count() > 0 and loc.first.is_visible():
                    debug(f"Found field by label: {label}")
                    return loc.first
            except Exception:
                continue

    # 4) Fallback: find by input type
    for input_type in field_cfg.get("types", []):
        for frame in page.frames:
            try:
                loc = frame.locator(f"input[type='{input_type}']")
                if loc.count() > 0 and loc.first.is_visible():
                    debug(f"Found field by type: input[type='{input_type}']")
                    return loc.first
            except Exception:
                continue

    return None


def click_button(page, button_cfg):
    """Click a button using IDs, labels, and CSS selectors."""
    # 1) Try explicit IDs
    for element_id in button_cfg.get("ids", []):
        for frame in page.frames:
            try:
                loc = frame.locator(f"#{element_id}")
                if loc.count() > 0 and loc.first.is_visible():
                    debug(f"Clicked button by ID: #{element_id}")
                    loc.first.click()
                    return True
            except Exception:
                continue

    # 2) Try labels (buttons and submit inputs)
    for label in button_cfg.get("labels", []):
        pattern = re.compile(re.escape(label), re.IGNORECASE)
        for frame in page.frames:
            for role in ["button", "link"]:
                try:
                    loc = frame.get_by_role(role, name=pattern)
                    if loc.count() > 0 and loc.first.is_visible():
                        debug(f"Clicked {role} by label: {label}")
                        loc.first.click()
                        return True
                except Exception:
                    continue
            try:
                loc = frame.locator("input[type='submit']")
                for idx in range(min(loc.count(), 10)):
                    candidate = loc.nth(idx)
                    value = (candidate.get_attribute("value") or "").strip()
                    if value and pattern.search(value) and candidate.is_visible():
                        debug(f"Clicked submit input by value: {value}")
                        candidate.click()
                        return True
            except Exception:
                continue

    # 3) Try explicit CSS selectors
    for selector in button_cfg.get("selectors", []):
        for frame in page.frames:
            try:
                loc = frame.locator(selector)
                if loc.count() > 0 and loc.first.is_visible():
                    debug(f"Clicked button by selector: {selector}")
                    loc.first.click()
                    return True
            except Exception:
                continue

    return False


def click_text(page, texts):
    """Click first visible element matching any of the given texts."""
    for text in texts:
        pattern = re.compile(re.escape(text), re.IGNORECASE)
        for frame in page.frames:
            for role in ["button", "link"]:
                try:
                    loc = frame.get_by_role(role, name=pattern)
                    if loc.count() > 0 and loc.first.is_visible():
                        debug(f"Clicked text: {text}")
                        loc.first.click()
                        return True
                except Exception:
                    continue
            try:
                loc = frame.get_by_text(pattern, exact=False)
                if loc.count() > 0 and loc.first.is_visible():
                    debug(f"Clicked text (fallback): {text}")
                    loc.first.click()
                    return True
            except Exception:
                continue
    return False


def page_has_text(page, texts):
    """Check if any of the given texts appear on the page."""
    for text in texts:
        for frame in page.frames:
            try:
                loc = frame.get_by_text(text, exact=False)
                if loc.count() > 0:
                    return True
            except Exception:
                continue
    return False


def is_vpn_url(url, vpn_host):
    try:
        return urllib.parse.urlparse(url).hostname == vpn_host
    except Exception:
        return False


def cookie_domain_matches(domain, vpn_host):
    domain = domain.lstrip(".")
    return domain == vpn_host or vpn_host.endswith(f".{domain}")


def extract_cookies(context, vpn_host, cookie_names):
    """Extract VPN session cookies from browser context."""
    cookies = context.cookies()
    result = {}
    for cookie in cookies:
        if cookie.get("value") and cookie_domain_matches(
            cookie.get("domain", ""), vpn_host
        ):
            if cookie["name"] in cookie_names:
                result[cookie["name"]] = cookie["value"]
    return result


def get_auth_timeout(provider):
    configured_timeout = os.environ.get("AUTH_TIMEOUT")
    if configured_timeout is None or not configured_timeout.strip():
        configured_timeout = provider.get("timeout", 90)
    return int(configured_timeout)


def authentication_complete(anyconnect_auth, saml_result, vpn_cookies):
    if anyconnect_auth and anyconnect_auth.get("token_cookie_name"):
        return bool(saml_result.get("sso_token"))
    return bool(
        saml_result.get("saml_response")
        or saml_result.get("prelogin_cookie")
        or vpn_cookies
    )


def run_auth():
    vpn_url = os.environ.get("VPN_URL")
    vpn_user = os.environ.get("VPN_USER")
    vpn_password = os.environ.get("VPN_PASSWORD")
    totp_secret = os.environ.get("VPN_TOTP_SECRET")
    protocol = os.environ.get("VPN_PROTOCOL", "anyconnect")
    auth_group = os.environ.get("VPN_AUTHGROUP")
    provider_name = os.environ.get("VPN_AUTH_PROVIDER", "microsoft")
    custom_config = os.environ.get("VPN_AUTH_CONFIG")
    output_file = os.environ.get("AUTH_OUTPUT_FILE", "/auth/cookie.json")

    if not vpn_url or not vpn_user or not vpn_password:
        log("Error: VPN_URL, VPN_USER, and VPN_PASSWORD are required")
        sys.exit(1)

    provider = load_provider(provider_name, custom_config)
    timeout = get_auth_timeout(provider)

    parsed = urllib.parse.urlparse(
        vpn_url if "://" in vpn_url else f"https://{vpn_url}"
    )
    vpn_host = parsed.hostname or vpn_url

    ignore_tls = os.environ.get("AUTH_IGNORE_TLS_ERRORS", "0") == "1"
    anyconnect_auth = None
    if protocol == "anyconnect":
        anyconnect_auth = initialize_anyconnect_auth(
            vpn_url, auth_group, ignore_tls_errors=ignore_tls
        )
        saml_url = anyconnect_auth["saml_url"]
    else:
        saml_url = build_saml_url(
            vpn_url, protocol, provider, auth_group, ignore_tls_errors=ignore_tls
        )
    cookie_names = provider.get("cookies", {}).get(
        protocol, provider.get("cookies", {}).get("anyconnect", [])
    )
    if anyconnect_auth and anyconnect_auth["token_cookie_name"]:
        cookie_names = [*cookie_names, anyconnect_auth["token_cookie_name"]]

    log(f"Provider: {provider.get('name', provider_name)}")
    log(f"VPN host: {vpn_host} | Protocol: {protocol}")
    log(f"SAML URL: {saml_url}")
    if anyconnect_auth and anyconnect_auth["token_cookie_name"]:
        debug(
            "AnyConnect SSO token cookie: "
            f"{anyconnect_auth['token_cookie_name']}"
        )
    log(f"Timeout: {timeout}s")

    if ignore_tls:
        log("WARNING: TLS certificate validation is DISABLED (AUTH_IGNORE_TLS_ERRORS=1)")
        log("Your credentials will be sent without verifying server certificates.")
        log("Only use this for testing or if you have mounted a custom CA certificate.")

    saml_result = {
        "saml_response": None,
        "prelogin_cookie": None,
        "sso_token": None,
    }

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"],
        )
        context = browser.new_context(
            ignore_https_errors=ignore_tls,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        )
        page = context.new_page()

        # Intercept VPN-bound requests for SAMLResponse / prelogin-cookie
        def handle_request(request):
            if not is_vpn_url(request.url, vpn_host):
                return
            if request.post_data:
                try:
                    params = urllib.parse.parse_qs(request.post_data)
                    if "SAMLResponse" in params:
                        saml_result["saml_response"] = params["SAMLResponse"][0]
                        debug(f"Captured SAMLResponse ({len(saml_result['saml_response'])} chars)")
                    if "prelogin-cookie" in params:
                        saml_result["prelogin_cookie"] = params["prelogin-cookie"][0]
                        debug("Captured prelogin-cookie from POST")
                except Exception:
                    pass

        def handle_response(response):
            if not is_vpn_url(response.url, vpn_host):
                return
            try:
                headers = response.headers
                if "prelogin-cookie" in headers:
                    saml_result["prelogin_cookie"] = headers["prelogin-cookie"]
                    debug("Captured prelogin-cookie from response header")
            except Exception:
                pass

        page.on("request", handle_request)
        page.on("response", handle_response)

        # Navigate to SAML URL
        log("Opening SAML portal...")
        for wait_until in ["domcontentloaded", "load", "networkidle"]:
            try:
                page.goto(saml_url, timeout=60000, wait_until=wait_until)
                break
            except Exception as e:
                debug(f"goto with wait_until={wait_until} failed: {e}")
                time.sleep(1)

        if os.environ.get("AUTH_DEBUG") == "1":
            page.screenshot(path="/tmp/saml-step1-portal.png")

        time.sleep(1)

        # Main auth loop — handle the non-deterministic login flow
        fields = provider.get("fields", {})
        buttons = provider.get("buttons", {})
        prompts = provider.get("prompts", {})
        filled_username = False
        filled_password = False
        filled_otp = False
        deadline = time.time() + timeout
        step = 0
        vpn_cookies = {}

        while time.time() < deadline:
            vpn_cookies = extract_cookies(context, vpn_host, cookie_names)
            if anyconnect_auth and anyconnect_auth["token_cookie_name"]:
                saml_result["sso_token"] = vpn_cookies.get(
                    anyconnect_auth["token_cookie_name"]
                )

            if authentication_complete(anyconnect_auth, saml_result, vpn_cookies):
                break

            progressed = False
            step += 1

            # Handle "Pick an account" prompt
            pick_cfg = prompts.get("pick_account", {})
            if pick_cfg.get("detect") and page_has_text(page, pick_cfg["detect"]):
                debug("Detected: pick account page")
                if click_text(page, pick_cfg.get("click", [])):
                    progressed = True
                elif click_button(page, buttons.get("next", {})):
                    progressed = True

            # Fill username
            if vpn_user and not filled_username:
                user_field = find_field(page, fields.get("username", {}))
                if user_field:
                    try:
                        user_field.fill(vpn_user)
                        filled_username = True
                        progressed = True
                        log("Filled username")
                        # Only click next if password field is NOT already visible
                        if not find_field(page, fields.get("password", {})):
                            click_button(page, buttons.get("next", {}))
                    except Exception as e:
                        debug(f"Failed to fill username: {e}")

            # Fill password
            if vpn_password and not filled_password:
                pass_field = find_field(page, fields.get("password", {}))
                if pass_field:
                    try:
                        pass_field.fill(vpn_password)
                        filled_password = True
                        progressed = True
                        log("Filled password")
                        click_button(page, buttons.get("sign_in", {}))
                        try:
                            pass_field.press("Enter")
                        except Exception:
                            pass
                    except Exception as e:
                        debug(f"Failed to fill password: {e}")

            # Handle MFA alternative selection (before OTP)
            mfa_alt_cfg = prompts.get("mfa_alternatives", {})
            if mfa_alt_cfg.get("click") and not filled_otp:
                if click_text(page, mfa_alt_cfg.get("click", [])):
                    progressed = True

            # Select TOTP method if needed
            totp_sel_cfg = prompts.get("mfa_totp_select", {})
            if totp_sel_cfg.get("click") and not filled_otp:
                if click_text(page, totp_sel_cfg.get("click", [])):
                    progressed = True
                # Also try direct selector
                sel = totp_sel_cfg.get("selector")
                if sel:
                    for frame in page.frames:
                        try:
                            loc = frame.locator(sel)
                            if loc.count() > 0 and loc.first.is_visible():
                                loc.first.click()
                                progressed = True
                                break
                        except Exception:
                            continue

            # Fill OTP
            if totp_secret and not filled_otp:
                otp_field = find_field(page, fields.get("otp", {}))
                if otp_field:
                    try:
                        otp_field.fill(get_totp_code(totp_secret))
                        filled_otp = True
                        progressed = True
                        log("Filled TOTP code")
                        click_button(page, buttons.get("verify", {}))
                    except Exception as e:
                        debug(f"Failed to fill OTP: {e}")

            # Handle "Stay signed in?" prompt
            stay_cfg = prompts.get("stay_signed_in", {})
            if stay_cfg.get("detect") and page_has_text(page, stay_cfg["detect"]):
                debug("Detected: stay signed in prompt")
                if click_text(page, stay_cfg.get("click", [])):
                    progressed = True
                elif click_button(page, buttons.get("next", {})):
                    progressed = True

            if progressed:
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=5000)
                except Exception:
                    pass
                time.sleep(0.5)
            else:
                time.sleep(1)

            if os.environ.get("AUTH_DEBUG") == "1" and step % 5 == 0:
                page.screenshot(path=f"/tmp/saml-step-{step}.png")

        # Wait a bit for final redirects
        time.sleep(2)

        # Collect cookies
        vpn_cookies = extract_cookies(context, vpn_host, cookie_names)
        if anyconnect_auth and anyconnect_auth["token_cookie_name"]:
            saml_result["sso_token"] = vpn_cookies.get(
                anyconnect_auth["token_cookie_name"]
            )
        final_page_url = page.url
        all_vpn_cookie_names = sorted(
            cookie["name"]
            for cookie in context.cookies()
            if cookie_domain_matches(cookie.get("domain", ""), vpn_host)
        )
        browser.close()

    session_token = None
    server_cert_hash = None
    if anyconnect_auth and saml_result["sso_token"]:
        log("Confirming AnyConnect SSO authentication...")
        session_token, server_cert_hash = confirm_anyconnect_auth(
            anyconnect_auth,
            saml_result["sso_token"],
            ignore_tls_errors=ignore_tls,
        )

    return write_result(
        vpn_cookies,
        saml_result,
        vpn_host,
        protocol,
        output_file,
        session_token=session_token,
        server_cert_hash=server_cert_hash,
        diagnostic_url=final_page_url,
        diagnostic_cookie_names=all_vpn_cookie_names,
    )


def write_result(
    vpn_cookies,
    saml_result,
    vpn_host,
    protocol,
    output_file,
    session_token=None,
    server_cert_hash=None,
    diagnostic_url=None,
    diagnostic_cookie_names=None,
):
    """Build the cookie string and write result JSON."""
    cookie_parts = []

    if session_token:
        cookie_parts.append(session_token)
    elif saml_result.get("saml_response"):
        cookie_parts.append(f"SAMLResponse={saml_result['saml_response']}")
    if not session_token and saml_result.get("prelogin_cookie"):
        cookie_parts.append(f"prelogin-cookie={saml_result['prelogin_cookie']}")
    if not session_token:
        for name, value in vpn_cookies.items():
            cookie_parts.append(f"{name}={value}")

    if not cookie_parts:
        log("Error: Failed to extract VPN session cookie")
        if diagnostic_url:
            log(f"Final browser URL: {diagnostic_url}")
        if diagnostic_cookie_names:
            log(
                "VPN cookies observed: "
                + ", ".join(diagnostic_cookie_names)
            )
        log("Tips: set AUTH_DEBUG=1 for screenshots, or try VPN_AUTH_PROVIDER=generic")
        sys.exit(1)

    cookie_string = "; ".join(cookie_parts)
    result = {
        "cookie": cookie_string,
        "host": vpn_host,
        "timestamp": int(time.time()),
        "protocol": protocol,
    }
    if server_cert_hash:
        result["server_cert_hash"] = server_cert_hash

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    log(f"Cookie saved to {output_file}")
    print(cookie_string)


if __name__ == "__main__":
    run_auth()
