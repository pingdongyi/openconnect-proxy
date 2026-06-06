import importlib.util
import io
import sys
import types
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock


playwright = types.ModuleType("playwright")
playwright_sync_api = types.ModuleType("playwright.sync_api")
playwright_sync_api.sync_playwright = None
sys.modules.setdefault("playwright", playwright)
sys.modules.setdefault("playwright.sync_api", playwright_sync_api)

MODULE_PATH = Path(__file__).parents[2] / "auth" / "saml-auth.py"
SPEC = importlib.util.spec_from_file_location("saml_auth", MODULE_PATH)
saml_auth = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(saml_auth)


class FakeResponse(io.BytesIO):
    def __init__(self, body=b"", url="https://vpn.example.com"):
        super().__init__(body)
        self.url = url

    def geturl(self):
        return self.url


def fake_opener(*responses):
    opener = mock.Mock()
    opener.open.side_effect = responses
    return opener


class BuildSamlUrlTest(unittest.TestCase):
    def test_get_actual_url_follows_redirects(self):
        opener = fake_opener(
            FakeResponse(url="https://vpn.example.com/actual-group")
        )

        result = saml_auth.get_actual_url(opener, "vpn.example.com")

        self.assertEqual(result, "https://vpn.example.com/actual-group")
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "https://vpn.example.com")
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.headers["Host"], "vpn.example.com")

    def test_anyconnect_initializes_auth_with_authgroup(self):
        response_xml = b"""\
            <config-auth xmlns="urn:test">
              <opaque>
                <tunnel-group>employees</tunnel-group>
                <aggauth-handle>auth-handle</aggauth-handle>
                <config-hash>config-hash</config-hash>
              </opaque>
              <auth><sso-v2-login>/dynamic/saml/login</sso-v2-login></auth>
              <auth>
                <sso-v2-token-cookie-name>acSamlv2Token</sso-v2-token-cookie-name>
              </auth>
            </config-auth>
        """

        opener = fake_opener(
            FakeResponse(url="https://vpn.example.com/actual-group"),
            FakeResponse(response_xml),
        )
        with mock.patch.object(
            saml_auth, "create_anyconnect_opener", return_value=opener
        ):
            result = saml_auth.build_saml_url(
                "vpn.example.com", "anyconnect", {}, "employees"
            )

        self.assertEqual(result, "https://vpn.example.com/dynamic/saml/login")
        request = opener.open.call_args_list[1].args[0]
        self.assertEqual(request.full_url, "https://vpn.example.com/actual-group")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(
            request.headers["Content-type"], "application/x-www-form-urlencoded"
        )

        payload = ET.fromstring(request.data)
        self.assertEqual(payload.attrib["type"], "init")
        self.assertEqual(payload.findtext("group-select"), "employees")
        self.assertEqual(
            payload.findtext("group-access"),
            "https://vpn.example.com/actual-group",
        )
        self.assertEqual(
            payload.findtext("capabilities/auth-method"), "single-sign-on-v2"
        )

    def test_anyconnect_initialization_returns_confirmation_metadata(self):
        response_xml = b"""\
            <config-auth>
              <opaque>
                <tunnel-group>employees</tunnel-group>
                <aggauth-handle>auth-handle</aggauth-handle>
                <config-hash>config-hash</config-hash>
              </opaque>
              <auth>
                <sso-v2-login>/saml/login</sso-v2-login>
                <sso-v2-token-cookie-name>acSamlv2Token</sso-v2-token-cookie-name>
              </auth>
            </config-auth>
        """

        opener = fake_opener(FakeResponse(), FakeResponse(response_xml))
        with mock.patch.object(
            saml_auth, "create_anyconnect_opener", return_value=opener
        ):
            result = saml_auth.initialize_anyconnect_auth(
                "https://vpn.example.com", "employees"
            )

        self.assertEqual(result["saml_url"], "https://vpn.example.com/saml/login")
        self.assertEqual(result["tunnel_group"], "employees")
        self.assertEqual(result["aggauth_handle"], "auth-handle")
        self.assertEqual(result["config_hash"], "config-hash")
        self.assertEqual(result["token_cookie_name"], "acSamlv2Token")
        self.assertIs(result["opener"], opener)

    def test_anyconnect_requires_sso_login_in_response(self):
        opener = fake_opener(
            FakeResponse(),
            FakeResponse(b"<config-auth><auth /></config-auth>"),
        )
        with mock.patch.object(
            saml_auth, "create_anyconnect_opener", return_value=opener
        ):
            with self.assertRaisesRegex(RuntimeError, "sso-v2-login"):
                saml_auth.build_saml_url(
                    "https://vpn.example.com", "anyconnect", {}, None
                )

    def test_anyconnect_can_disable_tls_validation(self):
        ssl_context = object()

        with mock.patch.object(
            saml_auth.ssl,
            "_create_unverified_context",
            return_value=ssl_context,
        ) as create_context, mock.patch.object(
            saml_auth.urllib.request, "build_opener"
        ) as build_opener:
            saml_auth.create_anyconnect_opener(ignore_tls_errors=True)

        create_context.assert_called_once_with()
        self.assertEqual(len(build_opener.call_args.args), 2)

    def test_other_protocol_uses_provider_path(self):
        provider = {"saml_paths": {"globalprotect": "/global/prelogin"}}

        result = saml_auth.build_saml_url(
            "vpn.example.com/ignored", "globalprotect", provider, "employees"
        )

        self.assertEqual(result, "https://vpn.example.com/global/prelogin")


class ConfirmAnyconnectAuthTest(unittest.TestCase):
    def test_confirmation_exchanges_sso_token_for_session_token(self):
        auth_init = {
            "target_url": "https://vpn.example.com",
            "tunnel_group": "employees",
            "aggauth_handle": "auth-handle",
            "config_hash": "config-hash",
        }
        response_xml = b"""\
            <config-auth>
              <session-token>session-token-value</session-token>
              <server-cert-hash>sha256:certificate</server-cert-hash>
            </config-auth>
        """

        opener = fake_opener(FakeResponse(response_xml))
        auth_init["opener"] = opener
        token, cert_hash = saml_auth.confirm_anyconnect_auth(
            auth_init, "sso-token-value"
        )

        self.assertEqual(token, "session-token-value")
        self.assertEqual(cert_hash, "sha256:certificate")
        payload = ET.fromstring(opener.open.call_args.args[0].data)
        self.assertEqual(payload.attrib["type"], "auth-reply")
        self.assertEqual(payload.findtext("opaque/tunnel-group"), "employees")
        self.assertEqual(payload.findtext("opaque/aggauth-handle"), "auth-handle")
        self.assertEqual(payload.findtext("opaque/config-hash"), "config-hash")
        self.assertEqual(
            payload.findtext("capabilities/auth-method"), "single-sign-on-v2"
        )
        self.assertEqual(payload.findtext("auth/sso-token"), "sso-token-value")


class AuthTimeoutTest(unittest.TestCase):
    def test_empty_environment_value_uses_provider_timeout(self):
        with mock.patch.dict(saml_auth.os.environ, {"AUTH_TIMEOUT": ""}):
            self.assertEqual(saml_auth.get_auth_timeout({"timeout": 120}), 120)

    def test_whitespace_environment_value_uses_provider_timeout(self):
        with mock.patch.dict(saml_auth.os.environ, {"AUTH_TIMEOUT": "  "}):
            self.assertEqual(saml_auth.get_auth_timeout({"timeout": 120}), 120)

    def test_environment_value_overrides_provider_timeout(self):
        with mock.patch.dict(saml_auth.os.environ, {"AUTH_TIMEOUT": "45"}):
            self.assertEqual(saml_auth.get_auth_timeout({"timeout": 120}), 45)

    def test_missing_values_use_default_timeout(self):
        with mock.patch.dict(saml_auth.os.environ, {}, clear=True):
            self.assertEqual(saml_auth.get_auth_timeout({}), 90)


class AuthenticationCompleteTest(unittest.TestCase):
    def test_anyconnect_waits_for_sso_token_after_saml_post(self):
        auth_init = {"token_cookie_name": "acSamlv2Token"}
        saml_result = {
            "saml_response": "assertion",
            "prelogin_cookie": None,
            "sso_token": None,
        }

        self.assertFalse(
            saml_auth.authentication_complete(auth_init, saml_result, {})
        )

        saml_result["sso_token"] = "token"
        self.assertTrue(
            saml_auth.authentication_complete(auth_init, saml_result, {})
        )

    def test_other_protocols_accept_existing_results(self):
        saml_result = {
            "saml_response": None,
            "prelogin_cookie": "cookie",
            "sso_token": None,
        }

        self.assertTrue(
            saml_auth.authentication_complete(None, saml_result, {})
        )


if __name__ == "__main__":
    unittest.main()
