#!/usr/bin/env python3
"""Security regression tests for region pinning, redirects, and redaction."""

import contextlib
import importlib.util
import io
import os
import unittest
import urllib.error
from unittest.mock import patch

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sealos-api.py")
SPEC = importlib.util.spec_from_file_location("sealos_api_security", SCRIPT)
api = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(api)


class RegionTests(unittest.TestCase):
    def setUp(self):
        self._env = os.environ.copy()
        for name in (api.ALLOWED_DOMAINS_ENV, api.SCOPED_TOKEN_ENV):
            os.environ.pop(name, None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)

    def test_official_domains_are_accepted(self):
        self.assertEqual(
            api.validate_region_url("https://usw-1.sealos.io"), "https://usw-1.sealos.io"
        )
        self.assertEqual(
            api.validate_region_url("bja.sealos.run"), "https://bja.sealos.run"
        )

    def test_plain_http_is_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                api.validate_region_url("http://usw-1.sealos.io")

    def test_lookalike_and_unlisted_hosts_are_rejected(self):
        for url in (
            "https://evil.example",
            "https://usw-1.sealos.io.evil.example",
            "https://evil-sealos.io",
        ):
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    api.validate_region_url(url)

    def test_explicit_allowlist_extends_trusted_domains(self):
        with patch.dict(
            os.environ, {api.ALLOWED_DOMAINS_ENV: "self-hosted.example.com"}
        ):
            self.assertEqual(
                api.validate_region_url("https://sealos.self-hosted.example.com"),
                "https://sealos.self-hosted.example.com",
            )
            self.assertEqual(
                api.validate_region_url("https://self-hosted.example.com"),
                "https://self-hosted.example.com",
            )

    def test_trailing_slash_and_default_port_are_normalized(self):
        self.assertEqual(
            api.validate_region_url("https://usw-1.sealos.io/"),
            "https://usw-1.sealos.io",
        )

    def test_region_domain_rejects_untrusted_kubeconfig_server(self):
        with (
            patch.object(api, "load_auth", return_value={}),
            patch.object(
                api,
                "load_kubeconfig",
                return_value="server: https://evil.example\n",
            ),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(SystemExit):
                api.region_domain()

    def test_region_domain_accepts_sealos_kubeconfig_server(self):
        with (
            patch.object(api, "load_auth", return_value={}),
            patch.object(
                api,
                "load_kubeconfig",
                return_value="server: https://usw-1.sealos.io:6443\n",
            ),
        ):
            self.assertEqual(api.region_domain(), "usw-1.sealos.io")

    def test_region_domain_rejects_http_auth_region(self):
        with (
            patch.object(api, "load_auth", return_value={"region": "http://usw-1.sealos.io"}),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(SystemExit):
                api.region_domain()

    def test_regional_token_uses_validated_region(self):
        with (
            patch.object(
                api,
                "load_auth",
                return_value={
                    "regional_token": "regional-token-value",
                    "region": "https://evil.example",
                },
            ),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(SystemExit):
                api.regional_token_or_fail()


class CredentialTests(unittest.TestCase):
    def setUp(self):
        self._env = os.environ.copy()
        os.environ.pop(api.SCOPED_TOKEN_ENV, None)
        os.environ.pop(api.ALLOWED_DOMAINS_ENV, None)
        api._KUBECONFIG_AUTH_WARNED = False
        api._SECRET_VALUES.clear()

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)
        api._KUBECONFIG_AUTH_WARNED = False
        api._SECRET_VALUES.clear()

    def test_scoped_token_is_preferred(self):
        os.environ[api.SCOPED_TOKEN_ENV] = "scoped-token-value"
        self.assertEqual(api.authorization_value(), "scoped-token-value")
        self.assertEqual(
            api.authorization_value(bearer=True), "Bearer scoped-token-value"
        )

    def test_kubeconfig_fallback_is_quoted_and_warned(self):
        with (
            patch.object(api, "load_kubeconfig", return_value="apiVersion: v1"),
            contextlib.redirect_stderr(io.StringIO()) as stderr,
        ):
            value = api.authorization_value(bearer=True)
        self.assertEqual(
            value, "Bearer " + api.urllib.parse.quote("apiVersion: v1", safe="")
        )
        self.assertIn("residual risk", stderr.getvalue())

    def test_sensitive_keys_are_redacted(self):
        api._remember_secret("super-secret-kubeconfig")
        redacted = api.redact_obj(
            {
                "kubeconfig": "super-secret-kubeconfig",
                "token": "opaque",
                "nested": {"client-key-data": "b64", "safe": "ok"},
                "safe": "value super-secret-kubeconfig tail",
            }
        )
        self.assertEqual(redacted["kubeconfig"], "[REDACTED]")
        self.assertEqual(redacted["token"], "[REDACTED]")
        self.assertEqual(redacted["nested"]["client-key-data"], "[REDACTED]")
        self.assertEqual(redacted["nested"]["safe"], "ok")
        self.assertNotIn("super-secret-kubeconfig", redacted["safe"])

    def test_pem_blocks_are_redacted(self):
        text = "-----BEGIN PRIVATE KEY-----\nzzz\n-----END PRIVATE KEY-----"
        self.assertNotIn("zzz", api._redact_text(text))


class RedirectTests(unittest.TestCase):
    def setUp(self):
        self._env = os.environ.copy()
        os.environ.pop(api.ALLOWED_DOMAINS_ENV, None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)

    def test_redirect_handler_refuses_every_redirect(self):
        handler = api._NoRedirectHandler()
        self.assertIsNone(
            handler.redirect_request(
                None, None, 302, "Found", {}, "https://evil.example/steal"
            )
        )

    def test_http_json_refuses_redirect_without_following(self):
        error = urllib.error.HTTPError(
            "https://template.usw-1.sealos.io/api",
            302,
            "Found",
            {"Location": "https://evil.example"},
            None,
        )
        with (
            patch.object(api._OPENER, "open", side_effect=error),
            contextlib.redirect_stderr(io.StringIO()) as stderr,
        ):
            with self.assertRaises(SystemExit):
                api.http_json("https://template.usw-1.sealos.io/api")
        self.assertIn("redirect", stderr.getvalue())

    def test_http_json_refuses_non_https(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                api.http_json("http://template.usw-1.sealos.io/api")

    def test_http_json_refuses_untrusted_host(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                api.http_json("https://template.evil.example/api")


if __name__ == "__main__":
    unittest.main()
