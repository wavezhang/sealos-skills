#!/usr/bin/env python3
"""Security regression tests for the Kaniko executor trust boundary."""

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).with_name("kaniko-build.py")
SPEC = importlib.util.spec_from_file_location("kaniko_build_security", SCRIPT)
KANIKO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(KANIKO)

DIGEST = "sha256:" + "a" * 64


def _clear_env(*names):
    for name in names:
        os.environ.pop(name, None)


class PathTests(unittest.TestCase):
    def test_devbox_name_must_be_a_dns_label(self):
        for value in ("../../../../home/user", "..", "evil/name", "UPPER", ""):
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    KANIKO.require_dns_label(value, "devboxName")

    def test_resolve_devbox_rejects_runtime_traversal(self):
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                KANIKO.resolve_devbox({"devboxName": "../../../../home/user"})

    def test_resolve_devbox_accepts_dns_label(self):
        self.assertEqual(
            KANIKO.resolve_devbox({"devboxName": "devbox-1"}), "devbox-1"
        )

    def test_object_dir_cannot_escape_context_store(self):
        with tempfile.TemporaryDirectory() as root:
            safe = KANIKO.safe_object_dir(root, "devbox", "app-1234")
            self.assertEqual(
                safe,
                os.path.realpath(os.path.join(root, "devbox", "app-1234")),
            )
            for devbox in ("..", "../../etc", "devbox/../../etc"):
                with contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        KANIKO.safe_object_dir(root, devbox, "app-1234")

    def test_bucket_and_prefix_reject_traversal(self):
        for bucket in ("../../etc", "bucket/name", "Bucket"):
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    KANIKO.validate_bucket(bucket)
        for prefix in ("../contexts", "/contexts", "contexts/../x", "a//b"):
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    KANIKO.validate_prefix(prefix)


class EndpointTests(unittest.TestCase):
    def setUp(self):
        self._env = os.environ.copy()
        _clear_env(
            "KANIKO_JOB_S3_ENDPOINT",
            "S3_ENDPOINT",
            "AWS_ENDPOINT_URL_S3",
            "AWS_ENDPOINT_URL",
            "KANIKO_S3_ALLOWED_HOSTS",
        )

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)

    def test_repository_endpoint_outside_allowlist_is_ignored(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertIsNone(
                KANIKO.validate_s3_endpoint(
                    "http://evil.example:1319", "runtime contract"
                )
            )

    def test_repository_endpoint_cannot_redirect_credentials(self):
        with (
            mock.patch.object(KANIKO, "resolve_pod_ip", return_value="10.0.0.5"),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            endpoint = KANIKO.resolve_job_s3_endpoint(
                {"s3Endpoint": "http://evil.example:1319"}, "ns-test"
            )
        self.assertEqual(endpoint, "http://10.0.0.5:1319")

    def test_cluster_internal_endpoint_is_allowed(self):
        endpoint = KANIKO.validate_s3_endpoint(
            "http://versitygw.ns-test.svc:1319", "runtime contract"
        )
        self.assertEqual(endpoint, "http://versitygw.ns-test.svc:1319")

    def test_configured_allowlist_extends_hosts(self):
        os.environ["KANIKO_S3_ALLOWED_HOSTS"] = "s3.internal.example"
        self.assertEqual(
            KANIKO.validate_s3_endpoint(
                "https://s3.internal.example", "runtime contract"
            ),
            "https://s3.internal.example",
        )

    def test_untrusted_environment_endpoint_is_rejected(self):
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                KANIKO.validate_s3_endpoint(
                    "https://evil.example", "KANIKO_JOB_S3_ENDPOINT", strict=True
                )


class SecretRefTests(unittest.TestCase):
    def setUp(self):
        self._env = os.environ.copy()
        os.environ.pop("KANIKO_S3_SECRET_ALLOWLIST", None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)

    def test_unlisted_secret_ref_is_ignored(self):
        with (
            mock.patch.dict(os.environ, {"AWS_SECRET_ACCESS_KEY": "build-secret"}),
            mock.patch.object(KANIKO, "kubectl", return_value=(0, "", "")) as kubectl,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            _, created = KANIKO.s3_credential_env(
                {"secretKeyRef": {"name": "kube-system-admin", "key": "token"}}, "ns"
            )
        args, _ = kubectl.call_args
        self.assertEqual(args[0], ["create", "-f", "-"])
        self.assertNotIn("kube-system-admin", created or "")
        for call in kubectl.call_args_list:
            self.assertNotEqual(call.args[0][:2], ["get", "secret"])

    def test_allowlisted_secret_ref_is_used(self):
        os.environ["KANIKO_S3_SECRET_ALLOWLIST"] = (
            "devbox-secret:SEALOS_DEVBOX_JWT_SECRET"
        )
        with mock.patch.object(KANIKO, "kubectl", return_value=(0, "", "")) as kubectl:
            lines, created = KANIKO.s3_credential_env(
                {
                    "secretKeyRef": {
                        "name": "devbox-secret",
                        "key": "SEALOS_DEVBOX_JWT_SECRET",
                    }
                },
                "ns",
            )
        self.assertIsNone(created)
        self.assertIn("devbox-secret", "\n".join(lines))
        self.assertEqual(kubectl.call_args.args[0][:2], ["get", "secret"])


class ImageTests(unittest.TestCase):
    def setUp(self):
        self._env = os.environ.copy()
        os.environ.pop(KANIKO.TRUSTED_REGISTRIES_ENV, None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)

    def test_tag_only_image_is_rejected(self):
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                KANIKO.validate_kaniko_image(
                    "gcr.io/kaniko-project/executor:v1.24.0"
                )

    def test_untrusted_registry_is_rejected(self):
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                KANIKO.validate_kaniko_image("evil.example/kaniko@" + DIGEST)

    def test_trusted_digest_reference_is_accepted(self):
        image = "gcr.io/kaniko-project/executor@" + DIGEST
        self.assertEqual(KANIKO.validate_kaniko_image(image), image)

    def test_configured_registry_extends_trust(self):
        os.environ[KANIKO.TRUSTED_REGISTRIES_ENV] = "registry.internal/kaniko"
        image = "registry.internal/kaniko/executor@" + DIGEST
        self.assertEqual(KANIKO.validate_kaniko_image(image), image)


class RuntimeContractTests(unittest.TestCase):
    def test_repository_contract_is_denied_by_default(self):
        runtime = {
            "s3Endpoint": "http://evil.example:1319",
            "devboxName": "../../etc",
        }
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(KANIKO.resolve_runtime_contract(runtime, False), {})
        self.assertIn("default deny", stderr.getvalue())

    def test_trusted_contract_is_accepted_then_validated(self):
        runtime = {"devboxName": "devbox-1"}
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(
                KANIKO.resolve_runtime_contract(runtime, True), runtime
            )

    def test_render_only_does_not_use_repository_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "runtime.json"
            runtime.write_text(
                json.dumps(
                    {
                        "s3Endpoint": "http://evil.example:1319",
                        "devboxName": "../../etc",
                    }
                )
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--image",
                    "ghcr.io/demo/app:tag",
                    "--runtime-file",
                    str(runtime),
                    "--render-only",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("default deny", result.stderr)
        self.assertNotIn("evil.example", result.stdout)


if __name__ == "__main__":
    unittest.main()
