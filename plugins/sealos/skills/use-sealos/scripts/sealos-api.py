#!/usr/bin/env python3
"""Sealos Cloud API helper: auth, template deploys, store queries.

Standard library only. Credentials live in ~/.sealos/:
  kubeconfig   kubectl-compatible credentials for the current workspace
  auth.json    region + tokens (written by `login`, needed only for login/switch)

The kubeconfig alone is enough for every non-login command, so users can also
paste a kubeconfig from the Sealos web console instead of running `login`.

Commands:
  status                         auth + region + namespace summary
  login [--region URL]           OAuth2 device-flow login, saves kubeconfig
  workspaces                     list workspaces of the signed-in account
  switch <workspace>             switch workspace, refresh kubeconfig
  deploy <template.yaml> [...]   deploy a local template YAML
  deploy-store <template> [...]  deploy a template-store template by name
  adopt <instance> [--template-name NAME]
                                 claim an existing instance as a Brain Project
                                 (no-op outside *.sealos.io regions)
  store-list [--search Q]        list template-store templates
  store-get <template> [--yaml]  template inputs/quota (and source YAML)
  store-export <template> --out F  write a store template's source to a file
  instances                      list deployed template instances
  delete <instance>              delete an instance and all its resources
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

CLIENT_ID = "af993c98-d19d-4bdc-b338-79b80dc4f8bf"
DEFAULT_REGION = "https://usw-1.sealos.io"
KNOWN_REGIONS = [
    "https://usw-1.sealos.io",
    "https://gzg.sealos.run",
    "https://bja.sealos.run",
    "https://hzh.sealos.run",
]

SEALOS_DIR = os.path.expanduser("~/.sealos")
AUTH_PATH = os.path.join(SEALOS_DIR, "auth.json")
DEFAULT_KUBECONFIG_PATH = os.path.join(SEALOS_DIR, "kubeconfig")

# Only official Sealos domains are trusted by default. Extra domains must be
# listed explicitly by the user, e.g.
#   SEALOS_ALLOWED_DOMAINS=self-hosted.example.com,sealos.internal
ALLOWED_DOMAINS_ENV = "SEALOS_ALLOWED_DOMAINS"
OFFICIAL_REGION_SUFFIXES = ("sealos.io", "sealos.run")

# A short-lived, least-privilege token is the intended credential for the
# Template/Brain API. Until the server issues one, the kubeconfig fallback is
# kept for compatibility and loudly flagged as a residual risk.
SCOPED_TOKEN_ENV = "SEALOS_API_SCOPED_TOKEN"

_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(authorization|access[_-]?token|regional[_-]?token|refresh[_-]?token|"
    r"device[_-]?code|client[_-]?key[_-]?data|client[_-]?certificate[_-]?data|"
    r"kubeconfig|password|secret([_-]?key)?|token)"
)
_SECRET_VALUES = set()
_KUBECONFIG_AUTH_WARNED = False


def resolve_kubeconfig_path():
    """Explicit SEALOS_KUBECONFIG wins; then the login-owned default; then an
    ambient KUBECONFIG (e.g. injected into a managed sandbox) if it exists."""
    explicit = os.environ.get("SEALOS_KUBECONFIG")
    if explicit:
        return explicit
    if os.path.exists(DEFAULT_KUBECONFIG_PATH):
        return DEFAULT_KUBECONFIG_PATH
    ambient = os.environ.get("KUBECONFIG")
    if ambient and os.path.exists(ambient):
        return ambient
    return DEFAULT_KUBECONFIG_PATH


KUBECONFIG_PATH = resolve_kubeconfig_path()
# `login`/`switch` never write to an ambient KUBECONFIG.
KUBECONFIG_WRITE_PATH = os.environ.get("SEALOS_KUBECONFIG") or DEFAULT_KUBECONFIG_PATH


def _remember_secret(value):
    if isinstance(value, str) and len(value) >= 8:
        _SECRET_VALUES.add(value)


def _redact_text(text):
    if not isinstance(text, str):
        return text
    for secret in sorted(_SECRET_VALUES, key=len, reverse=True):
        if secret in text:
            text = text.replace(secret, "[REDACTED]")
    text = re.sub(
        r"-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----",
        "[REDACTED PEM BLOCK]",
        text,
        flags=re.DOTALL,
    )
    return re.sub(
        r"(?i)([\"']?(?:authorization|access[_-]?token|regional[_-]?token|"
        r"device[_-]?code|kubeconfig|password|client[_-]?key[_-]?data|"
        r"secret(?:[_-]?key)?|token)[\"']?\s*[:=]\s*)[\"']?[^\s\"',}]+",
        r"\1[REDACTED]",
        text,
    )


def redact_obj(value):
    """Recursively redact credentials before printing errors or responses."""
    if isinstance(value, dict):
        return {
            key: (
                "[REDACTED]"
                if isinstance(key, str) and _SENSITIVE_KEY_RE.search(key)
                else redact_obj(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_obj(item) for item in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


def emit(value, **kwargs):
    print(json.dumps(redact_obj(value), **kwargs))


def allowed_domain_bases():
    """Official Sealos domains plus user-configured domains, lowercased."""
    bases = list(OFFICIAL_REGION_SUFFIXES)
    for raw in os.environ.get(ALLOWED_DOMAINS_ENV, "").split(","):
        value = raw.strip().lower()
        if not value:
            continue
        if "://" in value:
            value = urllib.parse.urlparse(value).hostname or ""
        value = value.lstrip("*.").strip(".")
        if value and re.fullmatch(r"[a-z0-9.-]+", value) and ".." not in value:
            bases.append(value)
    return tuple(dict.fromkeys(bases))


def host_is_allowed(host):
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return False
    return any(
        host == base or host.endswith("." + base) for base in allowed_domain_bases()
    )


def validate_region_url(value, source="region"):
    """Return a normalized https://host[:port] URL or abort."""
    raw = (value or "").strip()
    if not raw:
        fail(f"{source} is empty")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme != "https":
        fail(f"{source} must use https", scheme=parsed.scheme)
    if parsed.username or parsed.password:
        fail(f"{source} must not embed credentials")
    if not parsed.hostname:
        fail(f"{source} has no host")
    try:
        port = parsed.port
    except ValueError:
        fail(f"{source} has an invalid port")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        fail(f"{source} must be a bare https://host[:port] URL")
    if not host_is_allowed(parsed.hostname):
        fail(
            f"{source} host is not an allowed Sealos domain",
            host=parsed.hostname,
            allowed=list(allowed_domain_bases()),
        )
    return "https://" + parsed.hostname + (f":{port}" if port else "")


def require_https_sealos_url(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        fail("refusing non-https request URL", scheme=parsed.scheme)
    if not parsed.hostname or not host_is_allowed(parsed.hostname):
        fail(
            "refusing request to a host outside the allowed Sealos domains",
            host=parsed.hostname,
            allowed=list(allowed_domain_bases()),
        )


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: a 30x would replay credentials elsewhere."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirectHandler())


def _warn_legacy_kubeconfig_auth():
    global _KUBECONFIG_AUTH_WARNED
    if _KUBECONFIG_AUTH_WARNED:
        return
    _KUBECONFIG_AUTH_WARNED = True
    print(
        "warning: the full kubeconfig is being sent as an API credential. This "
        "is a known residual risk until the server issues scoped tokens; set "
        f"{SCOPED_TOKEN_ENV} to a server-issued scoped token to stop sending it.",
        file=sys.stderr,
        flush=True,
    )


def fail(message, **extra):
    payload = {"error": _redact_text(str(message))}
    payload.update(redact_obj(extra))
    print(json.dumps(payload), file=sys.stderr)
    sys.exit(1)


def http_json(url, method="GET", headers=None, data=None, form=None, timeout=30, fatal=True):
    """Make an HTTPS request to an allowed Sealos host; refuse redirects."""
    require_https_sealos_url(url)
    body = None
    headers = dict(headers or {})
    if form is not None:
        body = urllib.parse.urlencode(form).encode()
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif data is not None:
        body = json.dumps(data).encode()
        headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            text = resp.read().decode()
            status = resp.status
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            fail(
                "refusing to follow an HTTP redirect; credentials are never forwarded",
                status=e.code,
                host=urllib.parse.urlparse(url).hostname,
            )
        text = e.read().decode(errors="replace")
        status = e.code
    except (urllib.error.URLError, TimeoutError) as e:
        if not fatal:
            return 0, {"error": f"request to {url} failed: {e}"}
        fail(f"request to {url} failed: {e}")
    try:
        return status, json.loads(text)
    except ValueError:
        return status, text


def load_auth():
    if not os.path.exists(AUTH_PATH):
        return {}
    try:
        with open(AUTH_PATH) as f:
            auth = json.load(f)
    except ValueError:
        return {}
    _remember_secret(auth.get("access_token"))
    _remember_secret(auth.get("regional_token"))
    return auth


def load_kubeconfig():
    if not os.path.exists(KUBECONFIG_PATH):
        fail(
            "kubeconfig not found; run `sealos-api.py login` or save one from the Sealos web console",
            path=KUBECONFIG_PATH,
        )
    with open(KUBECONFIG_PATH) as f:
        kubeconfig = f.read()
    _remember_secret(kubeconfig)
    return kubeconfig


def authorization_value(bearer=False):
    """Credential for the Template/Brain API.

    Prefer SEALOS_API_SCOPED_TOKEN. The kubeconfig fallback is kept only until
    the server accepts scoped tokens and is warned about on stderr.
    """
    token = os.environ.get(SCOPED_TOKEN_ENV, "").strip()
    if token:
        _remember_secret(token)
        return f"Bearer {token}" if bearer else token
    _warn_legacy_kubeconfig_auth()
    kubeconfig = load_kubeconfig()
    quoted = urllib.parse.quote(kubeconfig, safe="")
    _remember_secret(kubeconfig)
    _remember_secret(quoted)
    return f"Bearer {quoted}" if bearer else quoted


def kubeconfig_field(kubeconfig, field):
    m = re.search(rf"^\s*{field}:\s*[\"']?([^\"'\s]+)", kubeconfig, re.MULTILINE)
    return m.group(1) if m else None


def region_domain():
    """Validated region domain (e.g. usw-1.sealos.io), from auth.json or kubeconfig."""
    auth = load_auth()
    if auth.get("region"):
        return urllib.parse.urlparse(
            validate_region_url(auth["region"], "auth.json region")
        ).hostname
    server = kubeconfig_field(load_kubeconfig(), "server")
    if not server:
        fail("cannot determine region: no auth.json region and no server in kubeconfig")
    return urllib.parse.urlparse(
        validate_region_url(server, "kubeconfig server")
    ).hostname


def save_credentials(region, access_token, regional_token, kubeconfig, workspace):
    _remember_secret(access_token)
    _remember_secret(regional_token)
    _remember_secret(kubeconfig)
    os.makedirs(SEALOS_DIR, exist_ok=True)
    with open(KUBECONFIG_WRITE_PATH, "w") as f:
        f.write(kubeconfig)
    os.chmod(KUBECONFIG_WRITE_PATH, 0o600)
    auth = {
        "region": region,
        "access_token": access_token,
        "regional_token": regional_token,
        "authenticated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "auth_method": "oauth2_device_grant",
    }
    if workspace:
        auth["current_workspace"] = workspace
    with open(AUTH_PATH, "w") as f:
        json.dump(auth, f, indent=2)
    os.chmod(AUTH_PATH, 0o600)


# ── commands ─────────────────────────────────────────────


def cmd_status(_args):
    out = {"authenticated": False}
    if os.path.exists(KUBECONFIG_PATH):
        kc = open(KUBECONFIG_PATH).read()
        namespace = kubeconfig_field(kc, "namespace")
        server = kubeconfig_field(kc, "server")
        if server and ("token:" in kc or "client-certificate" in kc):
            auth = load_auth()
            out = {
                "authenticated": True,
                "kubeconfig": KUBECONFIG_PATH,
                "server": server,
                "namespace": namespace,
                "region_domain": urllib.parse.urlparse(server).hostname,
                "workspace": (auth.get("current_workspace") or {}).get("id"),
                "authenticated_at": auth.get("authenticated_at"),
            }
    print(json.dumps(redact_obj(out), indent=2))


def cmd_login(args):
    region = validate_region_url(
        args.region or os.environ.get("SEALOS_REGION") or DEFAULT_REGION,
        "--region",
    )

    status, device = http_json(
        f"{region}/api/auth/oauth2/device",
        method="POST",
        form={
            "client_id": CLIENT_ID,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        },
    )
    if status != 200 or not isinstance(device, dict):
        fail(f"device authorization request failed ({status})", response=str(device)[:500])

    url = device.get("verification_uri_complete") or device.get("verification_uri")
    expires_in = int(device.get("expires_in", 600))
    interval = int(device.get("interval", 5))

    # Print the sign-in link immediately: the agent must relay it to the user
    # before this process finishes polling.
    print(
        f"\nOpen this URL in your browser to authorize (expires in {expires_in // 60} min):"
        f"\n\n  {url}\n\nUser code: {device.get('user_code')}\n\nWaiting for authorization...",
        file=sys.stderr,
        flush=True,
    )
    try:
        import webbrowser

        webbrowser.open(url)
    except Exception:
        pass

    deadline = time.time() + min(expires_in, 600)
    token = None
    while time.time() < deadline:
        time.sleep(interval)
        status, resp = http_json(
            f"{region}/api/auth/oauth2/token",
            method="POST",
            form={
                "client_id": CLIENT_ID,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device.get("device_code"),
            },
        )
        if status == 200 and isinstance(resp, dict) and resp.get("access_token"):
            token = resp["access_token"]
            break
        err = resp.get("error") if isinstance(resp, dict) else None
        if err == "authorization_pending":
            continue
        if err == "slow_down":
            interval += 5
            continue
        if err == "access_denied":
            fail("authorization denied by user")
        if err == "expired_token":
            fail("device code expired; run login again")
        fail(f"token request failed ({status})", response=str(resp)[:500])
    if not token:
        fail("authorization timed out; run login again")

    status, region_data = http_json(
        f"{region}/api/auth/regionToken", method="POST", headers={"Authorization": token}
    )
    data = region_data.get("data") if isinstance(region_data, dict) else None
    if status != 200 or not data or not data.get("token") or not data.get("kubeconfig"):
        fail(f"region token exchange failed ({status})", response=str(region_data)[:500])

    workspace = None
    status, ns_data = http_json(
        f"{region}/api/auth/namespace/list", headers={"Authorization": data["token"]}
    )
    if status == 200 and isinstance(ns_data, dict):
        namespaces = ns_data.get("data") or []
        if isinstance(namespaces, dict):
            namespaces = namespaces.get("namespaces") or []
        private = [ns for ns in namespaces if ns.get("nstype") == "private"]
        chosen = (private or namespaces or [None])[0]
        if chosen:
            workspace = {
                "uid": chosen.get("uid"),
                "id": chosen.get("id"),
                "teamName": chosen.get("teamName"),
            }

    save_credentials(region, token, data["token"], data["kubeconfig"], workspace)
    emit(
        {
            "authenticated": True,
            "region": region,
            "workspace": (workspace or {}).get("id"),
            "kubeconfig": KUBECONFIG_WRITE_PATH,
        },
        indent=2,
    )


def regional_token_or_fail():
    auth = load_auth()
    if not auth.get("regional_token"):
        fail("no regional token; run `sealos-api.py login` first")
    auth["region"] = validate_region_url(auth.get("region"), "auth.json region")
    return auth


def cmd_workspaces(_args):
    auth = regional_token_or_fail()
    status, ns_data = http_json(
        f"{auth['region']}/api/auth/namespace/list",
        headers={"Authorization": auth["regional_token"]},
    )
    if status != 200:
        fail(f"list workspaces failed ({status})", response=str(ns_data)[:500])
    namespaces = ns_data.get("data") or []
    if isinstance(namespaces, dict):
        namespaces = namespaces.get("namespaces") or []
    current = (auth.get("current_workspace") or {}).get("id")
    emit(
        {
            "current": current,
            "workspaces": [
                {
                    "uid": ns.get("uid"),
                    "id": ns.get("id"),
                    "teamName": ns.get("teamName"),
                    "role": ns.get("role"),
                    "nstype": ns.get("nstype"),
                }
                for ns in namespaces
            ],
        },
        indent=2,
    )


def cmd_switch(args):
    auth = regional_token_or_fail()
    status, ns_data = http_json(
        f"{auth['region']}/api/auth/namespace/list",
        headers={"Authorization": auth["regional_token"]},
    )
    if status != 200:
        fail(f"list workspaces failed ({status})", response=str(ns_data)[:500])
    namespaces = ns_data.get("data") or []
    if isinstance(namespaces, dict):
        namespaces = namespaces.get("namespaces") or []
    target = args.workspace.lower()
    match = next(
        (
            ns
            for ns in namespaces
            if target in (ns.get("id", "").lower(), ns.get("uid", "").lower())
            or target in ns.get("teamName", "").lower()
        ),
        None,
    )
    if not match:
        fail(
            f"no workspace matching '{args.workspace}'",
            available=[ns.get("id") for ns in namespaces],
        )

    status, switch_data = http_json(
        f"{auth['region']}/api/auth/namespace/switch",
        method="POST",
        headers={"Authorization": auth["regional_token"]},
        data={"ns_uid": match.get("uid")},
    )
    new_token = (switch_data.get("data") or {}).get("token") if isinstance(switch_data, dict) else None
    if status != 200 or not new_token:
        fail(f"switch workspace failed ({status})", response=str(switch_data)[:500])

    status, kc_data = http_json(
        f"{auth['region']}/api/auth/getKubeconfig", headers={"Authorization": new_token}
    )
    kubeconfig = (kc_data.get("data") or {}).get("kubeconfig") if isinstance(kc_data, dict) else None
    if status != 200 or not kubeconfig:
        fail(f"get kubeconfig failed ({status})", response=str(kc_data)[:500])

    workspace = {
        "uid": match.get("uid"),
        "id": match.get("id"),
        "teamName": match.get("teamName"),
    }
    save_credentials(auth["region"], auth.get("access_token"), new_token, kubeconfig, workspace)
    emit({"switched": True, "workspace": workspace}, indent=2)


# 0 = transport failure from http_json(..., fatal=False)
ADOPT_RETRY_STATUSES = frozenset({0, 404, 502, 503})
ADOPT_MAX_ATTEMPTS = 4
ADOPT_RETRY_SLEEP_SECONDS = 3


def extract_instance_name(resp, fallback=None):
    """Instance name from a Template API response, or *fallback* if missing."""

    def pick(*vals):
        for val in vals:
            if isinstance(val, str) and val.strip():
                return val.strip()
        return None

    found = None
    if isinstance(resp, dict):
        data = resp.get("data") if isinstance(resp.get("data"), dict) else {}
        meta = resp.get("metadata") if isinstance(resp.get("metadata"), dict) else {}
        data_meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        found = pick(
            resp.get("instanceName"),
            resp.get("name"),
            data.get("instanceName"),
            data.get("name"),
            data_meta.get("name"),
            meta.get("name"),
        )
    return found or pick(fallback)


def template_name_from_yaml(yaml_text):
    """Best-effort Template CR metadata.name from the first YAML document."""
    if not yaml_text:
        return None
    first = yaml_text.split("\n---", 1)[0]
    if not re.search(r"^kind:\s*Template\s*$", first, re.MULTILINE):
        return None
    meta = re.search(r"^metadata:\s*$", first, re.MULTILINE)
    if not meta:
        return None
    rest = first[meta.end() :]
    top = re.search(r"^[^:\s#][^:]*:", rest, re.MULTILINE)
    block = rest[: top.start()] if top else rest
    match = re.search(r"^  name:\s*[\"']?([^\"'\s]+)[\"']?\s*$", block, re.MULTILINE)
    if not match:
        return None
    name = match.group(1)
    if "${{" in name:
        return None
    return name


def _brain_adoption_skipped(reason, error=None, ok=None):
    return {
        "skipped": True,
        "reason": reason,
        "ok": ok,
        "status": None,
        "projectId": None,
        "warnings": [],
        "error": error,
    }


def _adoption_warnings(body):
    if not isinstance(body, dict):
        return []
    adoption = body.get("adoption") if isinstance(body.get("adoption"), dict) else {}
    warnings = adoption.get("warnings") or []
    return warnings if isinstance(warnings, list) else []


def _adoption_error(status, body):
    if isinstance(body, dict) and body.get("error"):
        return str(body["error"])
    if isinstance(body, str) and body.strip():
        return body.strip()[:500]
    return f"adopt-template-instance failed ({status})"


def _should_retry_adopt(status, body, attempt):
    if attempt >= ADOPT_MAX_ATTEMPTS:
        return False
    if status in ADOPT_RETRY_STATUSES:
        return True
    if status == 200 and "incompleteResourceSet" in _adoption_warnings(body):
        return True
    return False


def _adoption_result(status, body):
    warnings = _adoption_warnings(body)
    project = body.get("project") if isinstance(body, dict) else None
    project_id = project.get("id") if isinstance(project, dict) else None
    ok = status == 200
    return {
        "skipped": False,
        "reason": None,
        "ok": ok,
        "status": status,
        "projectId": project_id,
        "warnings": warnings,
        "error": None if ok else _adoption_error(status, body),
    }


def is_brain_managed_deploy():
    return bool(os.environ.get("SEALAI_DEPLOY_TASK_ID") or os.environ.get("SEALAI_PROJECT_ID"))


def is_brain_adoption_region(domain):
    """Brain only runs on international Sealos (*.sealos.io), not China (*.sealos.run)."""
    host = (domain or "").strip().lower().rstrip(".")
    return host == "sealos.io" or host.endswith(".sealos.io")


def maybe_adopt_template_instance(instance_name, template_name=None, dry_run=False):
    """POST Brain adopt-template-instance, or skip. HTTP failures are returned, not raised."""
    if dry_run:
        return _brain_adoption_skipped("dry-run")
    domain = region_domain()
    if not is_brain_adoption_region(domain):
        return _brain_adoption_skipped("not-sealos-io")
    if is_brain_managed_deploy():
        return _brain_adoption_skipped("managed")
    if not instance_name:
        return _brain_adoption_skipped(
            "missing-instance-name",
            error="could not determine instance name from the Template API response",
        )
    url = f"https://brain.{domain}/api/projects/adopt-template-instance"
    headers = {"Authorization": authorization_value(bearer=True)}
    body = {"instanceName": instance_name}
    if template_name:
        body["templateName"] = template_name
    status, resp = 0, None
    for attempt in range(1, ADOPT_MAX_ATTEMPTS + 1):
        status, resp = http_json(
            url, method="POST", headers=headers, data=body, timeout=60, fatal=False
        )
        if _should_retry_adopt(status, resp, attempt):
            time.sleep(ADOPT_RETRY_SLEEP_SECONDS)
            continue
        break
    return _adoption_result(status, resp)


def cmd_deploy(args):
    if not os.path.exists(args.template):
        fail("template file not found", path=args.template)
    with open(args.template) as f:
        yaml_text = f.read()

    deploy_args = parse_deploy_args(args)
    extra_labels = parse_extra_labels(args)
    domain = region_domain()
    url = f"https://template.{domain}/api/v2alpha/templates/raw"
    body = {"yaml": yaml_text, "args": deploy_args, "dryRun": bool(args.dry_run)}
    if extra_labels:
        body["extraLabels"] = extra_labels
    status, resp = http_json(
        url,
        method="POST",
        headers={"Authorization": authorization_value()},
        data=body,
        timeout=120,
    )
    ok = status in (200, 201)
    result = {
        "success": ok,
        "dry_run": bool(args.dry_run),
        "status": status,
        "deploy_url": url,
        "response": resp,
    }
    if ok:
        result["brain_adoption"] = maybe_adopt_template_instance(
            extract_instance_name(resp),
            template_name=template_name_from_yaml(yaml_text),
            dry_run=bool(args.dry_run),
        )
    emit(result, indent=2)
    if not ok:
        sys.exit(1)


def parse_deploy_args(args):
    deploy_args = {}
    if args.args_json:
        try:
            deploy_args = json.loads(args.args_json)
        except ValueError:
            fail("--args-json is not valid JSON")
    elif args.args_file:
        with open(args.args_file) as f:
            deploy_args = json.load(f)
    if not isinstance(deploy_args, dict):
        fail("deploy args must be a JSON object")
    return deploy_args


def parse_extra_labels(args):
    """Ownership labels attached to every deployed resource. Explicit
    --labels-json wins; otherwise a managed control plane's
    SEALAI_DEPLOY_LABELS_JSON is forwarded verbatim."""
    raw = getattr(args, "labels_json", None) or os.environ.get(
        "SEALAI_DEPLOY_LABELS_JSON"
    )
    if not raw:
        return None
    try:
        labels = json.loads(raw)
    except ValueError:
        fail("extra labels are not valid JSON")
    if not isinstance(labels, dict) or not all(
        isinstance(k, str) and k and isinstance(v, str) for k, v in labels.items()
    ):
        fail("extra labels must be a JSON object of string values")
    return labels or None


def cmd_deploy_store(args):
    import random
    import string

    name = args.name or (
        args.template + "-" + "".join(random.choices(string.ascii_lowercase, k=8))
    )
    domain = region_domain()
    url = f"https://template.{domain}/api/v2alpha/templates/instances"
    status, resp = http_json(
        url,
        method="POST",
        headers={"Authorization": authorization_value()},
        data={"name": name, "template": args.template, "args": parse_deploy_args(args)},
        timeout=120,
    )
    ok = status in (200, 201)
    result = {"success": ok, "status": status, "instance": name, "response": resp}
    if ok:
        result["brain_adoption"] = maybe_adopt_template_instance(
            extract_instance_name(resp, fallback=name),
            template_name=args.template,
        )
    emit(result, indent=2)
    if not ok:
        sys.exit(1)


def cmd_adopt(args):
    result = maybe_adopt_template_instance(args.instance, template_name=args.template_name)
    emit({"instance": args.instance, "brain_adoption": result}, indent=2)
    if result.get("skipped"):
        if result.get("error"):
            sys.exit(1)
        return
    if not result.get("ok"):
        sys.exit(1)


def cmd_store_get(args):
    domain = region_domain()
    status, resp = http_json(
        f"https://template.{domain}/api/v2alpha/templates/{urllib.parse.quote(args.template)}",
        timeout=30,
    )
    if status != 200:
        fail(f"template lookup failed ({status})", response=str(resp)[:500])
    out = resp if isinstance(resp, dict) else {"detail": resp}
    if args.yaml:
        status, src = http_json(
            f"https://template.{domain}/api/getTemplateSource"
            f"?templateName={urllib.parse.quote(args.template)}&includeReadme=false",
            headers={"Authorization": authorization_value()},
            timeout=30,
        )
        if status == 200 and isinstance(src, dict):
            data = src.get("data") or {}
            out["templateYaml"] = data.get("templateYaml")
            out["appYaml"] = data.get("appYaml")
        else:
            out["yaml_error"] = f"getTemplateSource failed ({status})"
    emit(out, indent=2)


def cmd_store_export(args):
    """Materialize a store template's source (Template CR + resources) into a
    single local file, ready for a raw deploy or a managed-mode handshake."""
    domain = region_domain()
    status, src = http_json(
        f"https://template.{domain}/api/getTemplateSource"
        f"?templateName={urllib.parse.quote(args.template)}&includeReadme=false",
        headers={"Authorization": authorization_value()},
        timeout=30,
    )
    if status != 200 or not isinstance(src, dict):
        fail(f"getTemplateSource failed ({status})", response=str(src)[:500])
    data = src.get("data") or {}
    template_yaml = (data.get("templateYaml") or "").strip("\n")
    app_yaml = (data.get("appYaml") or "").strip("\n")
    if "app.sealos.io/v1" not in template_yaml or "kind: Template" not in template_yaml:
        fail("template source is missing the app.sealos.io/v1 Template header")
    if not app_yaml:
        fail("template source has no resource documents")
    combined = template_yaml + "\n---\n" + app_yaml + "\n"
    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        f.write(combined)
    emit(
        {
            "success": True,
            "template": args.template,
            "out": args.out,
            "bytes": len(combined.encode()),
            "sha256": hashlib.sha256(combined.encode()).hexdigest(),
        },
        indent=2,
    )


def cmd_instances(_args):
    domain = region_domain()
    status, resp = http_json(
        f"https://template.{domain}/api/instance/list",
        headers={"Authorization": authorization_value()},
        timeout=30,
    )
    if status != 200:
        fail(f"instance list failed ({status})", response=str(resp)[:500])
    items = resp.get("data") if isinstance(resp, dict) else resp
    if isinstance(items, dict):
        items = items.get("items") or items
    out = []
    if isinstance(items, list):
        for it in items:
            meta = it.get("metadata") or {}
            spec = it.get("spec") or {}
            out.append(
                {
                    "name": meta.get("name"),
                    "template": spec.get("title") or spec.get("templateType"),
                    "created": meta.get("creationTimestamp"),
                }
            )
        emit({"count": len(out), "instances": out}, indent=2)
    else:
        emit(resp, indent=2)


def cmd_delete(args):
    domain = region_domain()
    url = f"https://template.{domain}/api/v2alpha/templates/instances/{urllib.parse.quote(args.instance)}"
    status, resp = http_json(
        url,
        method="DELETE",
        headers={"Authorization": authorization_value()},
        timeout=120,
    )
    ok = status in (200, 204)
    emit(
        {"success": ok, "status": status, "instance": args.instance, "response": resp or None},
        indent=2,
    )
    if not ok:
        sys.exit(1)


def cmd_store_list(args):
    domain = region_domain()
    status, resp = http_json(
        f"https://template.{domain}/api/listTemplate?language=en", timeout=30
    )
    if status != 200 or not isinstance(resp, dict):
        fail(f"listTemplate failed ({status})", response=str(resp)[:500])
    templates = (resp.get("data") or {}).get("templates") or []
    query = (args.search or "").lower()
    items = []
    for t in templates:
        meta = t.get("metadata") or {}
        spec = t.get("spec") or {}
        entry = {
            "name": meta.get("name"),
            "title": spec.get("title"),
            "description": (spec.get("description") or "")[:160],
            "categories": spec.get("categories") or [],
        }
        haystack = json.dumps(entry).lower()
        if not query or query in haystack:
            items.append(entry)
    emit({"count": len(items), "templates": items}, indent=2)


def main():
    if os.environ.get(ALLOWED_DOMAINS_ENV):
        print(
            "allowed Sealos domains: " + ", ".join(allowed_domain_bases()),
            file=sys.stderr,
        )
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status")

    p = sub.add_parser("login")
    p.add_argument(
        "--region",
        help=(
            f"region URL (default {DEFAULT_REGION}); known: {', '.join(KNOWN_REGIONS)}; "
            f"extra hosts must be listed in {ALLOWED_DOMAINS_ENV}"
        ),
    )

    sub.add_parser("workspaces")

    p = sub.add_parser("switch")
    p.add_argument("workspace", help="workspace id, uid, or team name")

    p = sub.add_parser("deploy")
    p.add_argument("template", help="path to a Sealos template YAML")
    p.add_argument("--args-json", help="deploy inputs as a JSON object string")
    p.add_argument("--args-file", help="deploy inputs as a JSON file (use for secrets)")
    p.add_argument(
        "--labels-json",
        help="extra ownership labels as a JSON object string "
        "(default: SEALAI_DEPLOY_LABELS_JSON when set)",
    )
    p.add_argument("--dry-run", action="store_true")

    p = sub.add_parser("deploy-store")
    p.add_argument("template", help="template-store template name")
    p.add_argument("--name", help="instance name (default: <template>-<random8>)")
    p.add_argument("--args-json", help="template inputs as a JSON object string")
    p.add_argument("--args-file", help="template inputs as a JSON file (use for secrets)")

    p = sub.add_parser("adopt")
    p.add_argument(
        "instance",
        help="template instance name to claim as a Brain Project (*.sealos.io only)",
    )
    p.add_argument(
        "--template-name",
        help="optional template name for the Brain Project display name",
    )

    p = sub.add_parser("store-list")
    p.add_argument("--search", help="case-insensitive filter")

    p = sub.add_parser("store-get")
    p.add_argument("template", help="template-store template name")
    p.add_argument("--yaml", action="store_true", help="include template source YAML")

    p = sub.add_parser("store-export")
    p.add_argument("template", help="template-store template name")
    p.add_argument("--out", required=True, help="output path for the combined YAML")

    sub.add_parser("instances")

    p = sub.add_parser("delete")
    p.add_argument("instance", help="instance name to delete (removes all its resources)")

    args = parser.parse_args()
    {
        "status": cmd_status,
        "login": cmd_login,
        "workspaces": cmd_workspaces,
        "switch": cmd_switch,
        "deploy": cmd_deploy,
        "deploy-store": cmd_deploy_store,
        "adopt": cmd_adopt,
        "store-list": cmd_store_list,
        "store-get": cmd_store_get,
        "store-export": cmd_store_export,
        "instances": cmd_instances,
        "delete": cmd_delete,
    }[args.command](args)


if __name__ == "__main__":
    main()
