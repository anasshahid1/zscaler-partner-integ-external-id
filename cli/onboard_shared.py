#!/usr/bin/env python3
"""
One-shot Zscaler + AWS onboarding with a SHARED external ID.

For every account in the CSV:
  1. Zscaler: register the AWS account with the shared externalId (skips if already registered)
  2. AWS:     create/update IAM role via Zscaler's CloudFormation template (needs an AWS profile)
  3. Zscaler: force a permissions re-check and report Allowed/Denied

CSV columns:
  account_name,aws_account_id[,iam_role_name]            always
  aws_profile                                             AWS auth option 1: named CLI profile
  aws_access_key_id,aws_secret_access_key[,aws_session_token]
                                                          AWS auth option 2: keys in the row
                                                          (keep such files out of git: *.local.csv is ignored)

Usage:
  python3 onboard_shared.py accounts.csv                       # auto-generates and saves external ID
  python3 onboard_shared.py accounts.csv --external-id <hex>   # use your own
  python3 onboard_shared.py accounts.csv --skip-aws            # Zscaler side only (do AWS via StackSet later)
  python3 onboard_shared.py accounts.csv --dry-run
"""

import argparse
import csv
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from zscaler_partner import ZscalerAuth, load_config, _find_account_by_aws_id, SSL_CTX  # noqa: E402

TEMPLATE_URL = "https://zscaler-discovery-role.s3.amazonaws.com/zscaler_discovery_role.yaml"
TRUSTED_ROLE = "arn:aws:iam::175726779870:role/ZscalerTagDiscoveryRole"
DEFAULT_ROLE = "ZscalerDiscoveryRole"
STACK_NAME = "ZscalerTagDiscoveryTrustingRole-shared"
EXT_ID_FILE = Path.home() / ".zscaler" / "shared-external-id"


def log(msg=""):
    print(msg, flush=True)


# --------------------------------------------------------------------------- external ID

def get_external_id(cli_value):
    if cli_value:
        return cli_value.strip()
    if EXT_ID_FILE.exists():
        ext = EXT_ID_FILE.read_text().strip()
        if ext:
            log(f"Reusing saved external ID from {EXT_ID_FILE}")
            return ext
    ext = secrets.token_hex(16)
    EXT_ID_FILE.parent.mkdir(parents=True, exist_ok=True)
    EXT_ID_FILE.write_text(ext + "\n")
    os.chmod(EXT_ID_FILE, 0o600)
    log(f"Generated new external ID, saved to {EXT_ID_FILE}")
    return ext


# --------------------------------------------------------------------------- Zscaler

def zscaler_register(auth, name, aws_id, role, ext, regions, dry):
    existing = _find_account_by_aws_id(auth, aws_id)
    if existing:
        stored = existing.get("externalId", "")
        note = "" if stored == ext else f"  !! stored externalId {stored} != shared {ext}"
        return existing["id"], "existing" + note
    if dry:
        return "-", "would create"
    payload = {
        "name": name, "cloudType": "AWS", "externalId": ext,
        "accountDetails": {"awsAccountId": aws_id, "awsRoleName": role, "externalId": ext},
        "supportedRegions": regions,
    }
    r = auth.post("/publicCloudInfo", payload)          # may time out after 120s but still create
    zid = r.get("id") if isinstance(r, dict) else None
    if not zid:
        found = _find_account_by_aws_id(auth, aws_id)
        zid = found["id"] if found else None
    if not zid:
        return None, f"FAILED: {json.dumps(r)[:200]}"
    return zid, "created"


def zscaler_recheck(auth, zid, role, ext, attempts=4, wait=10):
    """Force Zscaler to re-test the role. Retries because IAM trust-policy changes take a few
    seconds to propagate, which otherwise shows up as a false 'Denied'."""
    result = "unknown"
    for n in range(1, attempts + 1):
        r = auth.put(f"/discoveryService/{zid}/permissions", {"discoveryRole": role, "externalId": ext})
        if isinstance(r, dict):
            st = r.get("status", {})
            denied = [k for k, v in st.items() if v != "Allowed"]
            if st.get("assumeRole") == "Allowed" and not denied:
                return "Allowed" if n == 1 else f"Allowed (after {n} tries)"
            result = f"Denied ({', '.join(denied) or r.get('_error', '')})"
        if n < attempts:
            log(f"    verify  : {result} -- retrying in {wait}s ({n}/{attempts})")
            time.sleep(wait)
    return result


# --------------------------------------------------------------------------- AWS

def aws_creds_from_row(row):
    """Return (label, cli_args, env) describing how to authenticate the aws CLI for this row.

    Priority: explicit keys in the row > aws_profile > None (no AWS side for this row).
    Keys are passed to the subprocess via environment only; they are never logged or written.
    """
    key = (row.get("aws_access_key_id") or "").strip()
    secret = (row.get("aws_secret_access_key") or "").strip()
    token = (row.get("aws_session_token") or "").strip()
    profile = (row.get("aws_profile") or "").strip()
    if key or secret:
        if not (key and secret):
            return None, None, None
        env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
        env.update({"AWS_ACCESS_KEY_ID": key, "AWS_SECRET_ACCESS_KEY": secret})
        if token:
            env["AWS_SESSION_TOKEN"] = token
        return f"keys {key[:4]}...{key[-4:]}", [], env
    if profile:
        return f"profile '{profile}'", ["--profile", profile], None
    return None, None, None


def aws(creds, *args, region=None):
    _, cli_args, env = creds
    cmd = ["aws"] + cli_args + (["--region", region] if region else []) + list(args)
    p = subprocess.run(cmd, capture_output=True, text=True, env=env)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def aws_ensure_role(creds, aws_id, role, ext, region, template_file, dry):
    label = creds[0]
    rc, out, err = aws(creds, "sts", "get-caller-identity", "--query", "Account", "--output", "text")
    if rc != 0:
        return f"FAILED: {label} not usable: {err[:120]}"
    if out != aws_id:
        return f"FAILED: {label} is account {out}, expected {aws_id}"

    rc, _, _ = aws(creds, "iam", "get-role", "--role-name", role)
    if rc == 0:
        if dry:
            return "would update trust policy"
        trust = json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"AWS": TRUSTED_ROLE}, "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"sts:ExternalId": ext}}}]})
        rc, _, err = aws(creds, "iam", "update-assume-role-policy", "--role-name", role, "--policy-document", trust)
        return "trust policy updated" if rc == 0 else f"FAILED: {err[:150]}"

    if dry:
        return "would deploy CloudFormation stack"
    rc, out, err = aws(creds, "cloudformation", "deploy",
                       "--stack-name", STACK_NAME, "--template-file", template_file,
                       "--capabilities", "CAPABILITY_NAMED_IAM", "--no-fail-on-empty-changeset",
                       "--parameter-overrides", f"TrustingAccountRoleName={role}",
                       f"ZscalerTrustedRole={TRUSTED_ROLE}", f"ExternalId={ext}", region=region)
    return f"stack {STACK_NAME} deployed" if rc == 0 else f"FAILED: {err[-200:]}"


def download_template():
    fd, path = tempfile.mkstemp(suffix=".yaml", prefix="zscaler-cft-")
    with urllib.request.urlopen(TEMPLATE_URL, context=SSL_CTX, timeout=30) as r, os.fdopen(fd, "wb") as f:
        f.write(r.read())
    return path


# --------------------------------------------------------------------------- main

def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("csv_file")
    p.add_argument("--external-id", help="shared external ID (default: reuse/generate ~/.zscaler/shared-external-id)")
    p.add_argument("--region", default="us-east-1", help="region for the CloudFormation stack (IAM is global)")
    p.add_argument("--skip-aws", action="store_true", help="only do the Zscaler side")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    with open(args.csv_file) as f:
        rows = list(csv.DictReader(f))
    cols = set(rows[0].keys()) if rows else set()
    if not rows or not {"account_name", "aws_account_id"}.issubset(cols):
        sys.exit("CSV needs columns: account_name, aws_account_id")
    if not args.skip_aws and not ({"aws_profile", "aws_access_key_id"} & cols):
        sys.exit("CSV needs aws_profile or aws_access_key_id/aws_secret_access_key columns (or use --skip-aws)")

    ext = get_external_id(args.external_id)
    log(f"\nShared external ID: {ext}")
    log(f"Accounts: {len(rows)}   AWS side: {'skipped' if args.skip_aws else 'enabled'}   dry-run: {args.dry_run}\n")

    auth = ZscalerAuth(load_config())
    auth.authenticate()
    regions = auth.get("/publicCloudInfo/supportedRegions") or []
    template = None if args.skip_aws or args.dry_run else download_template()

    results = []
    for i, row in enumerate(rows, 1):
        name, aws_id = row["account_name"].strip(), row["aws_account_id"].strip()
        role = (row.get("iam_role_name") or "").strip() or DEFAULT_ROLE
        creds = aws_creds_from_row(row)
        log(f"[{i}/{len(rows)}] {name} ({aws_id})" + (f"  [aws via {creds[0]}]" if creds[0] else ""))

        zid, zs_status = zscaler_register(auth, name, aws_id, role, ext, regions, args.dry_run)
        log(f"    zscaler : {zs_status}" + (f"  (id {zid})" if zid and zid != "-" else ""))
        aws_status, perm = "skipped", "skipped"
        if zid and not zs_status.startswith("FAILED"):
            if not args.skip_aws:
                if creds[0]:
                    aws_status = aws_ensure_role(creds, aws_id, role, ext, args.region, template, args.dry_run)
                else:
                    aws_status = "skipped (no aws_profile or keys in row)"
                log(f"    aws     : {aws_status}")
            if not args.dry_run and not aws_status.startswith("FAILED"):
                perm = zscaler_recheck(auth, zid, role, ext)
                log(f"    verify  : {perm}")
        results.append((name, aws_id, str(zid or "-"), zs_status.split("  !!")[0], aws_status, perm))
        log()

    if template:
        os.unlink(template)

    log("=" * 96)
    log(f"  {'Name':<20} {'AWS Account':<14} {'Zscaler ID':<11} {'Zscaler':<14} {'AWS':<26} {'Permissions'}")
    log(f"  {'-'*20} {'-'*14} {'-'*11} {'-'*14} {'-'*26} {'-'*11}")
    for r in results:
        log(f"  {r[0]:<20} {r[1]:<14} {r[2]:<11} {r[3][:14]:<14} {r[4][:26]:<26} {r[5]}")
    log(f"\n  External ID used everywhere: {ext}")
    if args.skip_aws:
        log(f"  Next: deploy {TEMPLATE_URL}")
        log(f"        as a StackSet with ExternalId={ext}, TrustingAccountRoleName={DEFAULT_ROLE},")
        log(f"        ZscalerTrustedRole={TRUSTED_ROLE}, then re-run this script to verify.")


if __name__ == "__main__":
    main()
