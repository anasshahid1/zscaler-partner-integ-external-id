#!/usr/bin/env python3
"""
Zscaler Partner Integration CLI

A command-line tool for managing Zscaler AWS Partner Integrations.
Supports account onboarding, account groups, and resource queries
via the Zscaler REST API.

Usage:
    python3 zscaler_partner.py configure
    python3 zscaler_partner.py onboard --name "prod" --account-id 123456789012
    python3 zscaler_partner.py onboard --bulk accounts.csv
    python3 zscaler_partner.py onboard --bulk accounts.csv --external-id my-shared-ext-id
    python3 zscaler_partner.py list accounts|groups|regions|account <id>|permissions <id>
    python3 zscaler_partner.py groups create|update <id>|delete <id>|list
    python3 zscaler_partner.py update <id> [--name "new"] [--role-name "new"]
    python3 zscaler_partner.py destroy <aws_account_id>
    python3 zscaler_partner.py destroy --id <zscaler_id>
"""

import argparse
import csv
import json
import os
import ssl
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CONFIG_DIR = Path.home() / ".zscaler"
CONFIG_FILE = CONFIG_DIR / "config.json"

CLOUD_LOGIN_MAP = {
    "zscaler": "zslogin.net",
    "zscalerone": "zsloginone.net",
    "zscalertwo": "zslogintwo.net",
    "zscalerthree": "zsloginthree.net",
    "zscalerbeta": "zsloginbeta.net",
}

CLOUD_ACTIVATION_MAP = {
    "zscaler": "https://api.zsapi.net",
    "zscalerbeta": "https://api.beta.zsapi.net",
    "zscalerone": "https://api.one.zsapi.net",
    "zscalertwo": "https://api.two.zsapi.net",
    "zscalerthree": "https://api.three.zsapi.net",
}

SSL_CTX = ssl._create_unverified_context()
RATE_LIMIT_WAIT = 2


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_config(csv_path=None):
    """Load Zscaler credentials from a CSV (default: no fallback). CSV must contain columns
    client_id, client_secret, vanity_domain[, cloud, login_domain]."""
    if csv_path:
        if not Path(csv_path).exists():
            print(f"Error: Zscaler credentials CSV not found: {csv_path}")
            sys.exit(1)
        with open(csv_path) as f:
            rows = list(csv.DictReader(f))
        if not rows:
            print(f"Error: Zscaler credentials CSV is empty: {csv_path}")
            sys.exit(1)
        row = rows[0]
        required = {"client_id", "client_secret", "vanity_domain"}
        missing = required - set(row.keys())
        if missing:
            print(f"Error: CSV missing columns: {', '.join(sorted(missing))}")
            sys.exit(1)
        if not (row["client_id"] or "").strip() or not (row["client_secret"] or "").strip() or not (row["vanity_domain"] or "").strip():
            print("Error: client_id, client_secret, and vanity_domain are required in CSV.")
            sys.exit(1)
        return {
            "client_id": row["client_id"].strip(),
            "client_secret": row["client_secret"].strip(),
            "vanity_domain": row["vanity_domain"].strip(),
            "cloud": (row.get("cloud") or "").strip() or "zscalerthree",
            "login_domain": (row.get("login_domain") or "").strip(),
        }

    # Legacy ~/.zscaler/config.json path
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            return json.load(f)

    print("\nNo Zscaler credentials CSV supplied and no ~/.zscaler/config.json found.")
    print("Create cli/zscaler.local.csv with columns: client_id, client_secret, vanity_domain, cloud, login_domain")
    sys.exit(1)


def save_config(config):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)
    os.chmod(CONFIG_FILE, 0o600)
    print(f"Config saved to {CONFIG_FILE}")


def api_request(method, url, headers=None, data=None):
    if headers is None:
        headers = {}
    if data is not None:
        if isinstance(data, dict):
            data = json.dumps(data).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
        elif isinstance(data, str):
            data = data.encode("utf-8")

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=120) as resp:
            body = resp.read().decode("utf-8")
            if not body:
                return {"_http_code": resp.status}
            try:
                return json.loads(body)
            except json.JSONDecodeError:
                return {"_raw": body, "_http_code": resp.status}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return {"_error": body, "_http_code": e.code}
    except Exception as e:
        return {"_error": str(e)}


def rate_limit():
    time.sleep(RATE_LIMIT_WAIT)


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

class ZscalerAuth:
    def __init__(self, config):
        self.config = config
        self.access_token = None
        self.token_time = 0

        cloud = config["cloud"]
        login_domain = config.get("login_domain") or CLOUD_LOGIN_MAP.get(cloud, "zslogin.net")
        vanity = config["vanity_domain"]

        self.token_url = f"https://{vanity}.{login_domain}/oauth2/v1/token"
        self.base_url = f"https://connector.{cloud}.net/api/v1"
        self.cloud = cloud

    def authenticate(self):
        data = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": self.config["client_id"],
            "client_secret": self.config["client_secret"],
        }).encode("utf-8")

        req = urllib.request.Request(
            self.token_url, data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, context=SSL_CTX, timeout=30) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                self.access_token = result.get("access_token")
                if not self.access_token:
                    print("Error: No access token in response")
                    sys.exit(1)
                self.token_time = time.time()
                print("Authenticated successfully")
        except Exception as e:
            print(f"Authentication failed: {e}")
            sys.exit(1)

    def refresh_if_needed(self):
        if time.time() - self.token_time >= 240:
            print("Refreshing token...")
            self.authenticate()

    def headers(self):
        self.refresh_if_needed()
        return {"Authorization": f"Bearer {self.access_token}"}

    def get(self, path):
        rate_limit()
        return api_request("GET", f"{self.base_url}{path}", headers=self.headers())

    def post(self, path, data=None):
        rate_limit()
        return api_request("POST", f"{self.base_url}{path}", headers=self.headers(), data=data)

    def put(self, path, data=None):
        rate_limit()
        return api_request("PUT", f"{self.base_url}{path}", headers=self.headers(), data=data)

    def delete(self, path):
        rate_limit()
        return api_request("DELETE", f"{self.base_url}{path}", headers=self.headers())

    def force_activation(self):
        base = CLOUD_ACTIVATION_MAP.get(self.cloud)
        if not base:
            print(f"Warning: Unknown cloud '{self.cloud}', skipping activation")
            return
        url = f"{base}/ztw/api/v1/ecAdminActivateStatus/forcedActivate"
        rate_limit()
        result = api_request("PUT", url, headers=self.headers(), data={})
        print(f"Force activation: {json.dumps(result) if isinstance(result, dict) else result}")


# ---------------------------------------------------------------------------
# Commands: configure
# ---------------------------------------------------------------------------

def cmd_configure(args):
    print("\n--- Zscaler Partner Integration Configuration ---\n")

    existing = {}
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            existing = json.load(f)
        print(f"Existing config found at {CONFIG_FILE}")
        print("Press Enter to keep current values.\n")

    client_id = input(f"Client ID [{existing.get('client_id', '')}]: ").strip()
    client_secret = input(f"Client Secret [****]: ").strip()
    vanity_domain = input(f"Vanity Domain [{existing.get('vanity_domain', '')}]: ").strip()

    clouds = ["zscaler", "zscalerone", "zscalertwo", "zscalerthree", "zscalerbeta"]
    print(f"\nAvailable clouds: {', '.join(clouds)}")
    cloud = input(f"Cloud [{existing.get('cloud', 'zscalerthree')}]: ").strip()

    login_domain = input(f"Login Domain override [{existing.get('login_domain', '')}]: ").strip()

    config = {
        "client_id": client_id or existing.get("client_id", ""),
        "client_secret": client_secret or existing.get("client_secret", ""),
        "vanity_domain": vanity_domain or existing.get("vanity_domain", ""),
        "cloud": cloud or existing.get("cloud", "zscalerthree"),
        "login_domain": login_domain or existing.get("login_domain", ""),
    }

    if not config["client_id"] or not config["client_secret"] or not config["vanity_domain"]:
        print("Error: client_id, client_secret, and vanity_domain are required.")
        sys.exit(1)

    save_config(config)

    print("\nTesting authentication...")
    auth = ZscalerAuth(config)
    auth.authenticate()
    print("Configuration complete.\n")


# ---------------------------------------------------------------------------
# Commands: onboard
# ---------------------------------------------------------------------------

def cmd_onboard(args):
    config = load_config()
    auth = ZscalerAuth(config)
    auth.authenticate()

    gen_scripts = args.generate_scripts
    manual_ext_id = (args.external_id or "").strip() or None

    if args.bulk:
        _onboard_bulk(auth, args.bulk, gen_scripts, manual_ext_id)
    else:
        if not args.name or not args.account_id:
            print("Error: --name and --account-id required for single onboard.")
            print("  python3 zscaler_partner.py onboard --name 'prod' --account-id 123456789012")
            print("  python3 zscaler_partner.py onboard --bulk accounts.csv")
            sys.exit(1)
        _onboard_single(auth, args.name, args.account_id, args.role_name or "ZscalerDiscoveryRole",
                        gen_scripts, manual_ext_id)


def _resolve_external_id(auth, aws_account_id, role_name, manual_ext_id=None):
    """Return (external_id, raw_response). Uses manual_ext_id if given, else asks Zscaler to generate one."""
    if manual_ext_id:
        return manual_ext_id, None
    ext_result = auth.post("/publicCloudInfo/generateExternalId", {
        "awsAccountId": aws_account_id, "awsRoleName": role_name,
    })
    external_id = ext_result.get("_raw", ext_result) if isinstance(ext_result, dict) else ext_result
    if not external_id or (isinstance(ext_result, dict) and ext_result.get("_error")):
        return None, ext_result
    return external_id, ext_result


def _find_account_by_aws_id(auth, aws_account_id):
    accounts = auth.get("/publicCloudInfo")
    if not isinstance(accounts, list):
        return None
    for acct in accounts:
        if acct.get("accountDetails", {}).get("awsAccountId") == aws_account_id:
            return acct
    return None


def _write_results(filename, results):
    if not results:
        return
    fieldnames = ["account_name", "aws_account_id", "iam_role_name",
                  "zscaler_id", "external_id", "trusted_role", "status"]
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)


def _generate_iam_scripts(results, output_dir="generated-scripts"):
    """Generate per-account IAM role create/delete shell scripts."""
    if not results:
        return

    os.makedirs(output_dir, exist_ok=True)
    trusted_role = "arn:aws:iam::175726779870:role/ZscalerTagDiscoveryRole"
    create_scripts = []
    delete_scripts = []

    for r in results:
        aws_id = r["aws_account_id"]
        role_name = r["iam_role_name"]
        external_id = r["external_id"]
        acct_name = r["account_name"]

        trust_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": trusted_role},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": external_id}}
            }]
        })

        permissions_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": [
                    "ec2:DescribeVpcs", "ec2:DescribeSubnets",
                    "ec2:DescribeInstances", "ec2:DescribeNetworkInterfaces",
                    "ec2:DescribeIamInstanceProfileAssociations",
                    "ec2:DescribeVpcEndpoints"
                ],
                "Resource": "*"
            }]
        })

        # Create script
        create_file = f"{output_dir}/create-iam-{aws_id}.sh"
        with open(create_file, "w") as f:
            f.write(f"""#!/bin/bash
# Account: {acct_name} ({aws_id})
# Generated by zscaler_partner.py
# Run this while authenticated to AWS account {aws_id}

echo "Creating IAM role {role_name} in account {aws_id}..."

aws iam create-role \\
  --role-name {role_name} \\
  --assume-role-policy-document '{trust_policy}' \\
  --tags Key=Name,Value={role_name} Key=ManagedBy,Value=zscaler-partner-api \\
  --query "Role.{{RoleName:RoleName,Arn:Arn}}" 2>&1

aws iam put-role-policy \\
  --role-name {role_name} \\
  --policy-name ZscalerTagDiscovery \\
  --policy-document '{permissions_policy}' 2>&1

echo "Done. IAM role {role_name} created in account {aws_id}."
""")
        os.chmod(create_file, 0o755)
        create_scripts.append(f"create-iam-{aws_id}.sh")

        # Delete script
        delete_file = f"{output_dir}/delete-iam-{aws_id}.sh"
        with open(delete_file, "w") as f:
            f.write(f"""#!/bin/bash
# Account: {acct_name} ({aws_id})
# Generated by zscaler_partner.py
# Run this while authenticated to AWS account {aws_id}

echo "Deleting IAM role {role_name} from account {aws_id}..."

aws iam delete-role-policy \\
  --role-name {role_name} \\
  --policy-name ZscalerTagDiscovery 2>&1

aws iam delete-role \\
  --role-name {role_name} 2>&1

echo "Done. IAM role {role_name} deleted from account {aws_id}."
""")
        os.chmod(delete_file, 0o755)
        delete_scripts.append(f"delete-iam-{aws_id}.sh")

    # run-all-create.sh
    with open(f"{output_dir}/run-all-create.sh", "w") as f:
        f.write("#!/bin/bash\n")
        f.write("# Run all IAM role create scripts\n")
        f.write("# NOTE: You must be authenticated to each target AWS account before running its script.\n\n")
        for s in create_scripts:
            f.write(f'echo "\\n=== Running {s} ==="\n')
            f.write(f'"./{s}"\n\n')
        f.write('echo "\\nAll create scripts completed."\n')
    os.chmod(f"{output_dir}/run-all-create.sh", 0o755)

    # run-all-delete.sh
    with open(f"{output_dir}/run-all-delete.sh", "w") as f:
        f.write("#!/bin/bash\n")
        f.write("# Run all IAM role delete scripts\n")
        f.write("# NOTE: You must be authenticated to each target AWS account before running its script.\n\n")
        for s in delete_scripts:
            f.write(f'echo "\\n=== Running {s} ==="\n')
            f.write(f'"./{s}"\n\n')
        f.write('echo "\\nAll delete scripts completed."\n')
    os.chmod(f"{output_dir}/run-all-delete.sh", 0o755)

    print(f"\n  IAM scripts generated in {output_dir}/:")
    for s in create_scripts:
        print(f"    {s}")
    for s in delete_scripts:
        print(f"    {s}")
    print(f"    run-all-create.sh")
    print(f"    run-all-delete.sh")


def _onboard_single(auth, name, aws_account_id, role_name, gen_scripts=False, manual_ext_id=None):
    print(f"\n--- Onboarding: {name} ({aws_account_id}) ---\n")

    existing = _find_account_by_aws_id(auth, aws_account_id)
    if existing:
        print(f"Account already registered (Zscaler ID: {existing['id']}, name: {existing['name']})")
        return

    print("Using manual external ID..." if manual_ext_id else "Generating external ID...")
    external_id, ext_result = _resolve_external_id(auth, aws_account_id, role_name, manual_ext_id)
    if not external_id:
        print(f"Error generating external ID: {ext_result}")
        sys.exit(1)
    print(f"External ID: {external_id}")

    print("Fetching supported regions...")
    regions = auth.get("/publicCloudInfo/supportedRegions")
    region_list = regions if isinstance(regions, list) else []
    print(f"Found {len(region_list)} regions")

    print(f"Registering account '{name}'...")
    payload = {
        "name": name, "cloudType": "AWS",
        "externalId": external_id,
        "accountDetails": {
            "awsAccountId": aws_account_id, "awsRoleName": role_name,
            "externalId": external_id,
        },
        "supportedRegions": region_list,
    }

    result = auth.post("/publicCloudInfo", payload)
    if isinstance(result, dict) and result.get("code"):
        print(f"Error: {result.get('message', result)}")
        sys.exit(1)

    zscaler_id = result.get("id", "") if isinstance(result, dict) else ""
    if not zscaler_id:
        fallback = _find_account_by_aws_id(auth, aws_account_id)
        if fallback:
            zscaler_id = fallback["id"]
        else:
            print(f"Error: Account creation failed. Response: {result}")
            sys.exit(1)

    auth.force_activation()

    print(f"\n--- Onboarding Complete ---")
    print(f"  Account Name:    {name}")
    print(f"  AWS Account ID:  {aws_account_id}")
    print(f"  Zscaler ID:      {zscaler_id}")
    print(f"  External ID:     {external_id}")
    print(f"  IAM Role Name:   {role_name}")
    print(f"  Regions:         {len(region_list)}")
    if gen_scripts:
        _generate_iam_scripts([{
            "account_name": name, "aws_account_id": aws_account_id,
            "iam_role_name": role_name, "external_id": external_id,
        }])
    else:
        print(f"\n  Next: Create IAM role '{role_name}' in AWS account {aws_account_id}")
        print(f"    with External ID: {external_id}")
        print(f"    Trust: arn:aws:iam::175726779870:role/ZscalerTagDiscoveryRole")
        print(f"\n  Or re-run with --generate-scripts to generate IAM shell scripts.\n")


def _onboard_bulk(auth, csv_file, gen_scripts=False, manual_ext_id=None):
    if not os.path.exists(csv_file):
        print(f"Error: CSV file not found: {csv_file}")
        sys.exit(1)

    with open(csv_file) as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        rows = list(reader)

    required = {"account_name", "aws_account_id", "iam_role_name"}
    if not required.issubset(set(fieldnames)):
        print(f"Error: CSV must have columns: {', '.join(required)}")
        sys.exit(1)

    if not rows:
        print("Error: CSV has no data rows.")
        sys.exit(1)

    print(f"\n--- Bulk Onboarding: {len(rows)} accounts from {csv_file} ---\n")
    if manual_ext_id:
        print(f"Using manual external ID for all accounts: {manual_ext_id}")
    if "external_id" in fieldnames:
        print("CSV 'external_id' column found -- per-row values override --external-id")

    print("Fetching supported regions...")
    regions = auth.get("/publicCloudInfo/supportedRegions")
    region_list = regions if isinstance(regions, list) else []
    print(f"Found {len(region_list)} regions")

    existing_accounts = auth.get("/publicCloudInfo")
    existing_list = existing_accounts if isinstance(existing_accounts, list) else []
    existing_map = {}
    for acct in existing_list:
        aws_id = acct.get("accountDetails", {}).get("awsAccountId", "")
        if aws_id:
            existing_map[aws_id] = acct

    print()

    results = []
    created = 0
    existing_count = 0
    results_file = "onboard-results.csv"

    for i, row in enumerate(rows):
        name = row["account_name"].strip()
        aws_id = row["aws_account_id"].strip()
        role = row["iam_role_name"].strip()

        print(f"  [{i+1}/{len(rows)}] {name} ({aws_id})... ", end="", flush=True)

        if aws_id in existing_map:
            acct = existing_map[aws_id]
            print(f"existing (Zscaler ID: {acct['id']}, name: {acct.get('name', '')})")
            results.append({
                "account_name": name, "aws_account_id": aws_id,
                "iam_role_name": role, "zscaler_id": str(acct["id"]),
                "external_id": acct.get("externalId", ""),
                "trusted_role": "arn:aws:iam::175726779870:role/ZscalerTagDiscoveryRole",
                "status": "existing",
            })
            existing_count += 1
            continue

        auth.refresh_if_needed()
        row_ext_id = (row.get("external_id") or "").strip() or manual_ext_id
        external_id, ext_result = _resolve_external_id(auth, aws_id, role, row_ext_id)

        if not external_id:
            print("FAILED (external ID)")
            print(f"\nError: Failed to generate external ID for '{name}' ({aws_id})")
            print(f"Response: {ext_result}")
            print(f"\nStopping. {created} of {len(rows)} accounts onboarded.")
            _write_results(results_file, results)
            sys.exit(1)

        auth.refresh_if_needed()
        payload = {
            "name": name, "cloudType": "AWS",
            "externalId": external_id,
            "accountDetails": {
                "awsAccountId": aws_id, "awsRoleName": role,
                "externalId": external_id,
            },
            "supportedRegions": region_list,
        }

        create_result = auth.post("/publicCloudInfo", payload)

        if isinstance(create_result, dict) and create_result.get("code"):
            print("FAILED")
            print(f"\nError: Failed to register '{name}' ({aws_id})")
            print(f"Response: {create_result}")
            print(f"\nStopping. {created} of {len(rows)} accounts onboarded.")
            _write_results(results_file, results)
            sys.exit(1)

        zscaler_id = ""
        if isinstance(create_result, dict):
            zscaler_id = str(create_result.get("id", ""))

        if not zscaler_id:
            auth.refresh_if_needed()
            fallback = _find_account_by_aws_id(auth, aws_id)
            if fallback:
                zscaler_id = str(fallback["id"])
                existing_map[aws_id] = fallback

        if not zscaler_id:
            print("FAILED (not created)")
            print(f"\nError: Account '{name}' ({aws_id}) was not created.")
            print(f"\nStopping. {created} of {len(rows)} accounts onboarded.")
            _write_results(results_file, results)
            sys.exit(1)

        print(f"created (Zscaler ID: {zscaler_id})")
        results.append({
            "account_name": name, "aws_account_id": aws_id,
            "iam_role_name": role, "zscaler_id": zscaler_id,
            "external_id": external_id,
            "trusted_role": "arn:aws:iam::175726779870:role/ZscalerTagDiscoveryRole",
            "status": "created",
        })
        created += 1

    if created > 0:
        print()
        auth.force_activation()

    _write_results(results_file, results)

    print(f"\n{'='*60}")
    print(f"  BULK ONBOARDING RESULTS")
    print(f"{'='*60}\n")
    print(f"  {'Name':<20} {'AWS Account':<16} {'Zscaler ID':<12} {'External ID':<34} {'Status':<10}")
    print(f"  {'-'*20} {'-'*16} {'-'*12} {'-'*34} {'-'*10}")
    for r in results:
        ext = r["external_id"][:32] + ".." if len(r["external_id"]) > 32 else r["external_id"]
        print(f"  {r['account_name']:<20} {r['aws_account_id']:<16} {r['zscaler_id']:<12} {ext:<34} {r['status']:<10}")
    print(f"\n  Created: {created} | Existing: {existing_count} | Total: {len(rows)}")
    print(f"  Results saved to: {results_file}")

    if created > 0 and gen_scripts:
        _generate_iam_scripts(results)
    elif created > 0:
        print(f"\n{'='*60}")
        print(f"  NEXT STEPS")
        print(f"{'='*60}\n")
        print(f"  Create IAM roles in each AWS account.")
        print(f"  Re-run with --generate-scripts to generate per-account shell scripts.")
        print(f"  Or use CloudFormation StackSets with external IDs from {results_file}.\n")


# ---------------------------------------------------------------------------
# Commands: update
# ---------------------------------------------------------------------------

def cmd_update(args):
    config = load_config()
    auth = ZscalerAuth(config)
    auth.authenticate()

    zscaler_id = args.id
    print(f"\nFetching account {zscaler_id}...")

    acct = auth.get(f"/publicCloudInfo/{zscaler_id}")
    if isinstance(acct, dict) and acct.get("code"):
        print(f"Error: {acct.get('message', 'Account not found')}")
        sys.exit(1)

    print(f"  Current name:      {acct.get('name', '')}")
    print(f"  AWS Account ID:    {acct.get('accountDetails', {}).get('awsAccountId', '')}")
    print(f"  IAM Role:          {acct.get('accountDetails', {}).get('awsRoleName', '')}")

    if args.name:
        acct["name"] = args.name
        print(f"  Updating name to:  {args.name}")
    if args.role_name:
        acct["accountDetails"]["awsRoleName"] = args.role_name
        print(f"  Updating role to:  {args.role_name}")

    result = auth.put(f"/publicCloudInfo/{zscaler_id}", acct)
    if isinstance(result, dict) and result.get("code"):
        print(f"Error: {result.get('message', result)}")
        sys.exit(1)

    print("Account updated.")
    auth.force_activation()


# ---------------------------------------------------------------------------
# Commands: list
# ---------------------------------------------------------------------------

def cmd_list(args):
    config = load_config()
    auth = ZscalerAuth(config)
    auth.authenticate()

    query = args.query
    query_id = args.query_id

    if query == "accounts":
        _list_accounts(auth)
    elif query == "groups":
        _list_groups(auth)
    elif query == "regions":
        _list_regions(auth)
    elif query == "account":
        if not query_id:
            _show_available_accounts(auth)
            query_id = input("\nEnter account ID: ").strip()
        _show_account(auth, query_id)
    elif query == "permissions":
        if not query_id:
            _show_available_accounts(auth)
            query_id = input("\nEnter account ID: ").strip()
        _show_permissions(auth, query_id)
    else:
        print(f"Unknown query: {query}")
        print("Available: accounts, groups, regions, account <id>, permissions <id>")


def _show_available_accounts(auth):
    accounts = auth.get("/publicCloudInfo/lite")
    if isinstance(accounts, list):
        print("\nAvailable accounts:")
        for a in accounts:
            print(f"  ID: {a['id']}  Name: {a['name']}  AWS: {a.get('accountId', '')}")


def _list_accounts(auth):
    accounts = auth.get("/publicCloudInfo")
    acct_list = accounts if isinstance(accounts, list) else []

    print(f"\n{'='*80}")
    print(f"  ONBOARDED AWS ACCOUNTS")
    print(f"{'='*80}\n")

    if not acct_list:
        print("  No accounts onboarded.\n")
        return

    print(f"  {'ID':<12} {'Name':<20} {'AWS Account':<16} {'Regions':<10} {'Permission':<12} {'Groups':<10}")
    print(f"  {'-'*12} {'-'*20} {'-'*16} {'-'*10} {'-'*12} {'-'*10}")
    for acct in acct_list:
        details = acct.get("accountDetails", {})
        perm = acct.get("permissionStatus", {}).get("permission", {}).get("status", "Unknown")
        regions = len(acct.get("supportedRegions", []))
        groups = len(acct.get("accountGroups", []))
        aws_id = details.get("awsAccountId", "")
        print(f"  {acct['id']:<12} {acct['name']:<20} {aws_id:<16} {regions:<10} {perm:<12} {groups:<10}")
    print(f"\n  Total: {len(acct_list)} account(s)\n")


def _list_groups(auth):
    groups = auth.get("/accountGroups")
    group_list = groups if isinstance(groups, list) else []

    print(f"\n{'='*60}")
    print(f"  ACCOUNT GROUPS")
    print(f"{'='*60}\n")

    if not group_list:
        print("  No account groups found.\n")
        return

    for g in group_list:
        print(f"  Group: {g['name']} (ID: {g['id']})")
        accts = g.get("publicCloudAccounts", [])
        for a in accts:
            print(f"    Account: {a['name']} (ID: {a['id']})")
        if not accts:
            print(f"    No accounts assigned")
        ccs = g.get("cloudConnectorGroups", [])
        if ccs:
            print(f"    Cloud Connector Groups: {len(ccs)}")
        print()
    print(f"  Total: {len(group_list)} group(s)\n")


def _list_regions(auth):
    regions = auth.get("/publicCloudInfo/supportedRegions")
    region_list = regions if isinstance(regions, list) else []

    print(f"\n{'='*60}")
    print(f"  SUPPORTED AWS REGIONS")
    print(f"{'='*60}\n")

    if not region_list:
        print("  No regions found.\n")
        return

    print(f"  {'ID':<12} {'Region Code':<20} {'Region Name':<20}")
    print(f"  {'-'*12} {'-'*20} {'-'*20}")
    for r in sorted(region_list, key=lambda x: x.get("regionName", "")):
        print(f"  {r['id']:<12} {r.get('name', ''):<20} {r.get('regionName', ''):<20}")
    print(f"\n  Total: {len(region_list)} region(s)\n")


def _show_account(auth, acct_id):
    acct = auth.get(f"/publicCloudInfo/{acct_id}")
    if isinstance(acct, dict) and acct.get("code"):
        print(f"Error: {acct.get('message', 'Not found')}")
        return

    details = acct.get("accountDetails", {})

    print(f"\n{'='*60}")
    print(f"  ACCOUNT DETAILS (ID: {acct_id})")
    print(f"{'='*60}\n")
    print(f"  Name:                {acct.get('name', '')}")
    print(f"  Zscaler ID:          {acct.get('id', '')}")
    print(f"  Cloud Type:          {acct.get('cloudType', '')}")
    print(f"  AWS Account ID:      {details.get('awsAccountId', '')}")
    print(f"  IAM Role Name:       {details.get('awsRoleName', '')}")
    print(f"  External ID:         {acct.get('externalId', '')}")
    print(f"  Trusted Account:     {details.get('trustedAccountId', '')}")
    print(f"  Trusted Role:        {details.get('trustedRole', '')}")
    print(f"  Event Bus:           {details.get('eventBusName', '')}")

    regions = acct.get("supportedRegions", [])
    print(f"\n  Enabled Regions ({len(regions)}):")
    for r in regions:
        print(f"    {r.get('regionName', '')} ({r.get('name', '')})")

    groups = acct.get("accountGroups", [])
    print(f"\n  Account Groups ({len(groups)}):")
    for g in groups:
        print(f"    {g.get('name', '')} (ID: {g.get('id', '')})")
    if not groups:
        print(f"    None")
    print()


def _show_permissions(auth, acct_id):
    acct = auth.get(f"/publicCloudInfo/{acct_id}")
    if isinstance(acct, dict) and acct.get("code"):
        print(f"Error: {acct.get('message', 'Not found')}")
        return

    details = acct.get("accountDetails", {})
    perm = acct.get("permissionStatus", {})
    status = perm.get("status", {})
    overall = perm.get("permission", {})

    print(f"\n{'='*60}")
    print(f"  PERMISSION STATUS (Account ID: {acct_id})")
    print(f"{'='*60}\n")
    print(f"  Account:             {acct.get('name', '')} ({details.get('awsAccountId', '')})")
    print(f"  IAM Role:            {details.get('awsRoleName', '')}")
    print(f"  Overall Status:      {overall.get('status', 'Unknown')}")
    print(f"\n  Permission Details:")
    for perm_name, perm_status in status.items():
        icon = "  OK " if perm_status == "Allowed" else "  !!!"
        print(f"    {icon}  {perm_name}: {perm_status}")
    print()


# ---------------------------------------------------------------------------
# Commands: groups
# ---------------------------------------------------------------------------

def cmd_groups(args):
    config = load_config()
    auth = ZscalerAuth(config)
    auth.authenticate()

    action = args.action
    if action == "create":
        _group_create(auth)
    elif action == "update":
        if not args.group_id:
            print("Error: group ID required. Usage: groups update <id>")
            sys.exit(1)
        _group_update(auth, args.group_id)
    elif action == "delete":
        if not args.group_id:
            print("Error: group ID required. Usage: groups delete <id>")
            sys.exit(1)
        _group_delete(auth, args.group_id)
    elif action == "list":
        _list_groups(auth)
    else:
        print(f"Unknown action: {action}")


def _group_create(auth):
    print("\n--- Create Account Group ---\n")
    name = input("Enter group name: ").strip()
    if not name:
        print("Error: Group name is required.")
        sys.exit(1)

    _show_available_accounts(auth)
    ids_input = input("\nEnter account IDs to include (comma-separated): ").strip()
    account_ids = [int(x.strip()) for x in ids_input.split(",") if x.strip()] if ids_input else []

    payload = {"name": name, "cloudType": "AWS",
               "publicCloudAccounts": [{"id": i} for i in account_ids]}

    result = auth.post("/accountGroups", payload)
    if isinstance(result, dict) and result.get("code"):
        print(f"Error: {result.get('message', result)}")
        sys.exit(1)

    print(f"\nAccount group '{name}' created (ID: {result.get('id', '')})")
    auth.force_activation()


def _group_update(auth, group_id):
    print(f"\n--- Update Account Group {group_id} ---\n")

    current = auth.get(f"/accountGroups/{group_id}")
    if isinstance(current, dict) and current.get("code"):
        print(f"Error: {current.get('message', 'Group not found')}")
        sys.exit(1)

    print(f"  Current name: {current.get('name', '')}")
    accts = current.get("publicCloudAccounts", [])
    print(f"  Current accounts ({len(accts)}):")
    for a in accts:
        print(f"    {a['name']} (ID: {a['id']})")

    _show_available_accounts(auth)

    new_name = input(f"\nNew group name [Enter to keep '{current.get('name', '')}']: ").strip()
    ids_input = input("New account IDs (comma-separated): ").strip()
    account_ids = [int(x.strip()) for x in ids_input.split(",") if x.strip()] if ids_input else []

    payload = {"id": int(group_id), "name": new_name or current.get("name", ""),
               "cloudType": "AWS", "publicCloudAccounts": [{"id": i} for i in account_ids]}

    result = auth.put(f"/accountGroups/{group_id}", payload)
    if isinstance(result, dict) and result.get("code"):
        print(f"Error: {result.get('message', result)}")
        sys.exit(1)

    print("Account group updated.")
    auth.force_activation()


def _group_delete(auth, group_id):
    confirm = input(f"Delete group {group_id}? (yes/no): ").strip()
    if confirm not in ("yes", "y"):
        print("Cancelled.")
        return

    result = auth.delete(f"/accountGroups/{group_id}")
    http_code = result.get("_http_code", 0) if isinstance(result, dict) else 0

    if http_code in (200, 204):
        print(f"Account group {group_id} deleted.")
        auth.force_activation()
    else:
        print(f"Error deleting group: {result}")


# ---------------------------------------------------------------------------
# Commands: destroy
# ---------------------------------------------------------------------------

def cmd_destroy(args):
    config = load_config()
    auth = ZscalerAuth(config)
    auth.authenticate()

    if args.zscaler_id:
        zscaler_id = args.zscaler_id
        print(f"\nLooking up Zscaler account {zscaler_id}...")
    else:
        aws_id = args.aws_account_id
        if not aws_id:
            print("Error: AWS account ID or --id required.")
            sys.exit(1)
        print(f"\nLooking up AWS account {aws_id}...")
        acct = _find_account_by_aws_id(auth, aws_id)
        if not acct:
            print(f"Account {aws_id} not found. May already be deleted.")
            return
        zscaler_id = acct["id"]
        print(f"Found: {acct.get('name', '')} (Zscaler ID: {zscaler_id})")

    confirm = input(f"\nDelete account {zscaler_id}? (yes/no): ").strip()
    if confirm not in ("yes", "y"):
        print("Cancelled.")
        return

    result = auth.delete(f"/publicCloudInfo/{zscaler_id}")
    http_code = result.get("_http_code", 0) if isinstance(result, dict) else 0

    if http_code in (200, 204):
        print(f"Account {zscaler_id} deleted from Zscaler.")
        auth.force_activation()
    elif http_code == 404:
        print("Account not found (already deleted).")
    else:
        print(f"Error deleting account: {result}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Zscaler Partner Integration CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s configure
  %(prog)s onboard --name "prod-aws" --account-id 123456789012
  %(prog)s onboard --bulk accounts.csv
  %(prog)s list accounts
  %(prog)s list permissions 1234567
  %(prog)s groups create
  %(prog)s groups delete 2442003
  %(prog)s update 1234567 --name "new-name"
  %(prog)s destroy 123456789012
  %(prog)s destroy --id 1234567
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    subparsers.add_parser("configure", help="Configure Zscaler credentials")

    onboard_p = subparsers.add_parser("onboard", help="Onboard AWS account(s)")
    onboard_p.add_argument("--name", help="Account name in Zscaler")
    onboard_p.add_argument("--account-id", help="12-digit AWS account ID")
    onboard_p.add_argument("--role-name", default="ZscalerDiscoveryRole", help="IAM role name")
    onboard_p.add_argument("--bulk", metavar="CSV", help="CSV file for bulk onboarding")
    onboard_p.add_argument("--generate-scripts", action="store_true",
                           help="Generate per-account IAM role create/delete shell scripts")
    onboard_p.add_argument("--external-id",
                           help="Use this external ID instead of generating one via Zscaler. "
                                "With --bulk, applies to every row (CSV 'external_id' column overrides per row)")

    update_p = subparsers.add_parser("update", help="Update an AWS account")
    update_p.add_argument("id", help="Zscaler account ID")
    update_p.add_argument("--name", help="New account name")
    update_p.add_argument("--role-name", help="New IAM role name")

    list_p = subparsers.add_parser("list", help="List/query resources")
    list_p.add_argument("query", choices=["accounts", "groups", "regions", "account", "permissions"])
    list_p.add_argument("query_id", nargs="?", help="ID for account/permissions")

    groups_p = subparsers.add_parser("groups", help="Manage account groups")
    groups_p.add_argument("action", choices=["create", "update", "delete", "list"])
    groups_p.add_argument("group_id", nargs="?", help="Group ID for update/delete")

    destroy_p = subparsers.add_parser("destroy", help="Delete AWS account from Zscaler")
    destroy_p.add_argument("aws_account_id", nargs="?", help="12-digit AWS account ID")
    destroy_p.add_argument("--id", dest="zscaler_id", help="Zscaler account ID")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    {"configure": cmd_configure, "onboard": cmd_onboard, "update": cmd_update,
     "list": cmd_list, "groups": cmd_groups, "destroy": cmd_destroy}[args.command](args)


if __name__ == "__main__":
    main()
