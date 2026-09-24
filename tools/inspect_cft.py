#!/usr/bin/env python3
"""
Pull Zscaler's CloudFormation template for an onboarded AWS account and report
whether the ExternalId is a stack Parameter (StackSets-friendly) or hardcoded.

Usage:
  python3 inspect_cft.py --account-id 111111111111 [--save]
"""

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "cli"))
from zscaler_partner import ZscalerAuth, load_config, api_request  # noqa: E402


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--account-id", required=True)
    p.add_argument("--save", action="store_true", help="save template to cft-<account>.json/yaml")
    args = p.parse_args()

    auth = ZscalerAuth(load_config())
    auth.authenticate()

    r = auth.get(f"/publicCloudInfo/cloudFormationTemplate?awsAccountId={args.account_id}")
    print(f"\nAPI response: {json.dumps(r)[:500]}\n")

    # Response may be a URL, a raw template, or JSON wrapping either
    body = None
    if isinstance(r, dict):
        body = r.get("_raw") or r.get("url") or r.get("templateUrl") or r.get("template") or json.dumps(r)
    else:
        body = str(r)

    if body.startswith("http"):
        print(f"Template URL: {body}\nDownloading...")
        t = api_request("GET", body.strip())
        body = t.get("_raw") if isinstance(t, dict) and "_raw" in t else json.dumps(t)

    ext = "cft-%s" % args.account_id
    if args.save:
        fn = ext + (".json" if body.lstrip().startswith("{") else ".yaml")
        Path(fn).write_text(body)
        print(f"Saved -> {fn}")

    print("\n--- ExternalId analysis ---")
    is_param = bool(re.search(r"Parameters[\s\S]{0,2000}ExternalId", body))
    refs = re.findall(r'"?sts:ExternalId"?\s*:\s*(.+)', body)
    hex32 = re.findall(r"\b[0-9a-f]{32}\b", body)

    print(f"ExternalId declared under Parameters: {is_param}")
    for x in refs[:3]:
        print(f"sts:ExternalId condition value: {x.strip()[:120]}")
    if hex32:
        print(f"Hardcoded 32-hex values found: {sorted(set(hex32))}")

    if is_param:
        print("\nVERDICT: parameterized -> StackSets with one shared ExternalId param is viable.")
    elif hex32:
        print("\nVERDICT: hardcoded -> per-account template; you would need your own generic CFT with an ExternalId param.")
    else:
        print("\nVERDICT: unclear -- inspect saved template manually (--save).")


if __name__ == "__main__":
    main()
