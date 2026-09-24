#!/usr/bin/env python3
"""
Probe: does Zscaler Partner Integration accept a caller-supplied externalId?

Runs against ONE sandbox AWS account ID and cleans up after each variant.

  A  create with manual externalId in POST body
  B  create normally -> PUT with manual externalId
  C  generateExternalId for two different account IDs -> are they different?

Usage:
  python3 probe_external_id.py --account-id 111111111111 --account-id-2 222222222222 \
      --external-id my-shared-ext-id [--only A,B,C] [--keep]

Reuses ~/.zscaler/config.json and ZscalerAuth from ../zscaler-partner-api/cli.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "cli"))
from zscaler_partner import ZscalerAuth, load_config  # noqa: E402

ROLE = "ZscalerDiscoveryRole"
NAME = "extid-probe"


def show(label, obj):
    print(f"    {label}: {json.dumps(obj, indent=None)[:400]}")


def stored_ext_id(auth, zid):
    acct = auth.get(f"/publicCloudInfo/{zid}")
    return acct.get("externalId") if isinstance(acct, dict) else None, acct


def find_by_aws(auth, aws_id):
    for a in auth.get("/publicCloudInfo") or []:
        if isinstance(a, dict) and a.get("accountDetails", {}).get("awsAccountId") == aws_id:
            return a
    return None


def cleanup(auth, aws_id, keep):
    a = find_by_aws(auth, aws_id)
    if not a:
        return
    if keep:
        print(f"    [keep] leaving Zscaler ID {a['id']} in place")
        return
    r = auth.delete(f"/publicCloudInfo/{a['id']}")
    print(f"    cleanup: deleted Zscaler ID {a['id']} -> {r}")


def gen_ext(auth, aws_id):
    r = auth.post("/publicCloudInfo/generateExternalId", {"awsAccountId": aws_id, "awsRoleName": ROLE})
    return r.get("_raw", r) if isinstance(r, dict) else r


def create(auth, aws_id, regions, ext=None):
    payload = {"name": NAME, "cloudType": "AWS",
               "accountDetails": {"awsAccountId": aws_id, "awsRoleName": ROLE},
               "supportedRegions": regions}
    if ext:
        payload["externalId"] = ext
        payload["accountDetails"]["externalId"] = ext
    r = auth.post("/publicCloudInfo", payload)
    zid = r.get("id") if isinstance(r, dict) else None
    if not zid:
        a = find_by_aws(auth, aws_id)
        zid = a["id"] if a else None
    return zid, r


def verdict(want, got):
    if got == want:
        return "ACCEPTED  (stored == manual)"
    if not got:
        return "UNKNOWN   (no externalId in GET response)"
    return "REPLACED  (Zscaler stored its own value)"


def variant_a(auth, aws_id, ext, regions, keep):
    print("\n=== A: create with manual externalId in body ===")
    cleanup(auth, aws_id, False)
    zid, r = create(auth, aws_id, regions, ext)
    show("create response", r)
    if not zid:
        print("    RESULT: REJECTED (account not created)")
        return
    got, acct = stored_ext_id(auth, zid)
    show("GET after create", {"externalId": got})
    print(f"    RESULT: {verdict(ext, got)}")
    cleanup(auth, aws_id, keep)


def variant_b(auth, aws_id, ext, regions, keep):
    print("\n=== B: create normally, then PUT manual externalId ===")
    cleanup(auth, aws_id, False)
    zid, r = create(auth, aws_id, regions)
    show("create response", r)
    if not zid:
        print("    RESULT: create failed, cannot test PUT")
        return
    before, acct = stored_ext_id(auth, zid)
    show("externalId before PUT", before)
    acct["externalId"] = ext
    acct.setdefault("accountDetails", {})["externalId"] = ext
    r = auth.put(f"/publicCloudInfo/{zid}", acct)
    show("PUT response", r)
    got, _ = stored_ext_id(auth, zid)
    show("GET after PUT", {"externalId": got})
    print(f"    RESULT: {verdict(ext, got)}")
    cleanup(auth, aws_id, keep)


def variant_c(auth, aws_id, aws_id_2):
    print("\n=== C: generateExternalId for two accounts -- same or different? ===")
    e1, e2 = gen_ext(auth, aws_id), gen_ext(auth, aws_id_2)
    e1b = gen_ext(auth, aws_id)
    print(f"    {aws_id}: {e1}")
    print(f"    {aws_id_2}: {e2}")
    print(f"    {aws_id} again: {e1b}")
    if e1 == e2:
        print("    RESULT: SAME across accounts -> tenant-wide ID; shared ID already works, nothing to change")
    elif e1 == e1b:
        print("    RESULT: DIFFERENT per account, STABLE per account -> deterministic; manual override needed")
    else:
        print("    RESULT: DIFFERENT per account, RANDOM per call -> manual override needed")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--account-id", required=True, help="sandbox AWS account ID (will be created/deleted)")
    p.add_argument("--account-id-2", help="second AWS account ID, for variant C")
    p.add_argument("--external-id", default="my-shared-ext-id")
    p.add_argument("--only", default="C,A,B", help="comma list of variants to run")
    p.add_argument("--keep", action="store_true", help="do not delete the probe account after A/B")
    args = p.parse_args()

    auth = ZscalerAuth(load_config())
    auth.authenticate()
    regions = auth.get("/publicCloudInfo/supportedRegions") or []

    for v in [x.strip().upper() for x in args.only.split(",")]:
        if v == "C":
            if not args.account_id_2:
                print("\n[skip C] needs --account-id-2")
                continue
            variant_c(auth, args.account_id, args.account_id_2)
        elif v == "A":
            variant_a(auth, args.account_id, args.external_id, regions, args.keep)
        elif v == "B":
            variant_b(auth, args.account_id, args.external_id, regions, args.keep)

    print("\nDone. If A or B says ACCEPTED, use that path in the CLI.")


if __name__ == "__main__":
    main()
