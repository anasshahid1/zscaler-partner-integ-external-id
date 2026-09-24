# Zscaler Partner Integration -- Shared External ID Onboarding

Onboard one or many AWS accounts into Zscaler Partner Integration (Tag Discovery)
using a **single, caller-supplied External ID**, on both the Zscaler and AWS side,
with one command.

Why: Zscaler normally generates a random External ID per account, which forces a
different CloudFormation parameter for every account. Zscaler's API accepts a
manual `externalId` on create (verified), so one ID can be shared across all
accounts and deployed with a single StackSet parameter set.

---

## Prerequisites

- Python 3.9+
- AWS CLI v2, with a profile per target account (only if the script deploys the role for you)
- Zscaler OneAPI client credentials (Client ID / Secret, vanity domain, cloud)

## Setup

1. Copy the Zscaler credentials template and fill it in (do not commit):

```bash
cp cli/zscaler-creds.example.csv cli/zscaler.local.csv
# edit cli/zscaler.local.csv with your OneAPI client_id, client_secret, vanity_domain
```

CSV columns:
```csv
client_id,client_secret,vanity_domain,cloud,login_domain
your_client_id,your_client_secret,your_vanity,zscalerthree,zslogin.net
```

`cloud` defaults to `zscalerthree`; `login_domain` defaults to `zslogin.net`. These credentials are never logged, printed, or committed (`*.local.csv` is gitignored).

## Onboard

1. Edit `examples/accounts-shared.csv` -- one row per account:

   ```csv
   account_name,aws_account_id,aws_profile,iam_role_name
   prod-east,111111111111,prod-east-admin,ZscalerDiscoveryRole
   prod-west,222222222222,prod-west-admin,ZscalerDiscoveryRole
   ```

   | Column | Meaning |
   |---|---|
   | `account_name` | Display name in Zscaler |
   | `aws_account_id` | 12-digit AWS account |
   | `aws_profile` | AWS CLI profile with rights in that account (used for `cloudformation deploy`) |
   | `iam_role_name` | Role Zscaler assumes (optional, default `ZscalerDiscoveryRole`) |

2. Dry run (nothing created):

   ```bash
   python3 cli/onboard_shared.py examples/accounts-shared.csv --dry-run
   ```

3. Real run:

   ```bash
   python3 cli/onboard_shared.py examples/accounts-shared.csv
   ```

Per account the script:
1. **Zscaler** -- `POST /publicCloudInfo` with the shared `externalId` (skipped if already registered)
2. **AWS** -- deploys Zscaler's CloudFormation template with `ExternalId=<shared>` using the row's profile (or updates the trust policy if the role already exists)
3. **Verify** -- `PUT /discoveryService/{id}/permissions` forces a re-check and prints `Allowed` / `Denied`

The External ID is generated once and stored in `~/.zscaler/shared-external-id`;
pass `--external-id <value>` to supply your own. Re-running is safe: existing
accounts are skipped and re-verified.

### Using access keys instead of profiles

If you don't want to set up AWS CLI profiles, put the keys directly in the row:

```bash
cp examples/accounts-creds.csv examples/accounts.local.csv   # *.local.csv is gitignored
# edit examples/accounts.local.csv and fill in the keys
python3 cli/onboard_shared.py examples/accounts.local.csv
```

```csv
account_name,aws_account_id,aws_access_key_id,aws_secret_access_key,aws_session_token,iam_role_name
prod-east,111111111111,AKIA...,<secret>,,ZscalerDiscoveryRole
```

`aws_session_token` is only needed for temporary (STS/SSO) credentials. Keys are
handed to the `aws` CLI through environment variables for that subprocess only;
they are never logged, printed or written anywhere. Keys in a row take precedence
over `aws_profile`. Delete the `.local.csv` when done.

### Without AWS credentials in the script

```bash
python3 cli/onboard_shared.py examples/accounts-shared.csv --skip-aws
```

Does the Zscaler side only (CSV needs just `account_name,aws_account_id`). Then
deploy the role yourself -- e.g. a CloudFormation **StackSet** across all accounts:

- Template: `https://zscaler-discovery-role.s3.amazonaws.com/zscaler_discovery_role.yaml`
- `TrustingAccountRoleName` = `ZscalerDiscoveryRole`
- `ZscalerTrustedRole` = `arn:aws:iam::175726779870:role/ZscalerTagDiscoveryRole`
- `ExternalId` = your shared ID

Re-run the same `--skip-aws` command afterwards to verify.

## Clean up

```bash
python3 cli/zscaler_partner.py destroy --id <zscaler_id>
aws cloudformation delete-stack --region us-east-1 --stack-name ZscalerTagDiscoveryTrustingRole-shared --profile <profile>
```

## Tools

- `tools/probe_external_id.py` -- proves whether the tenant accepts a manual External ID (create / update / generate variants, self-cleaning)
- `tools/inspect_cft.py` -- fetches the Zscaler CloudFormation quick-create link for an account

## Notes

- `175726779870` is Zscaler's own AWS account (the trusted principal); it is public and identical for all customers.
- A shared External ID reduces confused-deputy protection compared with per-account IDs. Acceptable for labs; evaluate for production.
- The `POST /publicCloudInfo` call can take over 2 minutes to respond; the account is still created and the script recovers via lookup.
- `cli/zscaler_partner.py` is the general-purpose CLI (list, groups, update, destroy, `onboard --external-id`); `onboard_shared.py` builds on it.
