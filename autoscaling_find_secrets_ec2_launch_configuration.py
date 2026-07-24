#!/usr/bin/env python3
"""
Control : autoscaling_find_secrets_ec2_launch_configuration
Title   : [DEPRECATED] EC2 Auto Scaling launch configuration user data
          contains no secrets
Service : EC2 Auto Scaling (Launch Configurations)
Logic   : Decode each Launch Configuration's UserData (base64) and scan
          it for secret-like patterns (AWS access keys, hardcoded
          passwords, private key blocks, generic API/auth tokens). A
          Launch Configuration is NON_COMPLIANT if any pattern is found.
          No UserData at all is treated as COMPLIANT (nothing to leak).
          Note: Launch Configurations are a deprecated AWS feature, kept
          here only to audit legacy accounts that still have them.
"""

import argparse
import base64
import csv
import re
import boto3
from tqdm import tqdm
from botocore.exceptions import ClientError

CONTROL_NAME = "autoscaling_find_secrets_ec2_launch_configuration"

# ==================================================
# AUTH
# ==================================================

def get_session(role_arn=None):
    if role_arn:
        base = boto3.Session()
        sts = base.client("sts")
        assumed = sts.assume_role(RoleArn=role_arn, RoleSessionName="control-audit")
        creds = assumed["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    return boto3.Session()


def get_account_id(session):
    return session.client("sts").get_caller_identity()["Account"]


# ==================================================
# REGIONS
# ==================================================

def get_regions(session):
    ec2 = session.client("ec2", region_name="us-east-1")
    regions = ec2.describe_regions(AllRegions=True)["Regions"]
    return [
        r["RegionName"]
        for r in regions
        if r.get("OptInStatus") in ("opt-in-not-required", "opted-in")
    ]


# ==================================================
# HELPERS
# ==================================================

def classify_error(e):
    code = e.response["Error"]["Code"]
    if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
        return f"Access denied ({code})"
    if code in ("InvalidClientTokenId", "AuthFailure", "ExpiredToken"):
        return f"Auth error ({code})"
    if code in ("ThrottlingException", "Throttling", "RequestLimitExceeded"):
        return f"Throttled ({code})"
    return f"Error: {code}"


def add_row(results, account_id, region, resource_id, arn, status, evidence):
    results.append({
        "Account": account_id,
        "Region": region,
        "ResourceId": resource_id,
        "ResourceArn": arn,
        "Status": status,
        "Evidence": evidence,
    })


# Secret patterns to scan decoded UserData for. Each entry is
# (human-readable label, compiled regex).
SECRET_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Access Key", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}")),
    ("Private Key Block", re.compile(r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----")),
    ("Hardcoded Password", re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?\S+")),
    ("API/Auth Token", re.compile(r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"]?\S+")),
]


def scan_for_secrets(user_data_text):
    """Return a list of matched secret pattern labels found in the text."""
    found = []
    for label, pattern in SECRET_PATTERNS:
        if pattern.search(user_data_text):
            found.append(label)
    return found


def list_launch_configurations(client):
    configs, next_token = [], None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = client.describe_launch_configurations(**kwargs)
        configs.extend(resp.get("LaunchConfigurations", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return configs


# ==================================================
# CONTROL LOGIC
# ==================================================

def check_control(session, account_id):
    regions = get_regions(session)
    results = []
    total_checked = compliant = non_compliant = skipped = 0

    print(f"\nRegions to scan: {len(regions)}\n")

    for region in tqdm(regions, desc="Scanning Regions"):
        try:
            client = session.client("autoscaling", region_name=region)
            configs = list_launch_configurations(client)
        except ClientError as e:
            skipped += 1
            add_row(results, account_id, region, "N/A", "N/A", "SKIPPED", classify_error(e))
            continue

        for lc in configs:
            name = lc["LaunchConfigurationName"]
            arn = lc.get("LaunchConfigurationARN", f"arn:aws:autoscaling:{region}:{account_id}:launchConfiguration:{name}")
            total_checked += 1

            raw_user_data = lc.get("UserData")

            if not raw_user_data:
                status = "COMPLIANT"
                evidence = "No UserData present on the launch configuration"
                compliant += 1
            else:
                try:
                    decoded = base64.b64decode(raw_user_data).decode("utf-8", errors="ignore")
                    matches = scan_for_secrets(decoded)

                    if matches:
                        status = "NON_COMPLIANT"
                        evidence = f"UserData contains potential secret(s): {', '.join(matches)}"
                        non_compliant += 1
                    else:
                        status = "COMPLIANT"
                        evidence = "UserData scanned, no secret patterns found"
                        compliant += 1

                except Exception:
                    total_checked -= 1
                    skipped += 1
                    status, evidence = "SKIPPED", "UserData could not be base64-decoded"

            add_row(results, account_id, region, name, arn, status, evidence)

    return results, total_checked, compliant, non_compliant, skipped


# ==================================================
# CSV
# ==================================================

def write_csv(control_name, account_id, results):
    filename = f"{control_name}_{account_id}.csv"
    fieldnames = ["Account", "Region", "ResourceId", "ResourceArn", "Status", "Evidence"]
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    return filename


def print_summary(control_name, account_id, total_checked, compliant, non_compliant, skipped, csv_file):
    overall = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"
    print("\n" + "=" * 60)
    print(f"CONTROL: {control_name}")
    print(f"ACCOUNT: {account_id}")
    print("=" * 60)
    print(f"Total Checked  : {total_checked}")
    print(f"Compliant      : {compliant}")
    print(f"Non-Compliant  : {non_compliant}")
    print(f"Skipped        : {skipped}")
    print(f"Overall Status : {overall}")
    print(f"CSV Report     : {csv_file}")
    print("=" * 60 + "\n")


# ==================================================
# MAIN
# ==================================================

def main():
    parser = argparse.ArgumentParser(description=f"Check: {CONTROL_NAME}")
    parser.add_argument("-R", "--role-arn", help="IAM Role ARN to assume", default=None)
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    results, total_checked, compliant, non_compliant, skipped = check_control(session, account_id)

    csv_file = write_csv(CONTROL_NAME, account_id, results)
    print_summary(CONTROL_NAME, account_id, total_checked, compliant, non_compliant, skipped, csv_file)


if __name__ == "__main__":
    main()
