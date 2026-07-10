#!/usr/bin/env python3
"""
Control: Amazon EC2 Auto Scaling group uses an EC2 Launch Template rather
than the legacy Launch Configuration mechanism. Launch Templates support
versioning, Mixed Instances Policies, and newer EC2 features (e.g. IMDSv2
options, multiple ENIs) that Launch Configurations do not.
"""

import argparse
import csv
import sys
from datetime import datetime

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from tqdm import tqdm

CONTROL_NAME = "ASG Uses An EC2 Launch Template"

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
        if r.get("OptInStatus") in ["opt-in-not-required", "opted-in"]
    ]


# ==================================================
# HELPERS
# ==================================================
def classify_error(e):
    """Map a ClientError to a short, human-readable reason."""
    code = e.response.get("Error", {}).get("Code", "Unknown")
    reasons = {
        "AccessDeniedException": "Access denied - insufficient IAM permissions",
        "AccessDenied": "Access denied - insufficient IAM permissions",
        "UnauthorizedOperation": "Access denied - insufficient IAM permissions",
        "ThrottlingException": "Throttled by AWS API - request rate exceeded",
        "InvalidClientTokenId": "Invalid/expired credentials for this region",
        "OptInRequired": "Region not opted-in for this account",
    }
    return code, reasons.get(code, f"AWS error ({code})")


def evaluate_asg(asg):
    """Return (status, evidence) for one Auto Scaling Group."""
    lt = asg.get("LaunchTemplate")
    if lt:
        identifier = lt.get("LaunchTemplateName") or lt.get("LaunchTemplateId")
        version = lt.get("Version", "$Default")
        return "COMPLIANT", f"Uses Launch Template '{identifier}' (version {version})"

    mip_lt = asg.get("MixedInstancesPolicy", {}).get("LaunchTemplate", {}).get("LaunchTemplateSpecification")
    if mip_lt:
        identifier = mip_lt.get("LaunchTemplateName") or mip_lt.get("LaunchTemplateId")
        version = mip_lt.get("Version", "$Default")
        return "COMPLIANT", f"Uses Launch Template '{identifier}' (version {version}) via MixedInstancesPolicy"

    lc_name = asg.get("LaunchConfigurationName")
    if lc_name:
        return "NON_COMPLIANT", f"Uses legacy Launch Configuration '{lc_name}' instead of a Launch Template"

    return "SKIPPED", "ASG has neither a Launch Template nor a Launch Configuration - cannot evaluate"


# ==================================================
# CONTROL LOGIC
# ==================================================
def check_control(session, account_id, regions):
    results = []
    total_checked = 0
    compliant = 0
    non_compliant = 0
    skipped = 0

    print(f"\nRegions to Scan: {len(regions)}\n")

    for region in tqdm(regions, desc="Scanning Regions"):
        try:
            client = session.client("autoscaling", region_name=region)
            paginator = client.get_paginator("describe_auto_scaling_groups")
            asgs = []
            for page in paginator.paginate():
                asgs.extend(page.get("AutoScalingGroups", []))
        except ClientError as e:
            _, reason = classify_error(e)
            skipped += 1
            results.append({
                "Region": region,
                "AsgName": "N/A",
                "AsgArn": "N/A",
                "Status": "SKIPPED",
                "Evidence": reason,
            })
            continue
        except NoCredentialsError:
            skipped += 1
            results.append({
                "Region": region,
                "AsgName": "N/A",
                "AsgArn": "N/A",
                "Status": "SKIPPED",
                "Evidence": "No valid credentials available",
            })
            continue

        for asg in tqdm(asgs, desc=f"  {region}", leave=False):
            total_checked += 1
            asg_name = asg.get("AutoScalingGroupName", "N/A")
            asg_arn = asg.get("AutoScalingGroupARN", "N/A")

            try:
                status, evidence = evaluate_asg(asg)
                if status == "COMPLIANT":
                    compliant += 1
                elif status == "NON_COMPLIANT":
                    non_compliant += 1
                else:
                    skipped += 1
            except Exception as e:
                status = "SKIPPED"
                evidence = f"Could not evaluate ASG: {e}"
                skipped += 1

            results.append({
                "Region": region,
                "AsgName": asg_name,
                "AsgArn": asg_arn,
                "Status": status,
                "Evidence": evidence,
            })

    return results, total_checked, compliant, non_compliant, skipped


# ==================================================
# CSV
# ==================================================
def write_csv(results, account_id):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"asg_uses_launch_template_{account_id}_{timestamp}.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["Account", "Region", "AsgName", "AsgArn", "Status", "Evidence"]
        )
        writer.writeheader()
        for row in results:
            writer.writerow({"Account": account_id, **row})
    return filename


# ==================================================
# MAIN
# ==================================================
def main():
    parser = argparse.ArgumentParser(description=CONTROL_NAME)
    parser.add_argument("-R", "--role-arn", help="IAM role ARN to assume", default=None)
    args = parser.parse_args()

    try:
        session = get_session(args.role_arn)
        account_id = get_account_id(session)
        regions = get_regions(session)
    except (ClientError, NoCredentialsError) as e:
        print(f"FATAL: Could not establish session/credentials - {e}")
        sys.exit(1)

    print("=" * 60)
    print(f"CONTROL: {CONTROL_NAME}")
    print(f"ACCOUNT: {account_id}")
    print("=" * 60)

    results, total_checked, compliant, non_compliant, skipped = check_control(
        session, account_id, regions
    )

    overall = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"
    csv_file = write_csv(results, account_id)

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Control       : {CONTROL_NAME}")
    print(f"Account       : {account_id}")
    print(f"Total Checked : {total_checked}")
    print(f"Compliant     : {compliant}")
    print(f"Non-Compliant : {non_compliant}")
    print(f"Skipped       : {skipped}")
    print(f"Overall       : {overall}")
    print(f"CSV Report    : {csv_file}")
    print("=" * 60)


if __name__ == "__main__":
    main()