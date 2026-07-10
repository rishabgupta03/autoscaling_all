#!/usr/bin/env python3
"""
Control: Auto Scaling group's associated launch configuration does not
assign a public IP address.

Scope note: this control targets ASGs using a classic Launch Configuration.
ASGs using a Launch Template or a Mixed Instances Policy are out of scope
and are marked SKIPPED (not applicable).

Edge case handled: AssociatePublicIpAddress on a launch configuration is
only present in the API response if it was explicitly set. If it is absent,
AWS falls back to the subnet's MapPublicIpOnLaunch setting, so that is
checked via the ASG's VPCZoneIdentifier subnets before concluding.
"""

import argparse
import csv
import sys
from datetime import datetime

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from tqdm import tqdm

CONTROL_NAME = "ASG Launch Configuration Does Not Assign Public IP Address"
LC_BATCH_SIZE = 50  # describe_launch_configurations max names per call

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


def chunk(items, size):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def get_launch_config_map(client, names):
    """Batch-fetch launch configurations, return {name: AssociatePublicIpAddress|None}."""
    config_map = {}
    for batch in chunk(list(names), LC_BATCH_SIZE):
        resp = client.describe_launch_configurations(LaunchConfigurationNames=batch)
        for lc in resp.get("LaunchConfigurations", []):
            config_map[lc["LaunchConfigurationName"]] = lc.get("AssociatePublicIpAddress")
    return config_map


def subnet_auto_assigns_public_ip(ec2_client, vpc_zone_identifier):
    """Return True/False if determinable from subnet MapPublicIpOnLaunch, else None."""
    if not vpc_zone_identifier:
        return None
    subnet_ids = [s.strip() for s in vpc_zone_identifier.split(",") if s.strip()]
    if not subnet_ids:
        return None
    try:
        resp = ec2_client.describe_subnets(SubnetIds=subnet_ids)
        return any(s.get("MapPublicIpOnLaunch") for s in resp.get("Subnets", []))
    except ClientError:
        return None


def evaluate_asg(asg, lc_map, ec2_client):
    """Return (status, evidence) for one Auto Scaling Group."""
    lc_name = asg.get("LaunchConfigurationName")

    if not lc_name:
        return "SKIPPED", "ASG uses a Launch Template or Mixed Instances Policy, not a Launch Configuration - control not applicable"

    associate_public_ip = lc_map.get(lc_name, "__NOT_FOUND__")
    if associate_public_ip == "__NOT_FOUND__":
        return "SKIPPED", f"Launch configuration '{lc_name}' not found (may have been deleted)"

    if associate_public_ip is True:
        return "NON_COMPLIANT", f"Launch configuration '{lc_name}' explicitly sets AssociatePublicIpAddress=True"

    if associate_public_ip is False:
        return "COMPLIANT", f"Launch configuration '{lc_name}' explicitly sets AssociatePublicIpAddress=False"

    # Not explicitly set -> falls back to subnet's MapPublicIpOnLaunch
    subnet_result = subnet_auto_assigns_public_ip(ec2_client, asg.get("VPCZoneIdentifier"))
    if subnet_result is True:
        return "NON_COMPLIANT", f"Launch configuration '{lc_name}' does not set AssociatePublicIpAddress; subnet(s) have MapPublicIpOnLaunch=True"
    if subnet_result is False:
        return "COMPLIANT", f"Launch configuration '{lc_name}' does not set AssociatePublicIpAddress; subnet(s) have MapPublicIpOnLaunch=False"

    return "SKIPPED", f"Launch configuration '{lc_name}' does not set AssociatePublicIpAddress and subnet configuration could not be determined"


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
            asg_client = session.client("autoscaling", region_name=region)
            ec2_client = session.client("ec2", region_name=region)
            paginator = asg_client.get_paginator("describe_auto_scaling_groups")
            asgs = []
            for page in paginator.paginate():
                asgs.extend(page.get("AutoScalingGroups", []))
        except ClientError as e:
            code, reason = classify_error(e)
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

        lc_names = {a["LaunchConfigurationName"] for a in asgs if a.get("LaunchConfigurationName")}
        try:
            lc_map = get_launch_config_map(asg_client, lc_names) if lc_names else {}
        except ClientError as e:
            code, reason = classify_error(e)
            lc_map = {}
            tqdm.write(f"  [{region}] Could not fetch launch configurations: {reason}")

        for asg in tqdm(asgs, desc=f"  {region}", leave=False):
            total_checked += 1
            asg_name = asg.get("AutoScalingGroupName", "N/A")
            asg_arn = asg.get("AutoScalingGroupARN", "N/A")

            try:
                status, evidence = evaluate_asg(asg, lc_map, ec2_client)
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
    filename = f"asg_launch_config_public_ip_{account_id}_{timestamp}.csv"
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