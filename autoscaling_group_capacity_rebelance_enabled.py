#!/usr/bin/env python3
"""
Control : Amazon EC2 Auto Scaling has capacity rebalancing enabled

Logic   :
  For every Auto Scaling group in every enabled region,
  CapacityRebalance must be True.

  CapacityRebalance = True  → COMPLIANT
  CapacityRebalance = False → NON_COMPLIANT
  API error / access denied → SKIPPED

  What Capacity Rebalancing does:
    When AWS detects that a Spot Instance is at elevated risk of
    interruption, Auto Scaling proactively launches a replacement
    Spot Instance BEFORE the current one is interrupted, then
    terminates the old one. This keeps your desired capacity
    stable and avoids sudden capacity drops.

  Note: Capacity Rebalancing is most relevant for ASGs using Spot
  Instances (mixed instances policy). The control checks ALL ASGs
  regardless of instance purchase type and the evidence reflects
  whether the ASG uses Spot instances or not.
"""

import argparse
import csv
import sys

import boto3
from botocore.exceptions import ClientError
from tqdm import tqdm

CONTROL_NAME = "Amazon EC2 Auto Scaling has capacity rebalancing enabled"


# ==================================================
# AUTH
# ==================================================
def get_session(role_arn=None):
    if role_arn:
        base  = boto3.Session()
        creds = base.client("sts").assume_role(
            RoleArn=role_arn, RoleSessionName="control-audit"
        )["Credentials"]
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
    return [
        r["RegionName"]
        for r in ec2.describe_regions(AllRegions=True)["Regions"]
        if r.get("OptInStatus") in ("opt-in-not-required", "opted-in")
    ]


# ==================================================
# HELPERS
# ==================================================
def list_all_asgs(client):
    """Paginate describe_auto_scaling_groups and return all ASG dicts."""
    asgs      = []
    paginator = client.get_paginator("describe_auto_scaling_groups")
    for page in paginator.paginate():
        asgs.extend(page.get("AutoScalingGroups", []))
    return asgs


def uses_spot_instances(asg):
    """
    Returns True if the ASG is configured to use Spot Instances
    via a MixedInstancesPolicy. Useful for context in evidence.
    """
    mixed_policy = asg.get("MixedInstancesPolicy")
    if not mixed_policy:
        return False
    instances_distribution = mixed_policy.get("InstancesDistribution", {})
    spot_percentage = instances_distribution.get("SpotInstancePools", 0)
    spot_alloc = instances_distribution.get(
        "SpotAllocationStrategy", "")
    # If any spot config present, it uses spot
    return bool(spot_percentage or spot_alloc)


# ==================================================
# CONTROL LOGIC
# ==================================================
def check_control(session):
    account_id    = get_account_id(session)
    regions       = get_regions(session)
    results       = []
    total_checked = compliant = non_compliant = skipped = 0

    print(f"\nRegions to scan: {len(regions)}\n")

    for region in tqdm(regions, desc="Scanning regions"):
        try:
            client = session.client("autoscaling", region_name=region)
            asgs   = list_all_asgs(client)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            skipped += 1
            results.append(_row(
                account_id, region, "N/A", "N/A",
                "N/A", "N/A", "SKIPPED",
                f"Region access failed: {code}",
            ))
            continue

        if not asgs:
            continue

        for asg in tqdm(asgs, desc=f"  {region}", leave=False):
            asg_name = asg.get("AutoScalingGroupName", "N/A")
            asg_arn  = asg.get("AutoScalingGroupARN", "N/A")
            min_size = asg.get("MinSize", "N/A")
            max_size = asg.get("MaxSize", "N/A")
            desired  = asg.get("DesiredCapacity", "N/A")

            capacity_rebalance = asg.get("CapacityRebalance", False)
            spot_context       = uses_spot_instances(asg)
            spot_note = (
                "ASG uses Spot Instances — Capacity Rebalancing is "
                "directly applicable."
            ) if spot_context else (
                "ASG appears to use On-Demand Instances only — "
                "Capacity Rebalancing is still required by this control."
            )

            total_checked += 1

            if capacity_rebalance:
                compliant += 1
                status   = "COMPLIANT"
                evidence = (
                    f"CapacityRebalance=True for ASG '{asg_name}' "
                    f"(min: {min_size}, max: {max_size}, "
                    f"desired: {desired}). "
                    f"{spot_note}"
                )
            else:
                non_compliant += 1
                status   = "NON_COMPLIANT"
                evidence = (
                    f"CapacityRebalance=False for ASG '{asg_name}' "
                    f"(min: {min_size}, max: {max_size}, "
                    f"desired: {desired}). "
                    "Enable Capacity Rebalancing so Auto Scaling can "
                    "proactively replace Spot Instances at risk of "
                    f"interruption before they are reclaimed. {spot_note}"
                )

            results.append(_row(
                account_id, region, asg_name, asg_arn,
                str(capacity_rebalance), f"min:{min_size}/max:{max_size}/"
                f"desired:{desired}",
                status, evidence,
            ))

    return results, total_checked, compliant, non_compliant, skipped


def _row(account, region, asg_name, asg_arn,
         capacity_rebalance, capacity, status, evidence):
    return {
        "Account":            account,
        "Region":             region,
        "ASGName":            asg_name,
        "ResourceArn":        asg_arn,
        "CapacityRebalance":  capacity_rebalance,
        "Capacity":           capacity,
        "Status":             status,
        "Evidence":           evidence,
    }


# ==================================================
# CSV
# ==================================================
def write_csv(results, account_id):
    filename   = f"autoscaling_capacity_rebalance_{account_id}.csv"
    fieldnames = [
        "Account", "Region", "ASGName", "ResourceArn",
        "CapacityRebalance", "Capacity", "Status", "Evidence",
    ]
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    return filename


# ==================================================
# MAIN
# ==================================================
def main():
    parser = argparse.ArgumentParser(
        description="Check: EC2 Auto Scaling group has capacity rebalancing enabled"
    )
    parser.add_argument("-R", "--role-arn", help="IAM Role ARN to assume")
    args = parser.parse_args()

    session    = get_session(args.role_arn)
    account_id = get_account_id(session)

    print("=" * 60)
    print(f"  CONTROL : {CONTROL_NAME}")
    print(f"  ACCOUNT : {account_id}")
    print("=" * 60)

    results, total_checked, compliant, non_compliant, skipped = check_control(session)

    overall  = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"
    filename = write_csv(results, account_id)

    print("\n" + "=" * 60)
    print(f"  CONTROL        : {CONTROL_NAME}")
    print(f"  ACCOUNT        : {account_id}")
    print(f"  TOTAL CHECKED  : {total_checked}")
    print(f"  COMPLIANT      : {compliant}")
    print(f"  NON-COMPLIANT  : {non_compliant}")
    print(f"  SKIPPED        : {skipped}")
    print(f"  OVERALL STATUS : {overall}")
    print(f"  CSV GENERATED  : {filename}")
    print("=" * 60)

    sys.exit(0 if overall == "COMPLIANT" else 1)


if __name__ == "__main__":
    main()