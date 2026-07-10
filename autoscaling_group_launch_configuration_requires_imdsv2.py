#!/usr/bin/env python3
"""
Control: Auto Scaling group enforces IMDSv2 or disables the instance
metadata service.

An ASG's instances inherit their metadata options from whichever launch
resource the ASG uses - a Launch Configuration, or a Launch Template
(referenced directly or via a Mixed Instances Policy). Both sources are
evaluated. The ASG is COMPLIANT if the resolved MetadataOptions either
disable the metadata service (HttpEndpoint=disabled) or require IMDSv2
tokens (HttpTokens=required).
"""

import argparse
import csv
import sys
from datetime import datetime

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from tqdm import tqdm

CONTROL_NAME = "ASG Enforces IMDSv2 Or Disables Instance Metadata Service"
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
        "InvalidLaunchTemplateId.NotFound": "Referenced launch template no longer exists",
        "InvalidLaunchTemplateName.NotFoundException": "Referenced launch template no longer exists",
    }
    return code, reasons.get(code, f"AWS error ({code})")


def chunk(items, size):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def get_launch_config_map(client, names):
    """Batch-fetch launch configurations, return {name: MetadataOptions|None}."""
    config_map = {}
    for batch in chunk(list(names), LC_BATCH_SIZE):
        resp = client.describe_launch_configurations(LaunchConfigurationNames=batch)
        for lc in resp.get("LaunchConfigurations", []):
            config_map[lc["LaunchConfigurationName"]] = lc.get("MetadataOptions")
    return config_map


def get_launch_template_spec(asg):
    """Return (lt_id, lt_name, version) from either a direct LaunchTemplate
    reference or a MixedInstancesPolicy, or (None, None, None) if neither."""
    lt = asg.get("LaunchTemplate")
    if lt:
        return lt.get("LaunchTemplateId"), lt.get("LaunchTemplateName"), lt.get("Version", "$Default")
    lt2 = asg.get("MixedInstancesPolicy", {}).get("LaunchTemplate", {}).get("LaunchTemplateSpecification")
    if lt2:
        return lt2.get("LaunchTemplateId"), lt2.get("LaunchTemplateName"), lt2.get("Version", "$Default")
    return None, None, None


def get_lt_metadata_options(ec2_client, lt_id, lt_name, version, cache):
    """Resolve MetadataOptions for a specific launch template version, using a
    per-region cache so shared templates aren't fetched repeatedly."""
    key = (lt_id or lt_name, version)
    if key in cache:
        return cache[key]
    kwargs = {"Versions": [version]}
    if lt_id:
        kwargs["LaunchTemplateId"] = lt_id
    else:
        kwargs["LaunchTemplateName"] = lt_name
    resp = ec2_client.describe_launch_template_versions(**kwargs)
    versions = resp.get("LaunchTemplateVersions", [])
    result = versions[0]["LaunchTemplateData"].get("MetadataOptions") if versions else None
    cache[key] = result
    return result


def evaluate_asg(asg, lc_map, ec2_client, lt_cache):
    """Return (status, evidence) for one Auto Scaling Group."""
    lc_name = asg.get("LaunchConfigurationName")

    if lc_name:
        metadata_options = lc_map.get(lc_name, "__NOT_FOUND__")
        if metadata_options == "__NOT_FOUND__":
            return "SKIPPED", f"Launch configuration '{lc_name}' not found (may have been deleted)"
        source = f"launch configuration '{lc_name}'"
    else:
        lt_id, lt_name, version = get_launch_template_spec(asg)
        if not lt_id and not lt_name:
            return "SKIPPED", "ASG has no Launch Configuration or Launch Template associated - cannot evaluate"
        try:
            metadata_options = get_lt_metadata_options(ec2_client, lt_id, lt_name, version, lt_cache)
        except ClientError as e:
            _, reason = classify_error(e)
            return "SKIPPED", f"Could not fetch launch template metadata options: {reason}"
        source = f"launch template '{lt_name or lt_id}' version {version}"

    if not metadata_options:
        return "NON_COMPLIANT", f"No MetadataOptions configured on {source} - defaults to HttpTokens=optional (IMDSv1 allowed)"

    http_tokens = metadata_options.get("HttpTokens", "optional")
    http_endpoint = metadata_options.get("HttpEndpoint", "enabled")

    if http_endpoint == "disabled":
        return "COMPLIANT", f"Instance metadata service disabled on {source} (HttpEndpoint=disabled)"
    if http_tokens == "required":
        return "COMPLIANT", f"IMDSv2 enforced on {source} (HttpTokens=required)"
    return "NON_COMPLIANT", f"IMDSv2 not enforced on {source} (HttpTokens={http_tokens}, HttpEndpoint={http_endpoint})"


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

        lc_names = {a["LaunchConfigurationName"] for a in asgs if a.get("LaunchConfigurationName")}
        try:
            lc_map = get_launch_config_map(asg_client, lc_names) if lc_names else {}
        except ClientError as e:
            _, reason = classify_error(e)
            lc_map = {}
            tqdm.write(f"  [{region}] Could not fetch launch configurations: {reason}")

        lt_cache = {}
        for asg in tqdm(asgs, desc=f"  {region}", leave=False):
            total_checked += 1
            asg_name = asg.get("AutoScalingGroupName", "N/A")
            asg_arn = asg.get("AutoScalingGroupARN", "N/A")

            try:
                status, evidence = evaluate_asg(asg, lc_map, ec2_client, lt_cache)
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
    filename = f"asg_imdsv2_enforcement_{account_id}_{timestamp}.csv"
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