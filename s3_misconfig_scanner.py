import boto3
import json
import csv
import os
from botocore.exceptions import ClientError

def is_bucket_policy_public(policy_json):
    try:
        statements = policy_json.get("Statement", [])
        for statement in statements:
            principal = statement.get("Principal")
            effect = statement.get("Effect")
            condition = statement.get("Condition", {})

            if effect == "Allow" and (principal == "*" or principal == {"AWS": "*"}):
                if not condition:
                    return True
        return False
    except Exception as e:
        print(f"Error parsing policy: {e}")
        return False

def is_acl_public(acl):
    for grant in acl.get("Grants", []):
        grantee = grant.get("Grantee", {})
        permission = grant.get("Permission")
        if grantee.get("URI") in [
            "http://acs.amazonaws.com/groups/global/AllUsers",
            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
        ]:
            return True
    return False

def scan_buckets():
    s3 = boto3.client('s3')
    report = []
    try:
        buckets = s3.list_buckets()['Buckets']
        for bucket in buckets:
            bucket_name = bucket['Name']
            print(f"Scanning bucket: {bucket_name}")
            bucket_info = {
                "Bucket": bucket_name,
                "PublicPolicy": False,
                "PublicACL": False,
                "ObjectsPublic": False,
                "FixSuggestion": []
            }

            try:
                policy_str = s3.get_bucket_policy(Bucket=bucket_name)['Policy']
                policy_json = json.loads(policy_str)
                if is_bucket_policy_public(policy_json):
                    bucket_info["PublicPolicy"] = True
                    bucket_info["FixSuggestion"].append("Restrict bucket policy to specific IAM principals.")
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    print(f"Error getting policy for {bucket_name}: {e}")

            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)
                if is_acl_public(acl):
                    bucket_info["PublicACL"] = True
                    bucket_info["FixSuggestion"].append("Remove public grants from bucket ACL.")
            except ClientError as e:
                print(f"Error getting ACL for {bucket_name}: {e}")

            try:
                paginator = s3.get_paginator('list_objects_v2')
                for page in paginator.paginate(Bucket=bucket_name):
                    for obj in page.get('Contents', []):
                        object_acl = s3.get_object_acl(Bucket=bucket_name, Key=obj['Key'])
                        if is_acl_public(object_acl):
                            bucket_info["ObjectsPublic"] = True
                            bucket_info["FixSuggestion"].append(f"Restrict object {obj['Key']} ACL.")
                            break
            except ClientError as e:
                print(f"Error listing objects in {bucket_name}: {e}")

            report.append(bucket_info)
    except ClientError as e:
        print(f"Error listing buckets: {e}")
    return report

def save_report(report):
    os.makedirs("output", exist_ok=True)
    with open("output/s3_report.json", "w") as jf:
        json.dump(report, jf, indent=4)
    with open("output/s3_report.csv", "w", newline='') as cf:
        writer = csv.DictWriter(cf, fieldnames=["Bucket", "PublicPolicy", "PublicACL", "ObjectsPublic", "FixSuggestion"])
        writer.writeheader()
        for row in report:
            writer.writerow({
                "Bucket": row["Bucket"],
                "PublicPolicy": row["PublicPolicy"],
                "PublicACL": row["PublicACL"],
                "ObjectsPublic": row["ObjectsPublic"],
                "FixSuggestion": "; ".join(set(row["FixSuggestion"]))
            })
    print("Report saved in 'output/' directory.")

if __name__ == "__main__":
    findings = scan_buckets()
    save_report(findings)
