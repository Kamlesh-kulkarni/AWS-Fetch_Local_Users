import boto3
import csv
import time
import os
from datetime import datetime, timezone

CSV_FILE = "IAM/credential_reports_merged.csv"
ACCOUNT_LIST_FILE = "account_list.csv"
ROLE_NAME = "SecurityAutomation"
CREDENTIALS_FILE = "aws_credentials.txt"  # credential file with access key and secret key

def load_credentials(file_path):
    creds = {}
    with open(file_path, 'r') as f:
        for line in f:
            if '=' in line:
                key, value = line.strip().split('=', 1)
                creds[key.strip()] = value.strip()
    return creds.get("aws_access_key_id"), creds.get("aws_secret_access_key")

def get_account_list(file_path):
    with open(file_path, newline="") as f:
        reader = csv.DictReader(f)
        return [row["account_id"] for row in reader if row.get("account_id")]

def assume_role(account_id):
    access_key, secret_key = load_credentials(CREDENTIALS_FILE)
    base_session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key
    )
    sts = base_session.client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/{ROLE_NAME}"
    response = sts.assume_role(RoleArn=role_arn, RoleSessionName="KeyRotationSession")
    creds = response["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]
    )

def fetch_credential_report(iam):
    try:
        iam.generate_credential_report()
    except Exception:
        return None
    for _ in range(10):
        try:
            response = iam.get_credential_report()
            return response["Content"].decode("utf-8")
        except iam.exceptions.CredentialReportNotReadyException:
            time.sleep(2)
    return None

def parse_key_age(ts):
    if ts in ("N/A", "", None):
        return ""
    try:
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return str((datetime.now(timezone.utc) - dt).days)
    except Exception:
        return ""

def get_access_key_ids(iam, username):
    try:
        keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
        return {k["CreateDate"].strftime("%Y-%m-%dT%H:%M:%SZ"): k["AccessKeyId"] for k in keys}
    except Exception:
        return {}

def main():
    accounts = get_account_list(ACCOUNT_LIST_FILE)
    merged_rows = []
    header_written = False

    for account_id in accounts:
        try:
            session = assume_role(account_id)
            iam = session.client("iam")
        except Exception:
            print(f"[ERROR] Failed to assume role for account: {account_id}")
            continue

        report_csv = fetch_credential_report(iam)
        if not report_csv:
            print(f"[WARNING] Could not fetch credential report for account: {account_id}")
            continue

        lines = report_csv.strip().split("\n")
        header, *data_lines = lines
        header_fields = header.split(",")
        header_extended = header_fields + [
            "access_key_1_id", "access_key_2_id",
            "access_key_1_age", "access_key_2_age", "account_id"
        ]

        if not header_written:
            merged_rows.append(",".join(header_extended))
            header_written = True

        for line in data_lines:
            row_values = line.split(",")
            row_dict = dict(zip(header_fields, row_values))
            username = row_dict["user"]

            if username.startswith("<root_account>"):
                extended_row = row_values + ["", "", "", "", account_id]
                merged_rows.append(",".join(extended_row))
                continue

            key_ids = get_access_key_ids(iam, username)
            k1_rot = row_dict["access_key_1_last_rotated"]
            k2_rot = row_dict["access_key_2_last_rotated"]
            key1_age = parse_key_age(k1_rot)
            key2_age = parse_key_age(k2_rot)
            key1_id = key_ids.get(k1_rot, "")
            key2_id = key_ids.get(k2_rot, "")

            extended_row = row_values + [key1_id, key2_id, key1_age, key2_age, account_id]
            merged_rows.append(",".join(extended_row))

    if merged_rows:
        os.makedirs(os.path.dirname(CSV_FILE), exist_ok=True)
        with open(CSV_FILE, "w", newline="") as f:
            for row in merged_rows:
                f.write(row + "\n")

        print(f"[SUCCESS] Report saved to: {CSV_FILE}")
    else:
        print("[INFO] No data to write.")

if __name__ == "__main__":
    main()
