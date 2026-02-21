# ducklake-guard

> **Work in progress** — this is an evolving learning project, not a finished solution.

Explores access control for [DuckLake](https://ducklake.select) lakehouses — restricting a reader to specific tables across the Postgres catalog and S3 data layer. Built on Hetzner Cloud (Object Storage + managed Postgres), so the S3 policies use Hetzner-specific principal ARNs and Deny-only rules.

## Setup

```bash
cp .env.sample .env
# Fill in credentials — see comments in .env.sample
```

## 1. Load sample data

Generates TPC-H tables (scale factor 0.01) and loads them into the lakehouse.

```bash
set -a && source .env && set +a
uv run python scripts/load_sample_data.py
```

## 2. Apply granular read-only policies

### PostgreSQL catalog

Create a read-only Postgres user that can query the DuckLake metadata catalog but not modify it. See [research/postgres-access-control.md](research/postgres-access-control.md) for the full walkthrough, or apply the SQL directly:

```bash
ssh ducklake-guard
su - postgres
psql -d ducklake_catalog -f sql/create_reader.sql
```

### Catalog visibility (RLS)

Hide tables the reader shouldn't know about:

```bash
psql -d ducklake_catalog -f sql/enable_rls.sql
```

### S3 data layer

> **Warning:** Hetzner Object Storage has no IAM. The reader key can call
> `PutBucketPolicy` to remove its own restrictions and escalate to full write
> access. Bucket policies only restrict object-level operations — policy
> management bypasses them entirely. See [research/s3-blast-radius.md](research/s3-blast-radius.md).

Restrict an S3 reader key to `GetObject` on a single table prefix. See [research/s3-access-control.md](research/s3-access-control.md) for how the bucket policy works.

```bash
set -a && source .env && set +a
READER_TABLE=customer uv run python scripts/apply_s3_reader_policy.py
```

## 3. Verify

Connect as the reader and confirm the restrictions:

```bash
set -a && source .env && set +a && duckdb -init init-reader.sql
```

```sql
-- Should succeed
SELECT * FROM customer LIMIT 10;

-- Should fail (HTTP 403 — outside allowed prefix)
SELECT * FROM orders LIMIT 10;

-- Should fail (PutObject denied)
INSERT INTO customer (c_custkey) VALUES (999999);
```
