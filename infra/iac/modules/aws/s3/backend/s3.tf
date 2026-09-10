# The state bucket. §4.5, applied ONCE in the `default` workspace against a
# local backend, after which the state is migrated into it (§18 step 2).
#
# The chicken-and-egg is unavoidable: a bucket cannot live in the state it
# stores. Locking is S3-native (use_lockfile = true) so there is no DynamoDB
# table to create here.
#
# Terraform has no native state encryption, so protection is KMS + IAM + not
# putting secrets in state — and the third is the one that actually holds
# (§12.5).

resource "aws_s3_bucket" "tfstate" {
  bucket = var.bucket_name

  tags = merge(local.tags, { Name = var.bucket_name })
}

# Versioning is what makes a bad apply recoverable: the previous state is a
# prior object version.
resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }

    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Old state versions are not worth keeping forever, but they are worth keeping
# long enough to recover from a bad apply someone noticed a week later.
resource "aws_s3_bucket_lifecycle_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    id     = "expire-noncurrent-state"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}
