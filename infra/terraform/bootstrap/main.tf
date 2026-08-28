# Terraform state bucket — the chicken-and-egg module.
#
# Applied ONCE, with a local backend, before anything in envs/. Kept in its own directory so
# nobody runs it by accident and so its state can be committed nowhere: the bucket it creates
# is the only thing it manages, and re-creating that from scratch is a two-minute job.
#
#   cd infra/terraform/bootstrap
#   terraform init && terraform apply
#
# The bucket name it prints goes into envs/dev/backend.tf.

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project    = "giano"
      ManagedBy  = "terraform"
      Component  = "tfstate"
      Repository = "appliedblockchain/giano"
    }
  }
}

variable "region" {
  type        = string
  default     = "eu-west-2"
  description = "Region for the state bucket. Must match the `region` in envs/*/backend.tf."
}

data "aws_caller_identity" "current" {}

locals {
  bucket_name = "giano-tfstate-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket" "state" {
  bucket = local.bucket_name

  # The one bucket in this repository that must survive a careless `terraform destroy`.
  lifecycle {
    prevent_destroy = true
  }
}

# Versioning is not optional: with `use_lockfile = true` there is no DynamoDB table holding a
# second copy of anything, so object versions are the only way back from a corrupted state.
resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# State holds the generated RDS password and metrics token (spec §9.1), so refuse plaintext
# transport outright rather than trusting every future client to ask for TLS.
resource "aws_s3_bucket_policy" "tls_only" {
  bucket = aws_s3_bucket.state.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.state.arn,
        "${aws_s3_bucket.state.arn}/*",
      ]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

# Old state versions are worth keeping for a while and worthless after that.
resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    id     = "expire-noncurrent-versions"
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

output "bucket" {
  value       = aws_s3_bucket.state.id
  description = "Put this in envs/*/backend.tf as `bucket`."
}
