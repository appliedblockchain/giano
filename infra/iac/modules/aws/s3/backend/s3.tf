resource "aws_s3_bucket" "this" {
  bucket = var.bucket_name

  tags = merge(local.tags, { Name = var.bucket_name })
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id

  versioning_configuration {
    status = "Enabled"
  }
}

# aws_s3_bucket_server_side_encryption_configuration has no `tags` argument — it configures a
# child resource of the tagged bucket above.
resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

# aws_s3_bucket_public_access_block has no `tags` argument — it configures a child resource of
# the tagged bucket above.
resource "aws_s3_bucket_public_access_block" "this" {
  bucket = aws_s3_bucket.this.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
