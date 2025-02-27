resource "aws_s3_bucket" "ca_bucket" {
  bucket = "${var.prefix}-ca-certificates"
}

resource "aws_s3_bucket_ownership_controls" "ca_bucket" {
  bucket = aws_s3_bucket.ca_bucket.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "ca_bucket" {
  bucket = aws_s3_bucket.ca_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "ciphernest_bucket" {
  bucket = aws_s3_bucket.ca_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}
