resource "aws_s3_bucket" "ciphernest_bucket" {
  bucket        = "${var.prefix}-encrypted-bucket"
  force_destroy = true
}

resource "aws_s3_bucket_ownership_controls" "ciphernest_bucket" {
  bucket = aws_s3_bucket.ciphernest_bucket.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "ciphernest_bucket" {
  bucket = aws_s3_bucket.ciphernest_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "ciphernest_bucket" {
  bucket = aws_s3_bucket.ciphernest_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_policy" "ciphernest_bucket" {
  bucket = aws_s3_bucket.ciphernest_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonSecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.ciphernest_bucket.arn,
          "${aws_s3_bucket.ciphernest_bucket.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "AllowRootAccountAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.ciphernest_bucket.arn,
          "${aws_s3_bucket.ciphernest_bucket.arn}/*"
        ]
      },
      {
        Sid    = "AllowLambdaAccess"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda_role.arn
        }
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.ciphernest_bucket.arn}/*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
          StringLike = {
            "aws:SourceArn" = "arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:${var.prefix}-*"
          }
        }
      }
    ]
  })
}
