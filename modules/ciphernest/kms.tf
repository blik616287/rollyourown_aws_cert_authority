resource "aws_kms_key" "lambda_kms_key" {
  description             = "KMS key for ciphernest"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAccountManagement"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = [
          "kms:*"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowTerraformAccess"
        Effect = "Allow"
        Principal = {
          AWS = data.aws_caller_identity.current.arn
        }
        Action = [
          "kms:Create*",
          "kms:Delete*",
          "kms:Describe*",
          "kms:Enable*",
          "kms:List*",
          "kms:Put*",
          "kms:Update*",
          "kms:Revoke*",
          "kms:Disable*",
          "kms:Get*",
          "kms:Schedule*",
          "kms:Cancel*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:PrincipalType" : "User",
            "aws:AccountId" : data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AllowLambdaEnvelopeEncryption"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda_role.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:GenerateDataKeyWithoutPlaintext",
          "kms:Encrypt"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:PrincipalType" : "Service",
            "aws:Service" : "lambda.amazonaws.com",
            "aws:SourceAccount" : data.aws_caller_identity.current.account_id
          },
          ArnLike = {
            "aws:SourceArn" : "arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:${var.prefix}-sdk-lambda"
          }
        }
      }
    ]
  })
}

resource "aws_kms_alias" "lambda_kms_key_alias" {
  name          = "alias/${var.prefix}-ciphernest-key"
  target_key_id = aws_kms_key.lambda_kms_key.id
}
