# layers

resource "aws_lambda_layer_version" "aws_encryption_sdk" {
  filename            = "${path.module}/files/zip/aws-encryption-sdk.zip"
  layer_name          = "${var.prefix}-python312-aws-encryption-sdk"
  compatible_runtimes = ["python3.12"]
  description         = "AWS encryption SDK with MPL support library layer"
}

resource "aws_lambda_layer_version" "mypy_boto3_s3" {
  filename            = "${path.module}/files/zip/mypy-boto3-s3.zip"
  layer_name          = "${var.prefix}-python312-mypy-boto3-s3"
  compatible_runtimes = ["python3.12"]
  description         = "Annotations for boto3 s3 svc"
}

resource "aws_lambda_layer_version" "mypy_boto3_sts" {
  filename            = "${path.module}/files/zip/mypy-boto3-sts.zip"
  layer_name          = "${var.prefix}-python312-mypy-boto3-sts"
  compatible_runtimes = ["python3.12"]
  description         = "Annotations for boto3 sts svc"
}

# policy

resource "aws_iam_role" "lambda_role" {
  name = "${var.prefix}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "lambda_policy" {
  name        = "${var.prefix}-lambda-policy"
  description = "Allows Lambda to access KMS"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "${aws_s3_bucket.ciphernest_bucket.arn}",
          "${aws_s3_bucket.ciphernest_bucket.arn}/*",
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          #"kms:Encrypt" # todo test remove
        ]
        Resource = ["${aws_kms_key.lambda_kms_key.arn}"]
      },
      {
        Effect   = "Allow"
        Action   = ["lambda:InvokeFunction"]
        Resource = [aws_lambda_function.ciphernest_sdk.arn]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambda_attach" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

# handler

data "archive_file" "ciphernest_sdk_zip" {
  type        = "zip"
  output_path = "${path.module}/files/zip/ciphernest_sdk.zip"
  source_dir  = "${path.module}/files/lambda/ciphernest_sdk"
}

resource "aws_lambda_function" "ciphernest_sdk" {
  function_name    = "${var.prefix}-sdk-lambda"
  role             = aws_iam_role.lambda_role.arn
  runtime          = "python3.12"
  handler          = "ciphernest_sdk.lambda_handler"
  filename         = data.archive_file.ciphernest_sdk_zip.output_path
  source_code_hash = data.archive_file.ciphernest_sdk_zip.output_base64sha256
  timeout          = 60
  layers = [
    aws_lambda_layer_version.aws_encryption_sdk.arn,
    aws_lambda_layer_version.mypy_boto3_s3.arn,
    aws_lambda_layer_version.mypy_boto3_sts.arn
  ]

  environment {
    variables = {
      ACCOUNT_ID     = data.aws_caller_identity.current.account_id
      KMS_KEY_ARN    = aws_kms_key.lambda_kms_key.arn
      DEFAULT_BUCKET = aws_s3_bucket.ciphernest_bucket.bucket
    }
  }
}

resource "aws_lambda_permission" "allow_invoke_lambda" {
  statement_id  = "AllowExecutionFromAPI"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ciphernest_sdk.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = aws_iam_policy.lambda_policy.arn
}
