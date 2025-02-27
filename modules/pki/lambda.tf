# layer

resource "aws_lambda_layer_version" "cryptography" {
  filename            = "${path.module}/files/zip/cryptography.zip"
  layer_name          = "${var.prefix}-python312-cryptography"
  compatible_runtimes = ["python3.12"]
  description         = "Python cryptography library layer"
}

# policy

resource "aws_iam_role" "lambda_role" {
  name = "${var.prefix}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_policy" "lambda_policy" {
  name        = "${var.prefix}-lambda-permissions"
  description = "Allows Lambda to access S3 and Secrets Manager"

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
          aws_s3_bucket.ca_bucket.arn,
          "${aws_s3_bucket.ca_bucket.arn}/*",
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect   = "Allow"
        Action   = ["states:StartExecution"]
        Resource = aws_sfn_state_machine.pki_state_machine.arn
      },
      {
        Effect   = "Allow"
        Action   = ["sts:AssumeRole"]
        Resource = var.lambda.role
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

data "archive_file" "pki_zip" {
  type        = "zip"
  output_path = "${path.module}/files/zip/pki.zip"
  source_dir  = "${path.module}/files/lambda/pki"
}

resource "aws_lambda_function" "pki" {
  function_name    = "${var.prefix}-pki"
  role             = aws_iam_role.lambda_role.arn
  runtime          = "python3.12"
  handler          = "pki.lambda_handler"
  filename         = data.archive_file.pki_zip.output_path
  source_code_hash = data.archive_file.pki_zip.output_base64sha256
  timeout          = 60

  environment {
    variables = {
      PREFIX      = var.prefix
      ACCOUNT_ID  = data.aws_caller_identity.current.account_id
      CERT_BUCKET = aws_s3_bucket.ca_bucket.bucket
      LAMBDA_NAME = var.lambda.name
      LAMBDA_ROLE = var.lambda.role
    }
  }

  layers = [
    aws_lambda_layer_version.cryptography.arn
  ]
}

resource "aws_lambda_permission" "allow_invoke_pki" {
  statement_id  = "AllowExecutionFromAPI"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pki.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = aws_iam_policy.lambda_policy.arn
}

# invoke genca

resource "aws_lambda_invocation" "pki_genca" {
  function_name = aws_lambda_function.pki.function_name

  input = jsonencode({
    operation = "genca"
  })
}
