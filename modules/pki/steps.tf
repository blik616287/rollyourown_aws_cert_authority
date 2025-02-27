# logging

resource "aws_cloudwatch_log_group" "step_function_logs" {
  name              = "/aws/states/${var.prefix}"
  retention_in_days = 14
}

resource "aws_iam_policy" "step_function_logging_policy" {
  name = "${var.prefix}_step_function_logging_policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogDelivery",
          "logs:GetLogDelivery",
          "logs:UpdateLogDelivery",
          "logs:DeleteLogDelivery",
          "logs:ListLogDeliveries",
          "logs:PutLogEvents",
          "logs:PutResourcePolicy",
          "logs:DescribeResourcePolicies",
          "logs:DescribeLogGroups"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

resource "aws_cloudwatch_log_resource_policy" "step_function_logs_policy" {
  policy_name = "${var.prefix}_step_function_logs_policy"

  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "states.${data.aws_region.current.name}.amazonaws.com"
        }
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.step_function_logs.arn}:*"
      }
    ]
  })
}

# role

resource "aws_iam_role" "step_function_role" {
  name = "${var.prefix}_step_function_execution_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "states.amazonaws.com"
        }
      }
    ]
  })
}

# policy

resource "aws_iam_policy" "step_function_lambda_policy" {
  name = "${var.prefix}_step_function_lambda_policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "lambda:InvokeFunction"
        ]
        Effect   = "Allow"
        Resource = aws_lambda_function.pki.arn
      }
    ]
  })
}

# attach policies

resource "aws_iam_role_policy_attachment" "step_function_lambda_policy_attachment" {
  role       = aws_iam_role.step_function_role.name
  policy_arn = aws_iam_policy.step_function_lambda_policy.arn
}

resource "aws_iam_role_policy_attachment" "step_function_logging_attachment" {
  role       = aws_iam_role.step_function_role.name
  policy_arn = aws_iam_policy.step_function_logging_policy.arn
}

# entrypoint

resource "aws_sfn_state_machine" "pki_state_machine" {
  name     = "${var.prefix}_entrypoint_machine"
  role_arn = aws_iam_role.step_function_role.arn

  definition = jsonencode({
    StartAt = "InvokeLambda"
    States = {
      InvokeLambda = {
        Type     = "Task"
        Resource = aws_lambda_function.pki.arn
        End      = true
      }
    }
  })
}
