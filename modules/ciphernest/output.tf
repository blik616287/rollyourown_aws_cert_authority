output "lambda" {
  description = "Lambda role information"
  value = {
    role = aws_iam_role.lambda_role.arn,
    name = aws_lambda_function.ciphernest_sdk.function_name
    arn  = aws_lambda_function.ciphernest_sdk.arn
  }
}
