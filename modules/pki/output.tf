output "resources" {
  description = "PKI resources"
  value = {
    "ca_bucket"  = aws_s3_bucket.ca_bucket.bucket,
    "entrypoint" = aws_sfn_state_machine.pki_state_machine.arn
  }
}
