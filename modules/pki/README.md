## Description

This module deploys a lambda function which by default generates a root and intermediate certificate authority, and signs leaf certificates against the intermediate.

Certificates are stored to S3, and the intermediate CA private key is encrypted and stored in S3 via the ciphernest module.

A step machine is provided to simplify the invocation of the lambda, and to provide for a FIFO queue of lambda operation events.

The module outputs the name of the S3 bucket storing the certificate authorities, and the ARN for the step machine as an entrypoint into the lambda invocation.

## Diagram
![PKI Diagram](./workflow/pki.jpg)

## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.0.0 |
| <a name="requirement_archive"></a> [archive](#requirement\_archive) | ~> 2.0 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 4.16 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_archive"></a> [archive](#provider\_archive) | ~> 2.0 |
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 4.16 |

## Modules

| Name | Version |
|------|---------|
| <a name="module_resources"></a> [module](#ciphernest) | ~> 0.1 |

## Resources

| Name | Type |
|------|------|
| [aws_cloudwatch_log_group.step_function_logs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_cloudwatch_log_resource_policy.step_function_logs_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_resource_policy) | resource |
| [aws_iam_policy.lambda_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.step_function_lambda_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.step_function_logging_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_role.lambda_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.step_function_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy_attachment.lambda_attach](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.lambda_basic_execution](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.step_function_lambda_policy_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.step_function_logging_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_lambda_function.pki](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_invocation.pki_genca](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_invocation) | resource |
| [aws_lambda_layer_version.cryptography](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_layer_version) | resource |
| [aws_lambda_permission.allow_invoke_pki](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_s3_bucket.ca_bucket](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket_ownership_controls.ca_bucket](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_ownership_controls) | resource |
| [aws_s3_bucket_public_access_block.ca_bucket](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block) | resource |
| [aws_s3_bucket_versioning.ciphernest_bucket](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_versioning) | resource |
| [aws_sfn_state_machine.pki_state_machine](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sfn_state_machine) | resource |
| [archive_file.pki_zip](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_lambda"></a> [lambda](#input\_lambda) | Output specifying the ciphernest lambda function | <pre>object({<br/>    name = string<br/>    role = string<br/>    arn  = string<br/>  })</pre> | n/a | yes |
| <a name="input_prefix"></a> [prefix](#input\_prefix) | namespace prefix for the cert authority | `string` | `"default"` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_resources"></a> [resources](#output\_resources) | PKI resources 

## Usage
1) Environment level tf file: 
pki.tf
```hcl
   module "ciphernest" {
     source  = "insightsoftmax.jfrog.io/terraform__isc/ciphernest/isc"
     version = "~> 0.1"
     prefix  = "default" # optional: namespace prefix the aws resources generated for s3, kms, and lambda 
   }

   module "pki" {
     source  = "insightsoftmax.jfrog.io/terraform__isc/pki/isc"
     version = "~> 0.1"
     prefix = "default"
     lambda = module.ciphernest.lambda
   }
```
2) module.pki returns the step machine entrypoint for lambda opertions
```bash
$ terraform console
> module.pki
{
  "resources" = {
    "ca_bucket" = "default-ca-certificates"
    "entrypoint" = "arn:aws:states:us-east-2:982534390916:stateMachine:default_entrypoint_machine"
  }
}
```
3) Any AWS resource requiring a signed certificate executes the pki entrypoint machine
```bash
#!/bin/bash

# variables
REGION="us-east-2"
CA_BUCKET="default-ca-certificates"
ENTRY_POINT="arn:aws:states:us-east-2:982534390916:stateMachine:default_entrypoint_machine"
POLL_INTERVAL=5  

# get the ca chain
aws s3 cp "s3://${CA_BUCKET}/" . --recursive
cat intermediateCA.crt rootCA.crt > chain.pem

# run genleaf
## all certificate attributes can be optionally overwritten, defaults:
##   {
##     "common_name": "example.com",
##     "organization": "ISC",
##     "country": "US",
##     "state": "California",
##     "locality": "San Francisco",
##     "validity_days": 36500,
##     "sans": []
##   }
EXECUTION_ARN=`aws stepfunctions start-execution --region=us-east-2 \
  --state-machine-arn "${ENTRY_POINT}" \
  --name "Execution-$(date +%Y%m%d%H%M%S)" \
  --input '{"operation": "genleaf", "attributes": {"common_name": "ldap.isc.net", "sans": ["*", "*.isc.net"]}}' | jq -r '.executionArn'`
                                                                                        
# poll machine state, and extract leaf certificate and private key
while true; do

  # update status
  EXECUTION_DETAILS=$(aws stepfunctions describe-execution \
    --region=$REGION \
    --execution-arn "$EXECUTION_ARN")
  STATUS=$(echo "$EXECUTION_DETAILS" | grep -o '"status": "[^"]*"' | cut -d'"' -f4)
  echo "Current status: $STATUS"

  # Check if execution succeeded
  if [[ "$STATUS" == "SUCCEEDED" ]]; then
    echo "Execution completed successfully. Extracting certificate and private key..."
    # extract data
    echo "$EXECUTION_DETAILS" | grep '"output"' | \
      sed -nE 's/.*(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----).*/\1/p' | \
      sed 's/\\n/\n/g' | sed 's/\\$//' > certificate.pem
    echo "$EXECUTION_DETAILS" | grep '"output"' | \
      sed -nE 's/.*(-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----).*/\1/p' | \
      sed 's/\\n/\n/g' | sed 's/\\$//' > privkey.pem
    # garbage collection
    unset EXECUTION_DETAILS
    # file permissions
    chmod 644 certificate.pem
    chmod 600 privkey.pem
    break
  elif [[ "$STATUS" == "FAILED" || "$STATUS" == "TIMED_OUT" || "$STATUS" == "ABORTED" ]]; then
    echo "Execution failed with status: $STATUS"
    echo "Error details:"
    echo "$EXECUTION_DETAILS" | jq '.error, .cause'
  fi

  # Wait before polling again
  echo "Waiting $POLL_INTERVAL seconds before next poll..."
  sleep $POLL_INTERVAL
done

# verify the leaf cert
openssl verify -CAfile chain.pem certificate.pem 

# output leaf cert details
openssl x509 -in certificate.pem -text -noout
```
