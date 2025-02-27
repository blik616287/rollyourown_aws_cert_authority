import os
import logging
import json
from typing import Optional, Dict, Union, Tuple, Any
import boto3
import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy, EncryptionSDKClient
from aws_encryption_sdk.key_providers.kms import StrictAwsKmsMasterKeyProvider
from aws_encryption_sdk.structures import MessageHeader
from botocore.exceptions import ClientError
from botocore.client import BaseClient
from mypy_boto3_s3.client import S3Client
from mypy_boto3_sts.client import STSClient


# clients
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
s3_client: S3Client = boto3.client('s3')
sts_client: STSClient = boto3.client("sts")
client: EncryptionSDKClient = aws_encryption_sdk.EncryptionSDKClient(
    commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
)


def setup_logging() -> None:
    """Configure logging format and handlers."""
    logger.handlers = []
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)


def get_caller_id() -> str:
    """Retrieve caller id."""
    try:
        account_id = sts_client.get_caller_identity()["Account"]
        logger.debug(f"Retrieved caller account ID: {account_id}")
        return account_id
    except ClientError as e:
        logger.error(f"Failed to get caller identity: {str(e)}")
        raise


def get_kms_key_provider(key_arn: str) -> StrictAwsKmsMasterKeyProvider:
    """Create KMS key provider with specified key."""
    if not key_arn.startswith('arn:aws:kms:'):
        error_msg = f"Invalid KMS key ARN format: {key_arn}"
        logger.error(error_msg)
        raise ValueError(error_msg)
    logger.debug(f"Creating KMS key provider with key ARN: {key_arn}")
    return StrictAwsKmsMasterKeyProvider(key_ids=[key_arn])


def encrypt_content(content: str,
                   key_arn: str,
                   account_id: str,
                   encryption_context: Optional[Dict[str, str]] = None
                   ) -> Optional[Tuple[bytes, MessageHeader]]:
    """Encrypt content using SDK."""
    try:
        if not content:
            raise ValueError("Content to encrypt cannot be empty")
        content_bytes = content.encode('utf-8')
        key_provider = get_kms_key_provider(key_arn)
        encryption_context = encryption_context or {}
        encryption_context["accountid"] = account_id
        logger.info(f"Encrypting data with key {key_arn}")
        encrypted_data, encryptor_header = client.encrypt(
            source=content_bytes,
            key_provider=key_provider,
            encryption_context=encryption_context
        )
        logger.info(
            f"Successfully encrypted data with key {key_arn}."
            f"Encryption context: {encryption_context}"
        )
        return encrypted_data, encryptor_header
    except Exception as e:
        logger.error(
            f"Encryption failed: {str(e)}",
            f"Encryption context: {encryption_context}",
            exc_info=True
        )
        raise


def decrypt_content(encrypted_data: bytes,
                   key_arn: str,
                   encryption_context: Optional[Dict[str, str]] = None
                   ) -> Optional[str]:
    """Decrypt content using SDK."""
    try:
        if not encrypted_data:
            raise ValueError("Encrypted data cannot be empty")
        key_provider = get_kms_key_provider(key_arn)
        logger.info(f"Attempting to decrypt data with key {key_arn}")
        decrypted_data, decryptor_header = client.decrypt(
            source=encrypted_data,
            key_provider=key_provider
        )
        if encryption_context:
            for key, value in encryption_context.items():
                if decryptor_header.encryption_context.get(key) != value: # prefix known stamps
                    raise ValueError(
                        f"Encryption context mismatch for key '{key}': "
                        f"expected '{value}', got '{decryptor_header.encryption_context.get(key)}'"
                    )
        logger.info("Successfully decrypted data")
        return decrypted_data.decode('utf-8')
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}", exc_info=True)
        raise


def write_to_s3(bucket: str, key: str, data: bytes) -> bool:
    """Write encrypted data to S3"""
    try:
        if not isinstance(data, bytes):
            raise TypeError(f"Data must be bytes, got {type(data)}")
        s3_client.put_object(
            Bucket=bucket,
            Key=key,
            Body=data
        )
        logger.info(f"Successfully wrote encrypted data to s3://{bucket}/{key}")
        return True
    except Exception as e:
        logger.error(f"Failed to write to S3: {str(e)}", exc_info=True)
        return False


def read_from_s3(bucket: str, key: str) -> Optional[bytes]:
    """Read encrypted data from S3."""
    try:
        logger.info(f"Reading from s3://{bucket}/{key}")
        response = s3_client.get_object(
            Bucket=bucket,
            Key=key
        )
        return response['Body'].read()
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchKey':
            logger.error(f"Object s3://{bucket}/{key} does not exist")
        else:
            logger.error(f"Failed to read from S3: {str(e)}", exc_info=True)
        raise


def validate_request_parameters(operation: str) -> Optional[Dict[str, Any]]:
    """Validate requests."""
    if operation not in ['encrypt', 'decrypt']:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'error': f'Invalid operation: {operation}. Must be "encrypt" or "decrypt"'
            })
        }
    return None


def lambda_handler(event: Dict[str, Any],
                  context: Any
                  ) -> Dict[str, Any]:
    """Lambda entry point."""
    setup_logging()
    logger.info("Processing encryption/decryption request")
    try:
        # check caller context
        account_id = os.environ.get('ACCOUNT_ID')
        if not account_id:
            raise ValueError("ACCOUNT_ID environment variable is not set")
        if get_caller_id() != account_id:
            return {
                'statusCode': 403,
                'body': json.dumps({
                    'error': 'Unauthorized: Invalid caller ID'
                })
            }
        # check kms key
        kms_key_arn = os.environ.get('KMS_KEY_ARN')
        if not kms_key_arn:
            raise ValueError("KMS_KEY_ARN environment variable is not set")
        # producer parameters
        operation = event.get('operation', '').lower()
        validation_error = validate_request_parameters(operation)
        s3_bucket = event.get('s3_bucket', os.environ.get('DEFAULT_BUCKET'))
        s3_key = event.get('s3_key', f'encrypted/{context.aws_request_id}.encrypted')
        encryption_context: Dict[str, str] = event.get('encryption_context', {})
        # business logic for encrypt and decrypt operations
        if operation == 'encrypt':
            string_to_encrypt = event.get('string_to_encrypt')
            if not string_to_encrypt:
                return {
                    'statusCode': 400,
                    'body': json.dumps({
                        'error': 'Missing string_to_encrypt parameter'
                    })
                }
            encryption_result = encrypt_content(
                content=string_to_encrypt,
                key_arn=kms_key_arn,
                account_id=account_id,
                encryption_context=encryption_context
            )
            if encryption_result is None:
                return {
                    'statusCode': 500,
                    'body': json.dumps({
                        'error': 'Encryption failed'
                    })
                }
            encrypted_data, _ = encryption_result
            if write_to_s3(s3_bucket, s3_key, encrypted_data):
                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        'message': 'Successfully encrypted and stored data',
                        'bucket': s3_bucket,
                        'key': s3_key
                    })
                }
            else:
                return {
                    'statusCode': 500,
                    'body': json.dumps({
                        'error': 'Failed to write encrypted data to S3'
                    })
                }
        elif operation == 'decrypt':
            s3_key = event.get('s3_key')
            if not s3_key:
                return {
                    'statusCode': 400,
                    'body': json.dumps({
                        'error': 'Missing s3_key parameter for decryption'
                    })
                }
            encrypted_data = read_from_s3(s3_bucket, s3_key)
            if encrypted_data is None:
                return {
                    'statusCode': 500,
                    'body': json.dumps({
                        'error': 'Failed to read encrypted data from S3'
                    })
                }
            decrypted_content = decrypt_content(
                encrypted_data=encrypted_data,
                key_arn=kms_key_arn,
                encryption_context=encryption_context
            )
            if decrypted_content is None:
                return {
                    'statusCode': 500,
                    'body': json.dumps({
                        'error': 'Decryption failed'
                    })
                }
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Successfully decrypted data',
                    'decrypted_content': decrypted_content
                })
            }
    except Exception as e:
        logger.error(f"Unexpected error in lambda_handler: {str(e)}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': f'Internal server error: {str(e)}'
            })
        }
