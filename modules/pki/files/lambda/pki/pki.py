import base64
import hashlib
import json
import logging
import os
import tempfile
import time
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any, Dict, List, Optional, Tuple, Union
import boto3
import botocore.exceptions
from botocore.client import BaseClient
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


# clients
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
lambda_client: BaseClient = boto3.client('lambda')
s3: BaseClient = boto3.client("s3")
sts_client: BaseClient = boto3.client("sts")


def setup_logging() -> None:
    """Configure logging format and handlers."""
    logger.handlers = []
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
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


def generate_rsa_key(exponent: int = 65537,
                    size: int = 4096
                    ) -> rsa.RSAPrivateKey:
    """Generate RSA private key.
    Default values chosen based on cryptographic best practices:

    exponent=65537 (0x10001) because:
    1. Small Hamming weight (only 2 bits set) makes public key operations efficient
    2. Large enough to avoid mathematical attacks (Coppersmith's)
    3. Industry standard (RFC 4871, PKIX) and most widely used RSA exponent
    4. Recommended by NIST SP 800-89 Section 5.3.3

    size=4096 because:
    1. NIST SP 800-57 Part 1 Rev. 5 recommends 3072+ bits for security beyond 2030
    2. Provides ~128-bit equivalent symmetric security strength
    3. Balances security margin with reasonable performance
    4. Common CA requirement for root/intermediate certificates
    """
    logger.info(f"Generating RSA key with size {size} bits and exponent {exponent}")
    try:
        key = rsa.generate_private_key(
            public_exponent=exponent,
            key_size=size,
        )
        logger.debug("RSA key generation successful")
        return key
    except Exception as e:
        logger.error(f"Failed to generate RSA key: {str(e)}")
        raise


def get_certificate_kwargs(attributes: Dict[str, Any]) -> Dict[str, Any]:
    """Generate filtered kwargs for certificate generation."""
    logger.info("Generating certificate kwargs from event attributes")
    # Specify relevant user overrides to attributes with defaults
    relevant_params: Dict[str, Any] = {
        "common_name": "example.com",
        "organization": "ISC",
        "country": "US",
        "state": "California",
        "locality": "San Francisco",
        "validity_days": 36500,
        "sans": None
    }
    # Generate kwargs
    filtered_kwargs: Dict[str, Any] = {}
    for param, default in relevant_params.items():
        if param in attributes:
            filtered_kwargs[param] = attributes[param]
            logger.info(f"Using attribute value for parameter: {param}")
        elif default is not None:
            filtered_kwargs[param] = default
            logger.debug(f"Using default value for parameter: {param}")
    logger.debug(f"Final certificate parameters: {', '.join(filtered_kwargs.keys())}")
    return filtered_kwargs


def generate_certificate(common_name: str,
                        cert_type: str = "leaf",
                        issuer_key_pem: Optional[bytes] = None,
                        issuer_cert_pem: Optional[bytes] = None,
                        organization: str = "ISC",
                        country: str = "US",
                        state: str = "California",
                        locality: str = "San Francisco",
                        validity_days: int = 36500,
                        path_length: int = None,
                        sans: Optional[List[Union[str, IPv4Address, IPv6Address]]] = None
                        ) -> Tuple[bytes, bytes]:
    """
    Generate a certificate with flexible parameters for root, intermediate, or leaf certificates.
    All key and certificate inputs and outputs are in PEM format.
    Args:
        common_name: The CN field for the certificate
        cert_type: Type of certificate ("root", "intermediate", or "leaf")
        issuer_key_pem: The private key of the issuing certificate in PEM format (None for root CA)
        issuer_cert_pem: The issuing certificate in PEM format (None for root CA)
        organization: Organization name
        country: Country code
        state: State or province name
        locality: City or locality name
        validity_days: Number of days the certificate is valid
        path_length: Length of allowed chain
        sans: List of Subject Alternative Names (DNS names or IP addresses)
    Returns:
        Tuple[bytes, bytes]: (private_key_pem, certificate_pem)
    Raises:
        ValueError: If invalid parameters are provided
        TypeError: If parameters are of incorrect type
    """
    # parameter check
    if not isinstance(common_name, str):
        raise TypeError("common_name must be a string")
    if cert_type not in ("root", "intermediate", "leaf"):
        raise ValueError("cert_type must be 'root', 'intermediate', or 'leaf'")
    if validity_days <= 0:
        raise ValueError("validity_days must be positive")
    logger.info(f"Generating {cert_type} certificate for {common_name}")
    try:
        # privkey
        key: rsa.RSAPrivateKey = generate_rsa_key()
        key_pem: bytes = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        # subject name
        subject: Name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        # builder
        builder: x509.CertificateBuilder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.public_key(key.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.utcnow())
        builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
        # handle certificate issuer
        if cert_type == "root":
            if issuer_key_pem is not None or issuer_cert_pem is not None:
                raise ValueError("Root certificates should not have issuer parameters")
            issuer: Name = subject
            signing_key: rsa.RSAPrivateKey = key
            path_length = 1
        else:
            # check for issuer
            if not isinstance(issuer_key_pem, bytes) or not isinstance(issuer_cert_pem, bytes):
                raise TypeError("Issuer key and certificate must be provided as bytes for non-root certificates")
            # load issuer certificate and privkey
            issuer_key: rsa.RSAPrivateKey = load_pem_private_key(
                issuer_key_pem,
                password=None,
            )
            issuer_cert: Certificate = load_pem_x509_certificate(issuer_cert_pem)
            issuer = issuer_cert.subject
            signing_key = issuer_key
        builder = builder.issuer_name(issuer)
        # certificate extensions by type
        if cert_type in ("root", "intermediate"):  # signing certificates
            if path_length is None and cert_type == "intermediate":
                path_length = 0
            builder = builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=path_length),
                critical=True
            )
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
        else:  # leaf certificate
            builder = builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True
            )
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.SERVER_AUTH,
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=False
            )
            """
            RFC 5280, Section 4.2.1.12 Extended Key Usage:
            If a certificate contains both a key usage extension and an extended
            key usage extension, then both extensions MUST be processed independently
            and the certificate must only be used for a purpose consistent with both
            extensions.
            critical=False because:
            1. We already have a critical keyUsage extension
            2. Applications not recognizing EKU should still accept the cert
               (backwards compatibility)
            3. Common TLS implementations expect non-critical EKU for standard web PKI
            """
            if sans:
                san_list = []
                if isinstance(sans, str):
                    san_list.append(x509.DNSName(sans))
                elif isinstance(sans, list):
                    for san in sans:
                        try:
                            if isinstance(san, str):
                                san_list.append(x509.DNSName(san))
                            elif isinstance(san, (IPv4Address, IPv6Address)):
                                san_list.append(x509.IPAddress(san))
                            else:
                                try:
                                    ip = ip_address(san)
                                    san_list.append(x509.IPAddress(ip))
                                except ValueError:
                                    san_list.append(x509.DNSName(san))
                        except Exception as e:
                            raise ValueError(f"Invalid SAN entry: {san}") from e
                else:
                    raise TypeError("sans must be None, a string, or a list")
                if x509.DNSName(common_name) not in san_list:
                    san_list.insert(0, x509.DNSName(common_name))
                if san_list:
                    builder = builder.add_extension(
                        x509.SubjectAlternativeName(san_list),
                        critical=False
                    )
                    """
                    RFC 5280, Section 4.2.1.6 Subject Alternative Name:
                    SubjectAltName (SAN) allows additional identities to be
                    bound to the certificate subject. The criticality flag
                    depends on the presence of the subject field.
                    critical=False because:
                    1. We always include a non-empty subject DN containing:
                      - Country (C)
                      - State (ST)
                      - Locality (L)
                      - Organization (O)
                      - Common Name (CN)
                    2. RFC requires critical=TRUE only when subject field
                       is empty
                    3. Standard web PKI expects non-critical SAN when subject
                       DN is present
                    """
        cert: Certificate = builder.sign(private_key=signing_key, algorithm=hashes.SHA256())
        cert_pem: bytes = cert.public_bytes(serialization.Encoding.PEM)
        logger.info(f"{cert_type.capitalize()} certificate generated successfully")
        return key_pem, cert_pem
    except Exception as e:
        logger.error(f"Failed to generate {cert_type} certificate: {str(e)}")
        raise


def extract_intermediate_key(response_json: Dict[str, Any],
                            as_bytes: bool = False
                            ) -> Optional[str]:
    """Extracts the decrypted content from the response."""
    if not isinstance(response_json, dict):
        error_msg = f"Expected dictionary, got {type(response_json).__name__}"
        logger.error(error_msg)
        raise TypeError(error_msg)
    try:
        # Check if body exists in the response
        if 'body' not in response_json:
            logger.warning("No 'body' field found in response")
            return None
        # Extract the body string and parse it
        body_str = response_json['body']
        logger.debug("Successfully extracted body string")
        body_json = json.loads(body_str)
        logger.debug("Body JSON parsed successfully")
        # Check if decrypted_content exists in the parsed body
        if 'decrypted_content' not in body_json:
            logger.warning("No 'decrypted_content' field found in body JSON")
            return None
        # Extract the decrypted content
        private_key = body_json['decrypted_content']
        if not isinstance(private_key, str):
            logger.warning(f"Private key is not a string: {type(private_key).__name__}")
            private_key = str(private_key)
        logger.info("Successfully extracted private key")
        if as_bytes:
            return private_key.encode('utf-8')
        return private_key
    except json.JSONDecodeError as e:
        logger.error(f"JSON parsing error: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Error extracting private key: {str(e)}")
        raise


def file_exists_in_s3(bucket_name: str,
                     filename: str
                     ) -> bool:
    """Check if a file exists in the S3 bucket."""
    logger.debug(f"Checking if file {filename} exists in bucket {bucket_name}")
    try:
        s3.head_object(Bucket=bucket_name, Key=filename)
        logger.debug(f"File {filename} exists in bucket {bucket_name}")
        return True
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "404":
            logger.debug(f"File {filename} does not exist in bucket {bucket_name}")
            return False
        logger.error(f"Error checking file existence: {str(e)}")
        raise


def upload_to_s3(bucket_name: str,
                filename: str,
                content: bytes
                ) -> None:
    """Upsert and validate content to S3."""
    logger.info(f"Uploading file {filename} to bucket {bucket_name}")
    try:
        if not isinstance(content, bytes):
            raise TypeError(f"Content must be bytes, got {type(content)}")
        s3.put_object(Bucket=bucket_name, Key=filename, Body=content)
        file_exists_in_s3(bucket_name, filename)
        logger.info(f"Successfully uploaded {filename} to {bucket_name}")
    except Exception as e:
        logger.error(f"Failed to upload file to S3: {str(e)}")
        raise


def fetch_from_s3(bucket_name: str,
                 object_key: str
                 ) -> bytes:
    """Fetch an object from S3"""
    logger.info(f"Fetching object {object_key} from bucket {bucket_name}")
    try:
        response = s3.get_object(Bucket=bucket_name, Key=object_key)
        content = response['Body'].read()
        logger.info(f"Successfully fetched {object_key} from {bucket_name}")
        return content
    except Exception as e:
        logger.error(f"Failed to fetch object from S3: {str(e)}")
        raise


def invoke_ciphernest_sdk(function_name: str,
                         role_arn: str,
                         operation: str,
                         s3_key: str,
                         encryption_context: Dict[str, str],
                         intermediate_key_pem: Optional[bytes] = None,
                         ) -> Dict[str, Any]:
    """Invoke ciphernest-sdk lambda using the function's affiliated role."""
    # check parameters
    if operation not in ("encrypt", "decrypt"):
        raise ValueError("operation must be 'encrypt' or 'decrypt'")
    if operation == "encrypt" and not intermediate_key_pem:
        raise ValueError("intermediate_key_pem is required for encrypt operation")
    if operation == "encrypt" and not isinstance(intermediate_key_pem, bytes):
        raise TypeError("intermediate_key_pem must be bytes")
    # business logic
    logger.info(f"Assuming role {role_arn} to invoke {function_name}")
    try:
        # use lambda role for ciphernest
        assumed_role_response: Dict[str, Any] = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='lambda-invocation-session'
        )
        credentials: Dict[str, str] = assumed_role_response['Credentials']
        lambda_client: BaseClient = boto3.client(
            'lambda',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        # payload
        payload: Dict[str, Union[str, Dict[str, str]]] = {
            "operation": operation,
            "s3_key": s3_key,
            "encryption_context": encryption_context
        }
        # add encryption payload
        if operation == "encrypt":
            payload["string_to_encrypt"] = intermediate_key_pem.decode('utf-8')
        logger.debug(f"Sending {operation} request with assumed role")
        # invoke lambda
        response: Dict[str, Any] = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType='RequestResponse',
            Payload=json.dumps(payload)
        )
        response_payload: Dict[str, Any] = json.loads(
            response['Payload'].read()
        )
        if 'statusCode' not in response_payload:
            raise ValueError("Invalid response format - missing statusCode")
        if response_payload['statusCode'] != 200:
            logger.error(f"{operation.capitalize()} failed with status {response_payload['statusCode']}")
            raise Exception(f"{operation.capitalize()} failed: {response_payload}")
        logger.info(f"Successfully completed {operation} operation using assumed role")
        return response_payload
    except botocore.exceptions.ClientError as e:
        logger.error(f"AWS operation failed: {str(e)}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse lambda response: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise


def lambda_handler(event: Dict[str, Any],
                  context: Any
                  ) -> Dict[str, Any]:
    """Lambda entry point."""
    setup_logging()
    logger.info("Lambda handler started")
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
        # environment pull
        prefix = os.environ.get('PREFIX')
        cert_bucket = os.environ.get('CERT_BUCKET')
        lambda_name = os.environ.get('LAMBDA_NAME')
        lambda_role = os.environ.get('LAMBDA_ROLE')
        # event pull
        override_ca: bool = str(event.get("OVERRIDE_CA", "false")).lower() == "true"
        operation = event.get('operation', '').lower()
        attributes = event.get('attributes', {})
        filtered_kwargs = get_certificate_kwargs(attributes)
        # business logic
        logger.info(f"Processing operation: {operation}")
        if operation == 'genca':
            # check if the ca certs need to be generated
            if file_exists_in_s3(cert_bucket, "rootCA.crt") and not override_ca:
                msg = f"Certificate authority already exists for prefix: {prefix}"
                logger.warning(msg)
                return {
                    'statusCode': 500,
                    'body': json.dumps({'error': msg})
                }
            # generate root and intermediate certificate authorities
            with tempfile.TemporaryDirectory() as temp_dir:
                # root
                filtered_kwargs["cert_type"] = "root"
                filtered_kwargs["common_name"] = f"{prefix} Root CA"
                root_key_pem, root_cert_pem = generate_certificate(**filtered_kwargs)
                # intermediate
                filtered_kwargs["cert_type"] = "intermediate"
                filtered_kwargs["issuer_key_pem"] = root_key_pem
                filtered_kwargs["issuer_cert_pem"] = root_cert_pem
                filtered_kwargs["common_name"] = f"{prefix} Intermediate CA"
                intermediate_key_pem, intermediate_cert_pem = generate_certificate(**filtered_kwargs)
                # upload certs
                upload_to_s3(cert_bucket, "rootCA.crt", root_cert_pem)
                upload_to_s3(cert_bucket, "intermediateCA.crt", intermediate_cert_pem)
                logger.info("Successfully generated and stored root and intermediate certificates")
                # encrypt intermediate private key pem
                resp = invoke_ciphernest_sdk(function_name = lambda_name,
                                            role_arn = lambda_role,
                                            operation = "encrypt",
                                            s3_key = f"{prefix}-ica-privkey.encrypted",
                                            encryption_context = {f"{prefix}-{operation}": f"{prefix}-ica-privkey"},
                                            intermediate_key_pem = intermediate_key_pem)
                logger.info("Successfully encrypted and stored intermediate private key")
                return {
                    "statusCode": 200,
                    "body": json.dumps({
                        "message": "Certificates generated and uploaded to S3",
                        "s3_files": [
                            f"s3://{cert_bucket}/rootCA.crt",
                            f"s3://{cert_bucket}/intermediateCA.crt",
                        ],
                    })
                }
        # generate leaf certificate
        elif operation == 'genleaf':
            logger.info(f"Generate a leaf certificate with ciphernest prefix: {prefix}")
            # get intermediate cert
            intermediate_cert_pem = fetch_from_s3(cert_bucket, "intermediateCA.crt")
            # get private key for intermediate cert
            resp = invoke_ciphernest_sdk(function_name = lambda_name,
                                        role_arn = lambda_role,
                                        operation = "decrypt",
                                        s3_key = f"{prefix}-ica-privkey.encrypted",
                                        encryption_context = {f"{prefix}-genca": f"{prefix}-ica-privkey"})
            # finesse the response
            intermediate_key_pem = extract_intermediate_key(resp, as_bytes=True)
            if not isinstance(intermediate_cert_pem, bytes):
                intermediate_cert_pem = intermediate_cert_pem.encode('utf-8')
            # specify leaf kwarg and attributes
            filtered_kwargs["cert_type"] = "leaf"
            filtered_kwargs["issuer_key_pem"] = intermediate_key_pem
            filtered_kwargs["issuer_cert_pem"] = intermediate_cert_pem
            leaf_key_pem, leaf_cert_pem = generate_certificate(**filtered_kwargs)
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "message": "Leaf certificate generated.",
                    "certificate": leaf_cert_pem.decode('utf-8'),
                    "privatekey": leaf_key_pem.decode('utf-8')
                })
            }
        else:
            msg = f'Invalid operation: {operation}. Must be "genCA" or "genLEAF"'
            logger.error(msg)
            return {
                'statusCode': 400,
                'body': json.dumps({'error': msg})
            }
    except Exception as e:
        logger.error(f"Unexpected error in lambda_handler: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f'Internal server error: {str(e)}'})
        }
