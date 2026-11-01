"""Bounded read plans and encrypted local archives for development AWS observations."""
import hashlib
import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ACCOUNT = "653464153304"
REGION = "us-east-2"
BUCKETS = ("dissertation-research-653464153304-us-east-2-logs", "dissertation-653464153304-us-east-2-state")
RULES = ("dissertation-research-public-access-blocks", "dissertation-research-tls-required")
READER_PREFIX = f"arn:aws:sts::{ACCOUNT}:assumed-role/dissertation-evidence-reader/"


# Missing optional S3 configurations are observations, never proof of compliance.
OPTIONAL_ABSENCE_CODES = {
    "get_bucket_policy": {"NoSuchBucketPolicy"},
    "get_public_access_block": {"NoSuchPublicAccessBlockConfiguration"},
    "get_bucket_encryption": {"ServerSideEncryptionConfigurationNotFoundError"},
    "get_bucket_ownership_controls": {"OwnershipControlsNotFoundError"},
}


def verify_identity(identity):
    """Reject every principal except the dedicated research reader role.

    Inputs:
        identity: STS GetCallerIdentity response.
    Outputs:
        None: Raises ValueError for a wrong account, root, user or other role.
    """
    if identity.get("Account") != ACCOUNT or not identity.get("Arn", "").startswith(READER_PREFIX):
        raise ValueError("Dedicated evidence-reader role in the expected account is required")


def read_plan(bucket):
    """Describe a fixed development snapshot without discovering unrelated resources.

    Inputs:
        bucket: One of the two reviewed research bucket names.
    Outputs:
        list[dict]: Ordered read requests; the first two are ownership/scope guards.
    """
    if bucket not in BUCKETS:
        raise ValueError("Bucket is outside the reviewed scope")
    owner = {"Bucket": bucket, "ExpectedBucketOwner": ACCOUNT}
    operations = ["get_bucket_location", "get_bucket_tagging", "get_public_access_block", "get_bucket_versioning", "get_bucket_policy", "get_bucket_policy_status", "get_bucket_encryption", "get_bucket_ownership_controls"]
    plan = [{"service": "s3", "operation": operation, "params": dict(owner), "paginated": False} for operation in operations]
    # Retain recorder health alongside evaluations so absent monitoring is visible.
    for operation in ("describe_configuration_recorders", "describe_configuration_recorder_status", "describe_delivery_channels"):
        scope_key = "DeliveryChannelNames" if operation == "describe_delivery_channels" else "ConfigurationRecorderNames"
        plan.append({"service": "config", "operation": operation, "params": {scope_key: ["dissertation-research"]}, "paginated": False})
    for rule in RULES:
        plan.append({"service": "config", "operation": "get_compliance_details_by_config_rule", "params": {"ConfigRuleName": rule}, "paginated": True})
    filters = {key: [{"Value": value, "Comparison": "EQUALS"}] for key, value in {
        "AwsAccountId": ACCOUNT, "Region": REGION, "ProductName": "Security Hub", "RecordState": "ACTIVE", "ResourceId": f"arn:aws:s3:::{bucket}", "ResourceType": "AwsS3Bucket"}.items()}
    filters["ComplianceSecurityControlId"] = [{"Value": control, "Comparison": "EQUALS"} for control in ("S3.5", "S3.8")]
    plan.extend([
        {"service": "securityhub", "operation": "describe_hub", "params": {}, "paginated": False},
        {"service": "securityhub", "operation": "get_enabled_standards", "params": {}, "paginated": True},
        {"service": "securityhub", "operation": "get_findings", "params": {"Filters": filters}, "paginated": True},
        {"service": "cloudtrail", "operation": "get_trail_status", "params": {"Name": f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/dissertation-research"}, "paginated": False},
    ])
    return plan


def check_scope(operation, response):
    """Validate location and project ownership before reading resource evidence.

    Inputs:
        operation: Completed S3 guard operation name.
        response: Its successful AWS response.
    Outputs:
        None: Raises ValueError when the Ohio/project guard fails.
    """
    if operation == "get_bucket_location" and response.get("LocationConstraint") != REGION:
        raise ValueError("Bucket is outside the reviewed region")
    if operation == "get_bucket_tagging":
        tags = {tag["Key"]: tag["Value"] for tag in response.get("TagSet", [])}
        if tags.get("Project") != "aws-ai-compliance-dissertation":
            raise ValueError("Research project tag is required")


def json_default(value):
    """Preserve timezone-aware AWS timestamps without silently stringifying objects.

    Inputs:
        value: Non-JSON value encountered by the serializer.
    Outputs:
        str: UTC ISO timestamp; unsupported values raise TypeError.
    """
    if isinstance(value, datetime) and value.tzinfo is not None:
        return value.astimezone(timezone.utc).isoformat()
    raise TypeError("Unsupported or timezone-naive evidence value")


def sync_archive_directory(directory):
    """Ask the OS to synchronize an archive directory entry before reporting persistence.

    Inputs:
        directory: Existing local directory whose entries were created by the archive writer.
    Outputs:
        None: Opens, fsyncs and closes a directory descriptor. Filesystem errors propagate;
            this is not a guarantee against hardware loss or unsupported storage semantics.
    """
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class EncryptedArchive:
    """Write only CMS-encrypted evidence using a public recipient certificate."""

    def __init__(self, root, certificate, openssl=None, timeout_seconds=None):
        """Validate encryption prerequisites and reserve a new private output directory.

        Inputs:
            self: Archive instance receiving validated public-recipient and filesystem settings.
            root: New directory path; existing paths are rejected.
            certificate: Public RSA recipient certificate path, never a private key.
            openssl: Optional OpenSSL 3 executable path.
            timeout_seconds: Optional integer 1..300 local crypto deadline; None preserves legacy behavior.
        Outputs:
            None: Creates a mode-700 directory and synchronized public certificate copy after
                validation. Persistence failures propagate and leave partial output for review.
        """
        if timeout_seconds is not None and (type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 300):
            raise ValueError("Bounded integer crypto timeout required")
        self.timeout_seconds = timeout_seconds
        self.binary = openssl or ("/opt/homebrew/opt/openssl@3/bin/openssl" if Path("/opt/homebrew/opt/openssl@3/bin/openssl").exists() else shutil.which("openssl"))
        version = subprocess.run([self.binary, "version"], check=True, capture_output=True, timeout=self.timeout_seconds).stdout.decode()
        if not re.match(r"OpenSSL [3-9]\.", version):
            raise ValueError("OpenSSL 3 or newer is required")
        public = Path(certificate).read_bytes()
        if b"PRIVATE KEY" in public:
            raise ValueError("Supply only a public certificate, never a private key")
        # Normalize the certificate so extra input text cannot enter the plaintext copy.
        public = subprocess.run([self.binary, "x509", "-outform", "PEM"], input=public, check=True, capture_output=True, timeout=self.timeout_seconds).stdout
        subprocess.run([self.binary, "x509", "-checkend", "0", "-noout"], input=public, check=True, capture_output=True, timeout=self.timeout_seconds)
        key = subprocess.run([self.binary, "x509", "-pubkey", "-noout"], input=public, check=True, capture_output=True, timeout=self.timeout_seconds).stdout
        details = subprocess.run([self.binary, "pkey", "-pubin", "-text", "-noout"], input=key, check=True, capture_output=True, timeout=self.timeout_seconds).stdout.decode()
        bits = re.search(r"Public-Key: \((\d+) bit\)", details)
        if not bits or int(bits.group(1)) < 3072 or "Modulus:" not in details:
            raise ValueError("RSA recipient key must have at least 3072 bits")
        self.root = Path(root)
        self.root.mkdir(mode=0o700, parents=False, exist_ok=False)
        self.cert = self.root / "recipient-public.pem"
        with self.cert.open("xb") as stream:
            self.cert.chmod(0o600)
            stream.write(public)
            stream.flush()
            os.fsync(stream.fileno())
        # Retain the public-recipient entry and the new archive directory before use.
        sync_archive_directory(self.root)
        sync_archive_directory(self.root.parent)
        self.receipts = []

    def write(self, value):
        """Encrypt one record and acknowledge it only after local synchronization succeeds.

        Inputs:
            self: Initialized archive instance with an exclusive output directory.
            value: JSON-compatible evidence envelope, including any raw responses.
        Outputs:
            dict: Ciphertext filename/hash receipt after file and directory fsync succeeds.
                Writes a mode-600 CMS file; appends no receipt on synchronization failure.
                Partial ciphertext remains exclusive and blocks silent overwrite/retry.
        """
        plaintext = json.dumps(value, default=json_default, sort_keys=True).encode()
        # Authenticated content encryption protects raw evidence even on unencrypted disks.
        encrypted = subprocess.run([self.binary, "cms", "-encrypt", "-binary", "-aes-256-gcm", "-outform", "DER", "-recip", str(self.cert), "-keyopt", "rsa_padding_mode:oaep", "-keyopt", "rsa_oaep_md:sha256"], input=plaintext, check=True, capture_output=True, timeout=self.timeout_seconds).stdout
        name = f"record-{len(self.receipts):05d}.cms"
        with (self.root / name).open("xb") as stream:
            (self.root / name).chmod(0o600)
            stream.write(encrypted)
            stream.flush()
            os.fsync(stream.fileno())
        # A persisted file without a persisted filename is not yet an acknowledged record.
        sync_archive_directory(self.root)
        receipt = {"file": name, "ciphertext_sha256": hashlib.sha256(encrypted).hexdigest()}
        self.receipts.append(receipt)
        return receipt
