"""
pulumi/__main__.py  —  INTENTIONALLY INSECURE PULUMI PROGRAM
DO NOT DEPLOY. Test fixture for OX (Pulumi IaC) and Checkov secrets/SAST.

NOTE: Checkov has no native Pulumi IaC framework, so its policy engine will
NOT flag the resource misconfigurations here the way it does for Terraform.
OX *does* scan Pulumi. The hardcoded credentials below should still be caught
by Checkov's secrets scanner regardless.
"""
import json
import pulumi
import pulumi_aws as aws

# Hardcoded credentials (caught by secrets scanners)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_PASSWORD = "Password123!"

# Public, unencrypted S3 bucket
bucket = aws.s3.Bucket(
    "insecurePulumiBucket",
    acl="public-read-write",
)

aws.s3.BucketPublicAccessBlock(
    "insecurePab",
    bucket=bucket.id,
    block_public_acls=False,
    block_public_policy=False,
    ignore_public_acls=False,
    restrict_public_buckets=False,
)

# Security group open to the world on SSH / all
aws.ec2.SecurityGroup(
    "wideOpen",
    description="intentionally open",
    ingress=[
        {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]},
        {"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]},
    ],
    egress=[{"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}],
)

# Unencrypted, public RDS instance with hardcoded password
aws.rds.Instance(
    "badDb",
    engine="mysql",
    instance_class="db.t3.micro",
    allocated_storage=20,
    username="admin",
    password=DB_PASSWORD,
    storage_encrypted=False,
    publicly_accessible=True,
    backup_retention_period=0,
    skip_final_snapshot=True,
)

# IAM policy granting full admin
aws.iam.Policy(
    "adminStar",
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }),
)

pulumi.export("bucket", bucket.id)
