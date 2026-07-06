provider "aws" {
  region = "us-east-1"
}

# =========================================================================
# S3  — CKV_AWS_18/19/20/21/53/54/55/56/144/145, CKV2_AWS_6/41/61/62
#        Sysdig: S3 bucket public access / encryption / versioning / logging
# =========================================================================
resource "aws_s3_bucket" "bad" {
  bucket = "totally-insecure-bucket-fixture"
  acl    = "public-read"            # public ACL
  # no versioning, no logging, no SSE configured
}

resource "aws_s3_bucket_public_access_block" "bad" {
  bucket                  = aws_s3_bucket.bad.id
  block_public_acls       = false   # all four disabled on purpose
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "bad" {
  bucket = aws_s3_bucket.bad.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"               # world-readable bucket policy
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::totally-insecure-bucket-fixture/*"
    }]
  })
}

# =========================================================================
# IAM admin policy — CKV_AWS_1/62/63/107/108/109/110/111
#        Sysdig: IAM policies allow full admin "*:*"
# =========================================================================
resource "aws_iam_policy" "admin_star" {
  name   = "fixture-admin-star"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"               # full admin
      Resource = "*"
    }]
  })
}

resource "aws_iam_user" "bad" {
  name = "fixture-user"
}

resource "aws_iam_user_policy" "inline_admin" {
  name   = "inline-admin"
  user   = aws_iam_user.bad.name
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}

resource "aws_iam_access_key" "bad" {
  user = aws_iam_user.bad.name      # long-lived access key for a user
}

# IAM password policy — CKV_AWS_9/10/11/12/13/14/15
resource "aws_iam_account_password_policy" "weak" {
  minimum_password_length        = 6      # too short
  require_lowercase_characters   = false
  require_uppercase_characters   = false
  require_numbers                = false
  require_symbols                = false
  allow_users_to_change_password = false
  max_password_age               = 0      # never expires
  password_reuse_prevention      = 0
}

# =========================================================================
# Security Group — CKV_AWS_24/25/260/277, CKV2_AWS_5
#        Sysdig: SG open to 0.0.0.0/0 on SSH/RDP/all ports
# =========================================================================
resource "aws_security_group" "wide_open" {
  name        = "fixture-wide-open"
  description = "intentionally open"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "ALL ports from anywhere"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# =========================================================================
# EC2 + EBS — CKV_AWS_3/8/79/88/126/135
#        Sysdig: IMDSv2 not enforced / EBS not encrypted / public IP
# =========================================================================
resource "aws_instance" "bad" {
  ami                         = "ami-12345678"
  instance_type               = "t3.micro"
  associate_public_ip_address = true     # public IP
  monitoring                  = false    # no detailed monitoring

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"          # IMDSv1 allowed (no v2 enforcement)
  }

  root_block_device {
    encrypted = false                    # unencrypted root volume
  }
}

resource "aws_ebs_volume" "bad" {
  availability_zone = "us-east-1a"
  size              = 8
  encrypted         = false              # unencrypted EBS volume
}

resource "aws_ebs_encryption_by_default" "off" {
  enabled = false                        # account-wide EBS enc disabled
}

# =========================================================================
# RDS instance + cluster — CKV_AWS_16/17/118/129/133/157/161/226/293/353...
#        Sysdig: RDS not encrypted / public / no backups / no deletion prot
# =========================================================================
resource "aws_db_instance" "bad" {
  identifier                      = "fixture-db"
  engine                          = "mysql"
  instance_class                  = "db.t3.micro"
  allocated_storage               = 20
  username                        = "admin"
  password                        = "Password123!"   # hardcoded secret
  storage_encrypted               = false             # not encrypted
  publicly_accessible             = true              # public
  backup_retention_period         = 0                 # no backups
  deletion_protection             = false
  iam_database_authentication_enabled = false
  multi_az                        = false
  auto_minor_version_upgrade      = false
  monitoring_interval             = 0
  skip_final_snapshot             = true
}

resource "aws_rds_cluster" "bad" {
  cluster_identifier              = "fixture-cluster"
  engine                          = "aurora-mysql"
  master_username                 = "admin"
  master_password                 = "Password123!"   # hardcoded secret
  storage_encrypted               = false
  backup_retention_period         = 1
  deletion_protection             = false
  iam_database_authentication_enabled = false
  skip_final_snapshot             = true
}

# =========================================================================
# Redshift — CKV_AWS_64/71/87/105/142
# =========================================================================
resource "aws_redshift_cluster" "bad" {
  cluster_identifier  = "fixture-redshift"
  database_name       = "db"
  master_username     = "admin"
  master_password     = "Password123!"
  node_type           = "dc2.large"
  cluster_type        = "single-node"
  encrypted           = false            # not encrypted
  publicly_accessible = true             # public
  logging {
    enable = false
  }
}

# =========================================================================
# OpenSearch / Elasticsearch — CKV_AWS_5/6/83/84/137/247/317/318
# =========================================================================
resource "aws_opensearch_domain" "bad" {
  domain_name    = "fixture-os"
  engine_version = "OpenSearch_2.5"

  encrypt_at_rest {
    enabled = false                      # at-rest enc off
  }
  node_to_node_encryption {
    enabled = false                      # in-transit enc off
  }
  domain_endpoint_options {
    enforce_https = false                # https not enforced
  }
  # no audit/log publishing options
}

# =========================================================================
# CloudFront — CKV_AWS_34/68/86/174/305/310
# =========================================================================
resource "aws_cloudfront_distribution" "bad" {
  enabled = true

  origin {
    domain_name = "example.com"
    origin_id   = "o1"
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only"
      origin_ssl_protocols   = ["TLSv1"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "o1"
    viewer_protocol_policy = "allow-all"   # allows plain HTTP
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }
  }

  restrictions {
    geo_restriction { restriction_type = "none" }
  }

  viewer_certificate {
    cloudfront_default_certificate = true  # default cert -> weak min TLS
  }
  # no web_acl_id (no WAF), no logging_config
}

# =========================================================================
# ELB / ALB — CKV_AWS_2/91/92/103/131/150
# =========================================================================
resource "aws_lb" "bad" {
  name                       = "fixture-alb"
  internal                   = false
  load_balancer_type         = "application"
  drop_invalid_header_fields = false   # off
  enable_deletion_protection = false
  # no access_logs block
}

resource "aws_lb_listener" "bad_http" {
  load_balancer_arn = aws_lb.bad.arn
  port              = 80
  protocol          = "HTTP"           # plain HTTP listener
  default_action {
    type             = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:000000000000:targetgroup/x/x"
  }
}

# =========================================================================
# Lambda — CKV_AWS_45/50/115/116/117/173/272
# =========================================================================
resource "aws_lambda_function" "bad" {
  function_name = "fixture-fn"
  role          = aws_iam_policy.admin_star.arn
  runtime       = "python3.8"
  handler       = "index.handler"
  filename      = "fn.zip"

  # no tracing_config (X-Ray off)
  # no dead_letter_config
  # no reserved_concurrent_executions
  # no kms_key_arn -> env vars not CMK-encrypted
  environment {
    variables = {
      DB_PASSWORD = "Password123!"     # plaintext secret in env
    }
  }
}

resource "aws_lambda_permission" "public" {
  statement_id  = "AllowPublic"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.bad.function_name
  principal     = "*"                  # publicly invokable
}

# =========================================================================
# CloudTrail — CKV_AWS_35/36/67/252
# =========================================================================
resource "aws_cloudtrail" "bad" {
  name                          = "fixture-trail"
  s3_bucket_name                = aws_s3_bucket.bad.id
  is_multi_region_trail         = false   # single region
  enable_log_file_validation    = false   # no integrity validation
  # no kms_key_id -> logs not encrypted with CMK
}

# =========================================================================
# KMS — CKV_AWS_7/33
# =========================================================================
resource "aws_kms_key" "bad" {
  description         = "fixture key"
  enable_key_rotation = false              # rotation off
}

# =========================================================================
# SNS / SQS — CKV_AWS_26/27
# =========================================================================
resource "aws_sns_topic" "bad" {
  name = "fixture-topic"
  # no kms_master_key_id -> unencrypted
}

resource "aws_sqs_queue" "bad" {
  name = "fixture-queue"
  # no kms_master_key_id -> unencrypted
}

# =========================================================================
# DynamoDB — CKV_AWS_28/119
# =========================================================================
resource "aws_dynamodb_table" "bad" {
  name         = "fixture-table"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  attribute {
    name = "id"
    type = "S"
  }
  point_in_time_recovery {
    enabled = false                       # PITR off
  }
  # no server_side_encryption with CMK
}

# =========================================================================
# EFS / ECR — CKV_AWS_42/51/136/163
# =========================================================================
resource "aws_efs_file_system" "bad" {
  creation_token = "fixture-efs"
  encrypted      = false                  # unencrypted EFS
}

resource "aws_ecr_repository" "bad" {
  name                 = "fixture-repo"
  image_tag_mutability = "MUTABLE"        # mutable tags
  image_scanning_configuration {
    scan_on_push = false                  # no scan
  }
  # no encryption_configuration (CMK)
}

# =========================================================================
# EKS — CKV_AWS_38/39/58/151
# =========================================================================
resource "aws_eks_cluster" "bad" {
  name     = "fixture-eks"
  role_arn = aws_iam_policy.admin_star.arn

  vpc_config {
    endpoint_public_access  = true
    endpoint_private_access = false
    public_access_cidrs     = ["0.0.0.0/0"]  # API open to world
    subnet_ids              = ["subnet-12345678"]
  }
  # no encryption_config (secrets), no enabled_cluster_log_types
}

# =========================================================================
# API Gateway stage — CKV_AWS_73/76/120/225
# =========================================================================
resource "aws_api_gateway_rest_api" "bad" {
  name = "fixture-api"
}

resource "aws_api_gateway_stage" "bad" {
  stage_name    = "prod"
  rest_api_id   = aws_api_gateway_rest_api.bad.id
  deployment_id = "deadbeef"
  xray_tracing_enabled = false            # X-Ray off
  cache_cluster_enabled = false           # -> no cache encryption
  # no access_log_settings, no client_certificate_id, no WAF association
}

# =========================================================================
# WAFv2 — CKV_AWS_192 (and friends)
# =========================================================================
resource "aws_wafv2_web_acl" "bad" {
  name  = "fixture-acl"
  scope = "REGIONAL"
  default_action {
    allow {}
  }
  visibility_config {
    cloudwatch_metrics_enabled = false
    metric_name                = "f"
    sampled_requests_enabled   = false
  }
  # no rules, no logging configuration
}

# =========================================================================
# Neptune — CKV_AWS_166/180
# =========================================================================
resource "aws_neptune_cluster" "bad" {
  cluster_identifier                  = "fixture-neptune"
  storage_encrypted                   = false   # not encrypted
  iam_database_authentication_enabled = false
  # no enable_cloudwatch_logs_exports (audit logs off)
  skip_final_snapshot                 = true
}

# =========================================================================
# SageMaker notebook — CKV_AWS_122 (+ related)
# =========================================================================
resource "aws_sagemaker_notebook_instance" "bad" {
  name                    = "fixture-nb"
  instance_type           = "ml.t2.medium"
  role_arn                = aws_iam_policy.admin_star.arn
  direct_internet_access  = "Enabled"     # direct internet access
  root_access             = "Enabled"     # root access
  # no kms_key_id
}
