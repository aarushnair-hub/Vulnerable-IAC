# ============================================================================
#  terragrunt.hcl  —  INTENTIONALLY INSECURE, PLAN-CLEAN TERRAGRUNT FIXTURE
# ----------------------------------------------------------------------------
#  Purpose : Render via Terragrunt -> terraform plan -> plan.json -> Checkov.
#  This version is schema-valid for AWS provider v6 and plans fully OFFLINE
#  (mock creds + skip flags), so `terragrunt plan` produces no errors.
#  DO NOT DEPLOY. Every resource is deliberately misconfigured.
#
#  USAGE (from this folder):
#     export AWS_ACCESS_KEY_ID=mock AWS_SECRET_ACCESS_KEY=mock AWS_DEFAULT_REGION=us-east-1
#     terragrunt init -backend=false
#     terragrunt plan -out=tfplan.bin
#     terragrunt show -json tfplan.bin > plan.json
#     checkov -f plan.json --compact
# ============================================================================

terraform {
  source = "."
}

inputs = {
  environment = "vuln-fixture"
}

generate "bad_resources" {
  path      = "bad_generated.tf"
  if_exists = "overwrite"
  contents  = <<-TFEOF

    # Mock provider so `terraform plan` runs fully offline (no AWS calls)
    provider "aws" {
      region                      = "us-east-1"
      access_key                  = "mock_access_key"
      secret_key                  = "mock_secret_key"
      skip_credentials_validation = true
      skip_requesting_account_id  = true
      skip_metadata_api_check     = true
    }

    # S3 — public / unencrypted / unversioned / no logging
    resource "aws_s3_bucket" "bad" {
      bucket = "totally-insecure-bucket-fixture"
    }

    resource "aws_s3_bucket_public_access_block" "bad" {
      bucket                  = aws_s3_bucket.bad.id
      block_public_acls       = false
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
          Principal = "*"
          Action    = "s3:GetObject"
          Resource  = "arn:aws:s3:::totally-insecure-bucket-fixture/*"
        }]
      })
    }

    # IAM — full admin "*:*"
    resource "aws_iam_policy" "admin_star" {
      name   = "fixture-admin-star"
      policy = jsonencode({
        Version   = "2012-10-17"
        Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
      })
    }

    resource "aws_iam_role" "admin_role" {
      name = "fixture-admin-role"
      assume_role_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [{
          Effect    = "Allow"
          Principal = { Service = "ec2.amazonaws.com" }
          Action    = "sts:AssumeRole"
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
      user = aws_iam_user.bad.name
    }

    resource "aws_iam_account_password_policy" "weak" {
      minimum_password_length        = 6
      require_lowercase_characters   = false
      require_uppercase_characters   = false
      require_numbers                = false
      require_symbols                = false
      allow_users_to_change_password = false
      max_password_age               = 0
      password_reuse_prevention      = 0
    }

    # Security Group — 0.0.0.0/0 on SSH / RDP / all
    resource "aws_security_group" "wide_open" {
      name        = "fixture-wide-open"
      description = "intentionally open"
      ingress {
        from_port   = 22
        to_port     = 22
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
      }
      ingress {
        from_port   = 3389
        to_port     = 3389
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
      }
      ingress {
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

    # EC2 + EBS — IMDSv1, unencrypted, public IP
    resource "aws_instance" "bad" {
      ami                         = "ami-0123456789abcdef0"
      instance_type               = "t3.micro"
      associate_public_ip_address = true
      monitoring                  = false
      metadata_options {
        http_endpoint = "enabled"
        http_tokens   = "optional"
      }
      root_block_device {
        encrypted = false
      }
    }

    resource "aws_ebs_volume" "bad" {
      availability_zone = "us-east-1a"
      size              = 8
      encrypted         = false
    }

    resource "aws_ebs_encryption_by_default" "off" {
      enabled = false
    }

    # RDS instance + cluster — unencrypted, public, no backups, hardcoded creds
    resource "aws_db_instance" "bad" {
      identifier                          = "fixture-db"
      engine                              = "mysql"
      instance_class                      = "db.t3.micro"
      allocated_storage                   = 20
      username                            = "admin"
      password                            = "Password123!"
      storage_encrypted                   = false
      publicly_accessible                 = true
      backup_retention_period             = 0
      deletion_protection                 = false
      iam_database_authentication_enabled = false
      multi_az                            = false
      auto_minor_version_upgrade          = false
      monitoring_interval                 = 0
      skip_final_snapshot                 = true
    }

    resource "aws_rds_cluster" "bad" {
      cluster_identifier                  = "fixture-cluster"
      engine                              = "aurora-mysql"
      master_username                     = "admin"
      master_password                     = "Password123!"
      storage_encrypted                   = false
      backup_retention_period             = 1
      deletion_protection                 = false
      iam_database_authentication_enabled = false
      skip_final_snapshot                 = true
    }

    # Redshift — unencrypted, public  (logging block removed: not valid in v6)
    resource "aws_redshift_cluster" "bad" {
      cluster_identifier  = "fixture-redshift"
      database_name       = "db"
      master_username     = "admin"
      master_password     = "Password123!"
      node_type           = "dc2.large"
      cluster_type        = "single-node"
      encrypted           = false
      publicly_accessible = true
      skip_final_snapshot = true
    }

    # OpenSearch — no at-rest / in-transit enc, https not enforced
    resource "aws_opensearch_domain" "bad" {
      domain_name    = "fixture-os"
      engine_version = "OpenSearch_2.5"
      encrypt_at_rest {
        enabled = false
      }
      node_to_node_encryption {
        enabled = false
      }
      domain_endpoint_options {
        enforce_https = false
      }
    }

    # CloudFront — HTTP, weak TLS, no WAF, no logging
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
        viewer_protocol_policy = "allow-all"
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
        cloudfront_default_certificate = true
      }
    }

    # ALB — HTTP listener, no logs, no deletion protection  (subnets added)
    resource "aws_lb" "bad" {
      name                       = "fixture-alb"
      internal                   = false
      load_balancer_type         = "application"
      drop_invalid_header_fields = false
      enable_deletion_protection = false
      subnets                    = ["subnet-0123456789abcdef0", "subnet-0123456789abcdef1"]
    }

    resource "aws_lb_target_group" "bad" {
      name        = "fixture-tg"
      port        = 80
      protocol    = "HTTP"
      target_type = "ip"
      vpc_id      = "vpc-0123456789abcdef0"
    }

    resource "aws_lb_listener" "bad_http" {
      load_balancer_arn = aws_lb.bad.arn
      port              = 80
      protocol          = "HTTP"
      default_action {
        type             = "forward"
        target_group_arn = aws_lb_target_group.bad.arn
      }
    }

    # Lambda — no tracing/DLQ/CMK, public invoke, plaintext secret
    # (s3 source instead of local filename so plan needs no local zip)
    resource "aws_lambda_function" "bad" {
      function_name = "fixture-fn"
      role          = aws_iam_role.admin_role.arn
      runtime       = "python3.8"
      handler       = "index.handler"
      s3_bucket     = "fixtures-bucket"
      s3_key        = "fn.zip"
      environment {
        variables = {
          DB_PASSWORD = "Password123!"
        }
      }
    }

    resource "aws_lambda_permission" "public" {
      statement_id  = "AllowPublic"
      action        = "lambda:InvokeFunction"
      function_name = aws_lambda_function.bad.function_name
      principal     = "*"
    }

    # CloudTrail — single region, no validation, no CMK
    resource "aws_cloudtrail" "bad" {
      name                       = "fixture-trail"
      s3_bucket_name             = aws_s3_bucket.bad.id
      is_multi_region_trail      = false
      enable_log_file_validation = false
    }

    # KMS — rotation off
    resource "aws_kms_key" "bad" {
      description         = "fixture key"
      enable_key_rotation = false
    }

    # SNS / SQS — unencrypted
    resource "aws_sns_topic" "bad" {
      name = "fixture-topic"
    }

    resource "aws_sqs_queue" "bad" {
      name = "fixture-queue"
    }

    # DynamoDB — no PITR, no CMK
    resource "aws_dynamodb_table" "bad" {
      name         = "fixture-table"
      billing_mode = "PAY_PER_REQUEST"
      hash_key     = "id"
      attribute {
        name = "id"
        type = "S"
      }
      point_in_time_recovery {
        enabled = false
      }
    }

    # EFS / ECR — unencrypted, mutable tags, no scan
    resource "aws_efs_file_system" "bad" {
      creation_token = "fixture-efs"
      encrypted      = false
    }

    resource "aws_ecr_repository" "bad" {
      name                 = "fixture-repo"
      image_tag_mutability = "MUTABLE"
      image_scanning_configuration {
        scan_on_push = false
      }
    }

    # EKS — public API to 0.0.0.0/0, no secrets enc / logging
    resource "aws_eks_cluster" "bad" {
      name     = "fixture-eks"
      role_arn = aws_iam_role.admin_role.arn
      vpc_config {
        endpoint_public_access  = true
        endpoint_private_access = false
        public_access_cidrs     = ["0.0.0.0/0"]
        subnet_ids              = ["subnet-0123456789abcdef0", "subnet-0123456789abcdef1"]
      }
    }

    # API Gateway stage — no X-Ray / logs / WAF / client cert
    resource "aws_api_gateway_rest_api" "bad" {
      name = "fixture-api"
    }

    resource "aws_api_gateway_resource" "bad" {
      rest_api_id = aws_api_gateway_rest_api.bad.id
      parent_id   = aws_api_gateway_rest_api.bad.root_resource_id
      path_part   = "x"
    }

    resource "aws_api_gateway_method" "bad" {
      rest_api_id   = aws_api_gateway_rest_api.bad.id
      resource_id   = aws_api_gateway_resource.bad.id
      http_method   = "GET"
      authorization = "NONE"
    }

    resource "aws_api_gateway_integration" "bad" {
      rest_api_id = aws_api_gateway_rest_api.bad.id
      resource_id = aws_api_gateway_resource.bad.id
      http_method = aws_api_gateway_method.bad.http_method
      type        = "MOCK"
    }

    resource "aws_api_gateway_deployment" "bad" {
      rest_api_id = aws_api_gateway_rest_api.bad.id
      depends_on  = [aws_api_gateway_integration.bad]
    }

    resource "aws_api_gateway_stage" "bad" {
      stage_name            = "prod"
      rest_api_id           = aws_api_gateway_rest_api.bad.id
      deployment_id         = aws_api_gateway_deployment.bad.id
      xray_tracing_enabled  = false
      cache_cluster_enabled = false
    }

    # WAFv2 — no rules, no logging
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
    }

    # Neptune — unencrypted, no audit logs
    resource "aws_neptune_cluster" "bad" {
      cluster_identifier                  = "fixture-neptune"
      storage_encrypted                   = false
      iam_database_authentication_enabled = false
      skip_final_snapshot                 = true
    }

    # SageMaker — direct internet + root access, no CMK
    resource "aws_sagemaker_notebook_instance" "bad" {
      name                   = "fixture-nb"
      instance_type          = "ml.t2.medium"
      role_arn               = aws_iam_role.admin_role.arn
      direct_internet_access = "Enabled"
      root_access            = "Enabled"
    }

  TFEOF
}
