# ============================================================
# Enterprise Order Processing Platform - Terraform Configuration
# Layer 3 of Enterprise AWS Foundation
# ============================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket         = "enterprise-terraform-state-574337396853"
    key            = "layer-3/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "enterprise-terraform-locks"
    encrypt        = true
    profile        = "default"
  }
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile

  default_tags {
    tags = {
      Project     = "Enterprise-AWS-Foundation"
      Layer       = "3-Application"
      Environment = "Production"
      ManagedBy   = "Terraform"
      Owner       = "Abdul"
    }
  }
}

module "dynamodb" {
  source = "./modules/dynamodb"

  project_name = var.project_name
  environment  = var.environment
}

# --- Compute Layer ---
module "lambda" {
  source = "./modules/lambda"

  project_name       = var.project_name
  environment        = var.environment
  vpc_id             = var.vpc_id
  private_subnet_ids = var.private_subnet_ids

  # Wire DynamoDB module outputs into Lambda module inputs
  orders_table_name      = module.dynamodb.orders_table_name
  orders_table_arn       = module.dynamodb.orders_table_arn
  orders_stream_arn      = module.dynamodb.orders_stream_arn
  event_store_table_name = module.dynamodb.event_store_table_name
  event_store_table_arn  = module.dynamodb.event_store_table_arn
  idempotency_table_name = module.dynamodb.idempotency_table_name
  idempotency_table_arn  = module.dynamodb.idempotency_table_arn
}