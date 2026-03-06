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
  }
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile != null ? var.aws_profile : null
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

# --- API Layer ---
module "api_gateway" {
  source = "./modules/api-gateway"

  project_name = var.project_name
  environment  = var.environment

  create_order_invoke_arn    = module.lambda.create_order_invoke_arn
  create_order_function_name = module.lambda.create_order_function_name
  get_order_invoke_arn       = module.lambda.get_order_invoke_arn
  get_order_function_name    = module.lambda.get_order_function_name
}


# --- Orchestration Layer ---
module "step_functions" {
  source = "./modules/step-functions"

  project_name = var.project_name
  environment  = var.environment

  # Wire Lambda ARNs for saga steps
  process_payment_arn     = module.lambda.process_payment_arn
  reserve_inventory_arn   = module.lambda.reserve_inventory_arn
  initiate_fulfillment_arn = module.lambda.initiate_fulfillment_arn

  # Wire Lambda ARNs for compensation
  reverse_payment_arn     = module.lambda.reverse_payment_arn
  release_inventory_arn   = module.lambda.release_inventory_arn
}

# --- Event-Driven Layer ---
module "events" {
  source = "./modules/events"

  project_name             = var.project_name
  environment              = var.environment
  orders_stream_arn        = module.dynamodb.orders_stream_arn
  lambda_execution_role_arn = module.lambda.lambda_execution_role_arn
}