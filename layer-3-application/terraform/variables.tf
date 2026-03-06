# ============================================================
# Variables define the INTERFACE of your Terraform configuration.
# Think of these like function parameters - they make your code
# reusable across environments (dev, staging, prod).
# ============================================================

# --- General Configuration ---

variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "AWS CLI profile for authentication"
  type        = string
  default     = null
}

variable "project_name" {
  description = "Project identifier used in resource naming"
  type        = string
  default     = "enterprise-order"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "production"
}

# --- Network Configuration (from Layer 2) ---
# These reference existing infrastructure that Terraform
# does NOT manage. We just need the IDs to deploy Lambda
# functions into the right VPC/subnets later.

variable "vpc_id" {
  description = "Production VPC ID from Layer 2"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private application subnet IDs for Lambda deployment"
  type        = list(string)
}

variable "aws_account_id" {
  description = "Production AWS account ID"
  type        = string
}