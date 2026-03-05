# ============================================================
# Lambda Module - Input Variables
# ============================================================

variable "project_name" {
  description = "Project identifier for resource naming"
  type        = string
}

variable "environment" {
  description = "Deployment environment"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID for Lambda functions"
  type        = string
}

variable "private_subnet_ids" {
  description = "Subnet IDs for Lambda VPC deployment"
  type        = list(string)
}

# DynamoDB table names - passed from DynamoDB module outputs
variable "orders_table_name" {
  description = "Orders DynamoDB table name"
  type        = string
}

variable "orders_table_arn" {
  description = "Orders DynamoDB table ARN for IAM policy"
  type        = string
}

variable "event_store_table_name" {
  description = "Event store DynamoDB table name"
  type        = string
}

variable "event_store_table_arn" {
  description = "Event store DynamoDB table ARN for IAM policy"
  type        = string
}

variable "idempotency_table_name" {
  description = "Idempotency DynamoDB table name"
  type        = string
}

variable "idempotency_table_arn" {
  description = "Idempotency DynamoDB table ARN for IAM policy"
  type        = string
}

variable "orders_stream_arn" {
  description = "Orders DynamoDB stream ARN for event source mapping"
  type        = string
}   