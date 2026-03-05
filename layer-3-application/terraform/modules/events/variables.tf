# ============================================================
# Events Module - Input Variables
# ============================================================

variable "project_name" {
  description = "Project identifier for resource naming"
  type        = string
}

variable "environment" {
  description = "Deployment environment"
  type        = string
}

variable "orders_stream_arn" {
  description = "DynamoDB Orders table stream ARN for CQRS"
  type        = string
}

variable "lambda_execution_role_arn" {
  description = "Lambda execution role ARN for stream consumer"
  type        = string
}