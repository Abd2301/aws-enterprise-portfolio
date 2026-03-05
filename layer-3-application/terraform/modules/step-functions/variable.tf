# ============================================================
# Step Functions Module - Input Variables
#
# This module needs Lambda function ARNs to invoke saga steps.
# Step Functions calls Lambda directly using the function ARN,
# unlike API Gateway which uses the invoke ARN.
# ============================================================

variable "project_name" {
  description = "Project identifier for resource naming"
  type        = string
}

variable "environment" {
  description = "Deployment environment"
  type        = string
}

# --- Saga Step Function ARNs ---
variable "process_payment_arn" {
  description = "Process payment Lambda ARN"
  type        = string
}

variable "reserve_inventory_arn" {
  description = "Reserve inventory Lambda ARN"
  type        = string
}

variable "initiate_fulfillment_arn" {
  description = "Initiate fulfillment Lambda ARN"
  type        = string
}

# --- Saga Compensation Function ARNs ---
variable "reverse_payment_arn" {
  description = "Reverse payment Lambda ARN"
  type        = string
}

variable "release_inventory_arn" {
  description = "Release inventory Lambda ARN"
  type        = string
}