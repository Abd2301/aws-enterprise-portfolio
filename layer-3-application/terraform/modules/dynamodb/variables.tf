# ============================================================
# DynamoDB Module - Input Variables
# These define what the module needs from the caller.
# ============================================================

variable "project_name" {
  description = "Project identifier for resource naming"
  type        = string
}

variable "environment" {
  description = "Deployment environment (production, development)"
  type        = string
}