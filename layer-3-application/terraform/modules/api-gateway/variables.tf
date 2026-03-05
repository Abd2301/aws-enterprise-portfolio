# ============================================================
# API Gateway Module - Input Variables
# ============================================================

variable "project_name" {
  description = "Project identifier for resource naming"
  type        = string
}

variable "environment" {
  description = "Deployment environment"
  type        = string
}

# Lambda integration ARNs - passed from Lambda module outputs
variable "create_order_invoke_arn" {
  description = "Create order Lambda invoke ARN"
  type        = string
}

variable "create_order_function_name" {
  description = "Create order Lambda function name"
  type        = string
}

variable "get_order_invoke_arn" {
  description = "Get order Lambda invoke ARN"
  type        = string
}

variable "get_order_function_name" {
  description = "Get order Lambda function name"
  type        = string
}