# ============================================================
# Lambda Module - Outputs
# API Gateway needs invoke ARNs for integrations.
# Step Functions needs function ARNs for task states.
# ============================================================

# --- API Functions ---
output "create_order_function_name" {
  description = "Create order function name"
  value       = aws_lambda_function.create_order.function_name
}

output "create_order_invoke_arn" {
  description = "Create order invoke ARN for API Gateway"
  value       = aws_lambda_function.create_order.invoke_arn
}

output "create_order_arn" {
  description = "Create order function ARN for Step Functions"
  value       = aws_lambda_function.create_order.arn
}

output "get_order_function_name" {
  description = "Get order function name"
  value       = aws_lambda_function.get_order.function_name
}

output "get_order_invoke_arn" {
  description = "Get order invoke ARN for API Gateway"
  value       = aws_lambda_function.get_order.invoke_arn
}

# --- Saga Step Functions ---
output "process_payment_arn" {
  description = "Process payment function ARN for Step Functions"
  value       = aws_lambda_function.process_payment.arn
}

output "reserve_inventory_arn" {
  description = "Reserve inventory function ARN for Step Functions"
  value       = aws_lambda_function.reserve_inventory.arn
}

output "initiate_fulfillment_arn" {
  description = "Initiate fulfillment function ARN for Step Functions"
  value       = aws_lambda_function.initiate_fulfillment.arn
}

# --- Saga Compensation Functions ---
output "reverse_payment_arn" {
  description = "Reverse payment function ARN for Step Functions"
  value       = aws_lambda_function.reverse_payment.arn
}

output "release_inventory_arn" {
  description = "Release inventory function ARN for Step Functions"
  value       = aws_lambda_function.release_inventory.arn
}

# --- Security Group ---
output "lambda_security_group_id" {
  description = "Lambda security group ID for network rules"
  value       = aws_security_group.lambda.id
}       

# --- IAM Role ---
output "lambda_execution_role_arn" {
  description = "Lambda execution role ARN"
  value       = aws_iam_role.lambda_execution.arn
}