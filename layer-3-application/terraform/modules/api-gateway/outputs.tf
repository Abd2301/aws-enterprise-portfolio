# ============================================================
# API Gateway Module - Outputs
# ============================================================

output "api_endpoint" {
  description = "API Gateway endpoint URL - use this to call your API"
  value       = aws_apigatewayv2_api.orders.api_endpoint
}

output "api_id" {
  description = "API Gateway ID"
  value       = aws_apigatewayv2_api.orders.id
}

output "api_execution_arn" {
  description = "API Gateway execution ARN for permissions"
  value       = aws_apigatewayv2_api.orders.execution_arn
}