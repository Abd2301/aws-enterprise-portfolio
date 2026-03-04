# ============================================================
# DynamoDB Module - Outputs
# These values flow back to the root module and get passed
# into other modules (Lambda needs ARNs for IAM, names for
# environment variables).
# ============================================================

# --- Orders Table ---
output "orders_table_name" {
  description = "Orders table name for Lambda environment variables"
  value       = aws_dynamodb_table.orders.name
}

output "orders_table_arn" {
  description = "Orders table ARN for IAM policies"
  value       = aws_dynamodb_table.orders.arn
}

output "orders_stream_arn" {
  description = "Orders table stream ARN for Lambda event source mapping"
  value       = aws_dynamodb_table.orders.stream_arn
}

# --- Event Store Table ---
output "event_store_table_name" {
  description = "Event store table name for Lambda environment variables"
  value       = aws_dynamodb_table.event_store.name
}

output "event_store_table_arn" {
  description = "Event store table ARN for IAM policies"
  value       = aws_dynamodb_table.event_store.arn
}

# --- Idempotency Table ---
output "idempotency_table_name" {
  description = "Idempotency table name for Lambda environment variables"
  value       = aws_dynamodb_table.idempotency.name
}

output "idempotency_table_arn" {
  description = "Idempotency table ARN for IAM policies"
  value       = aws_dynamodb_table.idempotency.arn
}