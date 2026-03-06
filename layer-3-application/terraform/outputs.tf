# ============================================================
# Outputs display useful information after terraform apply.
# Think of these as return values - they show you what was
# created and provide values needed by other systems.
# ============================================================

# Outputs will be added as we create resources



# --- DynamoDB ---
output "orders_table_name" {
  description = "Orders DynamoDB table name"
  value       = module.dynamodb.orders_table_name
}

output "event_store_table_name" {
  description = "Event store DynamoDB table name"
  value       = module.dynamodb.event_store_table_name
}

output "idempotency_table_name" {
  description = "Idempotency DynamoDB table name"
  value       = module.dynamodb.idempotency_table_name
}

# --- API Gateway ---
output "api_endpoint" {
  description = "API Gateway endpoint URL"
  value       = module.api_gateway.api_endpoint
}

# --- Step Functions ---
output "state_machine_arn" {
  description = "Order saga state machine ARN"
  value       = module.step_functions.state_machine_arn
} # CI/CD Pipeline Active




