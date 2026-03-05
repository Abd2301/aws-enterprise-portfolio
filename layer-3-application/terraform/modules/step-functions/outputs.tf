# ============================================================
# Step Functions Module - Outputs
# ============================================================

output "state_machine_arn" {
  description = "Order saga state machine ARN for triggering executions"
  value       = aws_sfn_state_machine.order_saga.arn
}

output "state_machine_name" {
  description = "Order saga state machine name"
  value       = aws_sfn_state_machine.order_saga.name
}

output "sfn_execution_role_arn" {
  description = "Step Functions execution role ARN"
  value       = aws_iam_role.sfn_execution.arn
}