# ============================================================
# Events Module - Outputs
# ============================================================

output "event_bus_name" {
  description = "Custom EventBridge bus name"
  value       = aws_cloudwatch_event_bus.orders.name
}

output "event_bus_arn" {
  description = "Custom EventBridge bus ARN"
  value       = aws_cloudwatch_event_bus.orders.arn
}

output "analytics_queue_url" {
  description = "SQS analytics queue URL"
  value       = aws_sqs_queue.order_analytics.url
}

output "notification_topic_arn" {
  description = "SNS notification topic ARN"
  value       = aws_sns_topic.order_notifications.arn
}