# ============================================================
# Event-Driven Architecture for Order Processing
#
# Flow: DynamoDB Stream → Lambda → EventBridge → SQS/SNS
#
# This implements the "event backbone" pattern. Every order
# state change automatically triggers downstream consumers.
# Adding new consumers (analytics, ML, audit) requires only
# a new EventBridge rule - zero changes to existing code.
# That's the power of event-driven architecture.
# ============================================================

# --- EventBridge Custom Event Bus ---
# Custom bus separates our application events from AWS service
# events on the default bus. This is an enterprise pattern:
# each domain (orders, payments, shipping) gets its own bus.

resource "aws_cloudwatch_event_bus" "orders" {
  name = "${var.project_name}-order-events-${var.environment}"

  tags = {
    Component = "Events"
  }
}

# --- SQS Queue: Analytics Consumer ---
# Buffers order events for analytics processing.
# If the analytics consumer goes down, messages wait here
# instead of being lost. That's decoupling.

resource "aws_sqs_queue" "order_analytics" {
  name                       = "${var.project_name}-order-analytics-${var.environment}"
  message_retention_seconds  = 86400          # 24 hours
  visibility_timeout_seconds = 60             # Consumer has 60s to process
  receive_wait_time_seconds  = 20             # Long polling - reduces empty API calls

  tags = {
    Component = "Events"
    Consumer  = "Analytics"
  }
}

# Dead-letter queue: catches messages that fail processing repeatedly.
# Without a DLQ, poison messages block the queue forever.
# With a DLQ, they move here after 3 failures for investigation.
resource "aws_sqs_queue" "order_analytics_dlq" {
  name                      = "${var.project_name}-order-analytics-dlq-${var.environment}"
  message_retention_seconds = 604800          # 7 days - gives ops team time to investigate

  tags = {
    Component = "Events"
    Consumer  = "Analytics-DLQ"
  }
}

# Wire the DLQ to the main queue
resource "aws_sqs_queue_redrive_policy" "order_analytics" {
  queue_url = aws_sqs_queue.order_analytics.id
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.order_analytics_dlq.arn
    maxReceiveCount     = 3      # After 3 failed attempts, move to DLQ
  })
}

# --- SNS Topic: Order Notifications ---
# Fan-out notifications when orders complete or fail.
# Multiple subscribers can receive the same notification:
# email to customer, Slack to ops team, Lambda for automation.

resource "aws_sns_topic" "order_notifications" {
  name = "${var.project_name}-order-notifications-${var.environment}"

  tags = {
    Component = "Events"
  }
}

# --- EventBridge Rules ---
# Rules match events by pattern and route to targets.
# Each rule is like an "if-then": if event matches pattern,
# send to these targets.

# Rule 1: ALL order events → SQS for analytics
resource "aws_cloudwatch_event_rule" "all_order_events" {
  name           = "${var.project_name}-all-order-events-${var.environment}"
  event_bus_name = aws_cloudwatch_event_bus.orders.name
  description    = "Route all order events to analytics queue"

  event_pattern = jsonencode({
    source      = ["enterprise.orders"]
    detail-type = ["OrderStateChange"]
  })

  tags = {
    Component = "Events"
  }
}

# Rule 2: Only FULFILLED and FAILED orders → SNS for notifications
resource "aws_cloudwatch_event_rule" "order_completed" {
  name           = "${var.project_name}-order-completed-${var.environment}"
  event_bus_name = aws_cloudwatch_event_bus.orders.name
  description    = "Notify on order fulfillment or failure"

  event_pattern = jsonencode({
    source      = ["enterprise.orders"]
    detail-type = ["OrderStateChange"]
    detail = {
      newStatus = ["FULFILLED", "PAYMENT_FAILED", "INVENTORY_FAILED", "FULFILLMENT_FAILED"]
    }
  })

  tags = {
    Component = "Events"
  }
}

# --- EventBridge Targets ---
# Connect rules to destinations

# SQS policy: allow EventBridge to send messages to the queue
resource "aws_sqs_queue_policy" "allow_eventbridge" {
  queue_url = aws_sqs_queue.order_analytics.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowEventBridge"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.order_analytics.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.all_order_events.arn
          }
        }
      }
    ]
  })
}

resource "aws_cloudwatch_event_target" "analytics_queue" {
  rule           = aws_cloudwatch_event_rule.all_order_events.name
  event_bus_name = aws_cloudwatch_event_bus.orders.name
  target_id      = "analytics-sqs"
  arn            = aws_sqs_queue.order_analytics.arn
}

# SNS policy: allow EventBridge to publish to the topic
resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.order_notifications.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowEventBridge"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.order_notifications.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.order_completed.arn
          }
        }
      }
    ]
  })
}

resource "aws_cloudwatch_event_target" "notification_topic" {
  rule           = aws_cloudwatch_event_rule.order_completed.name
  event_bus_name = aws_cloudwatch_event_bus.orders.name
  target_id      = "notification-sns"
  arn            = aws_sns_topic.order_notifications.arn
}

# --- DynamoDB Stream Consumer ---
# This Lambda reads the Orders table stream and publishes
# events to EventBridge. It's the bridge between the data
# layer and the event layer.

data "archive_file" "stream_consumer" {
  type        = "zip"
  source_file = "${path.module}/src/stream_consumer.py"
  output_path = "${path.module}/build/stream_consumer.zip"
}

resource "aws_lambda_function" "stream_consumer" {
  function_name    = "${var.project_name}-stream-consumer-${var.environment}"
  role             = var.lambda_execution_role_arn
  handler          = "stream_consumer.lambda_handler"
  runtime          = "python3.12"
  timeout          = 60
  memory_size      = 256
  filename         = data.archive_file.stream_consumer.output_path
  source_code_hash = data.archive_file.stream_consumer.output_base64sha256

  environment {
    variables = {
      EVENT_BUS_NAME = aws_cloudwatch_event_bus.orders.name
      ENVIRONMENT    = var.environment
    }
  }

  tags = {
    Component = "Events"
    Function  = "StreamConsumer"
  }
}

resource "aws_cloudwatch_log_group" "stream_consumer" {
  name              = "/aws/lambda/${aws_lambda_function.stream_consumer.function_name}"
  retention_in_days = 14
  tags = { Component = "Observability" }
}

# Connect DynamoDB Stream to Lambda
# batch_size = 10 means Lambda receives up to 10 stream records per invocation.
# starting_position = LATEST means only process new changes, not replay history.
resource "aws_lambda_event_source_mapping" "orders_stream" {
  event_source_arn  = var.orders_stream_arn
  function_name     = aws_lambda_function.stream_consumer.arn
  starting_position = "LATEST"
  batch_size        = 10

  # If stream processing fails, don't block the entire stream.
  # Retry twice then skip. Failed records go to error handling.
  maximum_retry_attempts = 2
}