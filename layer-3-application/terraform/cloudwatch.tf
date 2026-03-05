# ============================================================
# CloudWatch Dashboard and Alarms
# Observability layer spanning all modules
#
# Dashboard provides single-pane-of-glass view for:
#   - API Gateway request rates and errors
#   - Lambda execution metrics
#   - DynamoDB read/write capacity
#   - Step Functions execution status
#   - SQS queue depth
# ============================================================

# --- CloudWatch Dashboard ---
resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${var.project_name}-dashboard-${var.environment}"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "text"
        x      = 0
        y      = 0
        width  = 24
        height = 1
        properties = {
          markdown = "# Enterprise Order Processing - Production Dashboard"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 1
        width  = 8
        height = 6
        properties = {
          title   = "API Gateway Requests"
          region  = var.aws_region
          metrics = [
            ["AWS/ApiGateway", "Count", "ApiId", module.api_gateway.api_id, { stat = "Sum", period = 60 }]
          ]
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 1
        width  = 8
        height = 6
        properties = {
          title   = "API Gateway Latency (ms)"
          region  = var.aws_region
          metrics = [
            ["AWS/ApiGateway", "Latency", "ApiId", module.api_gateway.api_id, { stat = "Average", period = 60 }],
            ["AWS/ApiGateway", "Latency", "ApiId", module.api_gateway.api_id, { stat = "p99", period = 60 }]
          ]
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 1
        width  = 8
        height = 6
        properties = {
          title   = "API Gateway 4xx/5xx Errors"
          region  = var.aws_region
          metrics = [
            ["AWS/ApiGateway", "4xx", "ApiId", module.api_gateway.api_id, { stat = "Sum", period = 60, color = "#ff9900" }],
            ["AWS/ApiGateway", "5xx", "ApiId", module.api_gateway.api_id, { stat = "Sum", period = 60, color = "#d13212" }]
          ]
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 7
        width  = 12
        height = 6
        properties = {
          title   = "Lambda Invocations"
          region  = var.aws_region
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", "${var.project_name}-create-order-${var.environment}", { stat = "Sum", period = 60 }],
            ["AWS/Lambda", "Invocations", "FunctionName", "${var.project_name}-get-order-${var.environment}", { stat = "Sum", period = 60 }],
            ["AWS/Lambda", "Invocations", "FunctionName", "${var.project_name}-process-payment-${var.environment}", { stat = "Sum", period = 60 }],
            ["AWS/Lambda", "Invocations", "FunctionName", "${var.project_name}-stream-consumer-${var.environment}", { stat = "Sum", period = 60 }]
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 7
        width  = 12
        height = 6
        properties = {
          title   = "Lambda Errors"
          region  = var.aws_region
          metrics = [
            ["AWS/Lambda", "Errors", "FunctionName", "${var.project_name}-create-order-${var.environment}", { stat = "Sum", period = 60 }],
            ["AWS/Lambda", "Errors", "FunctionName", "${var.project_name}-process-payment-${var.environment}", { stat = "Sum", period = 60 }],
            ["AWS/Lambda", "Errors", "FunctionName", "${var.project_name}-reserve-inventory-${var.environment}", { stat = "Sum", period = 60 }],
            ["AWS/Lambda", "Errors", "FunctionName", "${var.project_name}-initiate-fulfillment-${var.environment}", { stat = "Sum", period = 60 }]
          ]
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 13
        width  = 8
        height = 6
        properties = {
          title   = "Step Functions Executions"
          region  = var.aws_region
          metrics = [
            ["AWS/States", "ExecutionsStarted", "StateMachineArn", module.step_functions.state_machine_arn, { stat = "Sum", period = 60, color = "#2ca02c" }],
            ["AWS/States", "ExecutionsSucceeded", "StateMachineArn", module.step_functions.state_machine_arn, { stat = "Sum", period = 60, color = "#1f77b4" }],
            ["AWS/States", "ExecutionsFailed", "StateMachineArn", module.step_functions.state_machine_arn, { stat = "Sum", period = 60, color = "#d13212" }]
          ]
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 13
        width  = 8
        height = 6
        properties = {
          title   = "DynamoDB Read/Write"
          region  = var.aws_region
          metrics = [
            ["AWS/DynamoDB", "ConsumedReadCapacityUnits", "TableName", module.dynamodb.orders_table_name, { stat = "Sum", period = 60 }],
            ["AWS/DynamoDB", "ConsumedWriteCapacityUnits", "TableName", module.dynamodb.orders_table_name, { stat = "Sum", period = 60 }]
          ]
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 13
        width  = 8
        height = 6
        properties = {
          title   = "SQS Queue Depth"
          region  = var.aws_region
          metrics = [
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", "${var.project_name}-order-analytics-${var.environment}", { stat = "Average", period = 60 }],
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", "${var.project_name}-order-analytics-dlq-${var.environment}", { stat = "Average", period = 60, color = "#d13212" }]
          ]
        }
      }
    ]
  })
}

# --- CloudWatch Alarms ---

# Alarm: High API error rate
resource "aws_cloudwatch_metric_alarm" "api_5xx_errors" {
  alarm_name          = "${var.project_name}-api-5xx-errors-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "5xx"
  namespace           = "AWS/ApiGateway"
  period              = 60
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "API Gateway 5xx errors exceeded threshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    ApiId = module.api_gateway.api_id
  }

  tags = {
    Component = "Observability"
  }
}

# Alarm: Step Functions failures
resource "aws_cloudwatch_metric_alarm" "saga_failures" {
  alarm_name          = "${var.project_name}-saga-failures-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ExecutionsFailed"
  namespace           = "AWS/States"
  period              = 300
  statistic           = "Sum"
  threshold           = 3
  alarm_description   = "Order saga failures exceeded threshold - check compensation"
  treat_missing_data  = "notBreaching"

  dimensions = {
    StateMachineArn = module.step_functions.state_machine_arn
  }

  tags = {
    Component = "Observability"
  }
}

# Alarm: DLQ messages (poison messages need investigation)
resource "aws_cloudwatch_metric_alarm" "dlq_messages" {
  alarm_name          = "${var.project_name}-dlq-messages-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Dead letter queue has messages - failed event processing needs investigation"
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = "${var.project_name}-order-analytics-dlq-${var.environment}"
  }

  tags = {
    Component = "Observability"
  }
}