# ============================================================
# Step Functions State Machine for Order Processing Saga
#
# This is the orchestration layer. Step Functions manages:
#   - Execution order of saga steps
#   - Error handling and retry logic
#   - Compensation (rollback) on failures
#   - Execution history for debugging
#
# Standard Workflow chosen over Express because:
#   - Exactly-once execution (Express is at-least-once)
#   - Execution history retained for 90 days
#   - Visual debugging in console
#   - Runs up to 1 year (Express limited to 5 minutes)
#   - Order processing is low-volume, high-value — 
#     we want reliability over throughput
# ============================================================

# --- IAM Role for Step Functions ---
# Step Functions needs permission to invoke Lambda functions.
# The trust policy says "only Step Functions can assume this role."

data "aws_iam_policy_document" "sfn_assume_role" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "sfn_execution" {
  name               = "${var.project_name}-sfn-role-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.sfn_assume_role.json

  tags = {
    Component = "Orchestration"
  }
}

# Permission policy: Step Functions can invoke our saga Lambda functions
data "aws_iam_policy_document" "sfn_permissions" {
  # Invoke Lambda functions for saga steps and compensation
  statement {
    sid    = "InvokeLambda"
    effect = "Allow"
    actions = [
      "lambda:InvokeFunction",
    ]
    resources = [
      var.process_payment_arn,
      var.reserve_inventory_arn,
      var.initiate_fulfillment_arn,
      var.reverse_payment_arn,
      var.release_inventory_arn,
    ]
  }

  # CloudWatch Logs for execution logging
  statement {
    sid    = "CloudWatchLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogDelivery",
      "logs:CreateLogStream",
      "logs:GetLogDelivery",
      "logs:UpdateLogDelivery",
      "logs:DeleteLogDelivery",
      "logs:ListLogDeliveries",
      "logs:PutLogEvents",
      "logs:PutResourcePolicy",
      "logs:DescribeResourcePolicies",
      "logs:DescribeLogGroups",
    ]
    resources = ["*"]
  }

  # X-Ray tracing
  statement {
    sid    = "XRayTracing"
    effect = "Allow"
    actions = [
      "xray:PutTraceSegments",
      "xray:PutTelemetryRecords",
      "xray:GetSamplingRules",
      "xray:GetSamplingTargets",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "sfn_permissions" {
  name   = "${var.project_name}-sfn-policy-${var.environment}"
  role   = aws_iam_role.sfn_execution.id
  policy = data.aws_iam_policy_document.sfn_permissions.json
}

# --- CloudWatch Log Group for Step Functions ---
resource "aws_cloudwatch_log_group" "sfn" {
  name              = "/aws/stepfunctions/${var.project_name}-order-saga-${var.environment}"
  retention_in_days = 14

  tags = {
    Component = "Observability"
  }
}

# --- State Machine ---
# templatefile() reads the ASL JSON and replaces ${var} placeholders
# with actual Lambda ARNs. This keeps the state machine definition
# readable as a standalone JSON file while injecting Terraform values.

resource "aws_sfn_state_machine" "order_saga" {
  name     = "${var.project_name}-order-saga-${var.environment}"
  role_arn = aws_iam_role.sfn_execution.arn

  definition = templatefile("${path.module}/order_saga.json", {
    process_payment_arn     = var.process_payment_arn
    reserve_inventory_arn   = var.reserve_inventory_arn
    initiate_fulfillment_arn = var.initiate_fulfillment_arn
    reverse_payment_arn     = var.reverse_payment_arn
    release_inventory_arn   = var.release_inventory_arn
  })

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.sfn.arn}:*"
    include_execution_data = true
    level                  = "ALL"
  }

  tracing_configuration {
    enabled = true
  }

  tags = {
    Component = "Orchestration"
    Pattern   = "Saga"
  }
}