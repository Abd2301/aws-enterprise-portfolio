# ============================================================
# Lambda Functions for Enterprise Order Processing Platform
#
# Components:
#   1. IAM execution role with least-privilege policies
#   2. Security group for VPC-deployed Lambda functions
#   3. Lambda functions for order processing + saga steps
#
# All functions deploy into Production VPC private subnets,
# connecting Layer 3 (application) to Layer 2 (network).
# ============================================================

# --- Data Sources ---
# Data sources READ existing AWS resources without managing them.
# We need the VPC CIDR for security group rules.

data "aws_vpc" "production" {
  id = var.vpc_id
}

# --- IAM Execution Role ---
# Every Lambda function needs an IAM role that defines what
# AWS services it can access. One role shared across functions
# in this module - in production you might create per-function
# roles for tighter least-privilege.

# Trust policy: "Who can assume this role?"
# Answer: Only the Lambda service.
data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "lambda_execution" {
  name               = "${var.project_name}-lambda-role-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  tags = {
    Component = "Compute"
  }
}

# Permission policy: "What can this role do?"
# Follows least-privilege - only the specific tables and actions needed.
data "aws_iam_policy_document" "lambda_permissions" {
  # DynamoDB permissions - scoped to our specific tables only
  statement {
    sid    = "DynamoDBAccess"
    effect = "Allow"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:Query",
      "dynamodb:Scan",
    ]
    resources = [
      var.orders_table_arn,
      "${var.orders_table_arn}/index/*",
      var.event_store_table_arn,
      "${var.event_store_table_arn}/index/*",
      var.idempotency_table_arn,
    ]
  }

  # DynamoDB Streams - read-only access for CQRS consumers
  statement {
    sid    = "DynamoDBStreams"
    effect = "Allow"
    actions = [
      "dynamodb:DescribeStream",
      "dynamodb:GetRecords",
      "dynamodb:GetShardIterator",
      "dynamodb:ListStreams",
    ]
    resources = [
      "${var.orders_table_arn}/stream/*",
    ]
  }

  # CloudWatch Logs - Lambda needs to write its own logs
  statement {
    sid    = "CloudWatchLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }

  # VPC networking - Lambda needs ENI management to run in VPC
  statement {
    sid    = "VPCAccess"
    effect = "Allow"
    actions = [
      "ec2:CreateNetworkInterface",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DeleteNetworkInterface",
    ]
    resources = ["*"]
  }

  # X-Ray tracing - for distributed tracing in Session 6
  statement {
    sid    = "XRayTracing"
    effect = "Allow"
    actions = [
      "xray:PutTraceSegments",
      "xray:PutTelemetryRecords",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "lambda_permissions" {
  name   = "${var.project_name}-lambda-policy-${var.environment}"
  role   = aws_iam_role.lambda_execution.id
  policy = data.aws_iam_policy_document.lambda_permissions.json
}

# --- Security Group ---
# Controls what network traffic Lambda functions can send/receive.
# Lambda in VPC needs outbound access to DynamoDB (via VPC endpoint
# or NAT Gateway) and other AWS services.

resource "aws_security_group" "lambda" {
  name        = "${var.project_name}-lambda-sg-${var.environment}"
  description = "Security group for Lambda functions in Production VPC"
  vpc_id      = var.vpc_id

  # Outbound: Allow all - Lambda needs to reach DynamoDB, CloudWatch,
  # X-Ray, and other AWS services. In production, you'd restrict this
  # to specific VPC endpoints and CIDR ranges.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound for AWS service access"
  }

  tags = {
    Name      = "${var.project_name}-lambda-sg-${var.environment}"
    Component = "Compute"
  }
}

# --- Lambda Function Packaging ---
# Terraform's archive_file creates a zip from source code.
# Each function gets its own zip for independent deployment.

data "archive_file" "create_order" {
  type        = "zip"
  source_file = "${path.module}/src/create_order.py"
  output_path = "${path.module}/build/create_order.zip"
}

data "archive_file" "get_order" {
  type        = "zip"
  source_file = "${path.module}/src/get_order.py"
  output_path = "${path.module}/build/get_order.zip"
}

data "archive_file" "process_payment" {
  type        = "zip"
  source_file = "${path.module}/src/process_payment.py"
  output_path = "${path.module}/build/process_payment.zip"
}

data "archive_file" "reserve_inventory" {
  type        = "zip"
  source_file = "${path.module}/src/reserve_inventory.py"
  output_path = "${path.module}/build/reserve_inventory.zip"
}

data "archive_file" "initiate_fulfillment" {
  type        = "zip"
  source_file = "${path.module}/src/initiate_fulfillment.py"
  output_path = "${path.module}/build/initiate_fulfillment.zip"
}

data "archive_file" "reverse_payment" {
  type        = "zip"
  source_file = "${path.module}/src/reverse_payment.py"
  output_path = "${path.module}/build/reverse_payment.zip"
}

data "archive_file" "release_inventory" {
  type        = "zip"
  source_file = "${path.module}/src/release_inventory.py"
  output_path = "${path.module}/build/release_inventory.zip"
}

# --- Lambda Functions ---
# Each function deploys into Production VPC private subnets.
# Environment variables connect functions to DynamoDB tables.
# source_code_hash triggers redeployment when code changes.

resource "aws_lambda_function" "create_order" {
  function_name    = "${var.project_name}-create-order-${var.environment}"
  role             = aws_iam_role.lambda_execution.arn
  handler          = "create_order.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 256
  filename         = data.archive_file.create_order.output_path
  source_code_hash = data.archive_file.create_order.output_base64sha256

  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      ORDERS_TABLE      = var.orders_table_name
      EVENT_STORE_TABLE = var.event_store_table_name
      IDEMPOTENCY_TABLE = var.idempotency_table_name
      ENVIRONMENT       = var.environment
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = {
    Component = "Compute"
    Function  = "CreateOrder"
  }
}

resource "aws_lambda_function" "get_order" {
  function_name    = "${var.project_name}-get-order-${var.environment}"
  role             = aws_iam_role.lambda_execution.arn
  handler          = "get_order.lambda_handler"
  runtime          = "python3.12"
  timeout          = 15
  memory_size      = 256
  filename         = data.archive_file.get_order.output_path
  source_code_hash = data.archive_file.get_order.output_base64sha256

  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      ORDERS_TABLE = var.orders_table_name
      ENVIRONMENT  = var.environment
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = {
    Component = "Compute"
    Function  = "GetOrder"
  }
}

resource "aws_lambda_function" "process_payment" {
  function_name    = "${var.project_name}-process-payment-${var.environment}"
  role             = aws_iam_role.lambda_execution.arn
  handler          = "process_payment.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 256
  filename         = data.archive_file.process_payment.output_path
  source_code_hash = data.archive_file.process_payment.output_base64sha256

  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      ORDERS_TABLE      = var.orders_table_name
      EVENT_STORE_TABLE = var.event_store_table_name
      ENVIRONMENT       = var.environment
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = {
    Component = "Compute"
    Function  = "ProcessPayment"
    Pattern   = "SagaStep"
  }
}

resource "aws_lambda_function" "reserve_inventory" {
  function_name    = "${var.project_name}-reserve-inventory-${var.environment}"
  role             = aws_iam_role.lambda_execution.arn
  handler          = "reserve_inventory.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 256
  filename         = data.archive_file.reserve_inventory.output_path
  source_code_hash = data.archive_file.reserve_inventory.output_base64sha256

  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      ORDERS_TABLE      = var.orders_table_name
      EVENT_STORE_TABLE = var.event_store_table_name
      ENVIRONMENT       = var.environment
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = {
    Component = "Compute"
    Function  = "ReserveInventory"
    Pattern   = "SagaStep"
  }
}

resource "aws_lambda_function" "initiate_fulfillment" {
  function_name    = "${var.project_name}-initiate-fulfillment-${var.environment}"
  role             = aws_iam_role.lambda_execution.arn
  handler          = "initiate_fulfillment.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 256
  filename         = data.archive_file.initiate_fulfillment.output_path
  source_code_hash = data.archive_file.initiate_fulfillment.output_base64sha256

  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      ORDERS_TABLE      = var.orders_table_name
      EVENT_STORE_TABLE = var.event_store_table_name
      ENVIRONMENT       = var.environment
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = {
    Component = "Compute"
    Function  = "InitiateFulfillment"
    Pattern   = "SagaStep"
  }
}

resource "aws_lambda_function" "reverse_payment" {
  function_name    = "${var.project_name}-reverse-payment-${var.environment}"
  role             = aws_iam_role.lambda_execution.arn
  handler          = "reverse_payment.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 256
  filename         = data.archive_file.reverse_payment.output_path
  source_code_hash = data.archive_file.reverse_payment.output_base64sha256

  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      ORDERS_TABLE      = var.orders_table_name
      EVENT_STORE_TABLE = var.event_store_table_name
      ENVIRONMENT       = var.environment
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = {
    Component = "Compute"
    Function  = "ReversePayment"
    Pattern   = "SagaCompensation"
  }
}

resource "aws_lambda_function" "release_inventory" {
  function_name    = "${var.project_name}-release-inventory-${var.environment}"
  role             = aws_iam_role.lambda_execution.arn
  handler          = "release_inventory.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 256
  filename         = data.archive_file.release_inventory.output_path
  source_code_hash = data.archive_file.release_inventory.output_base64sha256

  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      ORDERS_TABLE      = var.orders_table_name
      EVENT_STORE_TABLE = var.event_store_table_name
      ENVIRONMENT       = var.environment
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = {
    Component = "Compute"
    Function  = "ReleaseInventory"
    Pattern   = "SagaCompensation"
  }
}

# --- CloudWatch Log Groups ---
# Explicitly create log groups so Terraform manages retention.
# Without this, Lambda auto-creates them with infinite retention
# which wastes money and violates compliance policies.

resource "aws_cloudwatch_log_group" "create_order" {
  name              = "/aws/lambda/${aws_lambda_function.create_order.function_name}"
  retention_in_days = 14
  tags = { Component = "Observability" }
}

resource "aws_cloudwatch_log_group" "get_order" {
  name              = "/aws/lambda/${aws_lambda_function.get_order.function_name}"
  retention_in_days = 14
  tags = { Component = "Observability" }
}

resource "aws_cloudwatch_log_group" "process_payment" {
  name              = "/aws/lambda/${aws_lambda_function.process_payment.function_name}"
  retention_in_days = 14
  tags = { Component = "Observability" }
}

resource "aws_cloudwatch_log_group" "reserve_inventory" {
  name              = "/aws/lambda/${aws_lambda_function.reserve_inventory.function_name}"
  retention_in_days = 14
  tags = { Component = "Observability" }
}

resource "aws_cloudwatch_log_group" "initiate_fulfillment" {
  name              = "/aws/lambda/${aws_lambda_function.initiate_fulfillment.function_name}"
  retention_in_days = 14
  tags = { Component = "Observability" }
}

resource "aws_cloudwatch_log_group" "reverse_payment" {
  name              = "/aws/lambda/${aws_lambda_function.reverse_payment.function_name}"
  retention_in_days = 14
  tags = { Component = "Observability" }
}

resource "aws_cloudwatch_log_group" "release_inventory" {
  name              = "/aws/lambda/${aws_lambda_function.release_inventory.function_name}"
  retention_in_days = 14
  tags = { Component = "Observability" }
}

data "aws_route_tables" "private" {
  vpc_id = var.vpc_id

  filter {
    name   = "association.subnet-id"
    values = var.private_subnet_ids
  }
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.us-east-1.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = data.aws_route_tables.private.ids

  tags = {
    Name      = "${var.project_name}-dynamodb-endpoint-${var.environment}"
    Component = "Network"
  }
}