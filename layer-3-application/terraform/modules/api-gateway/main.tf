# ============================================================
# API Gateway HTTP API for Enterprise Order Processing Platform
#
# HTTP API (v2) chosen over REST API (v1) because:
#   - 71% lower cost ($1 vs $3.50 per million requests)
#   - Lower latency (single-digit ms overhead)
#   - Simpler configuration for Lambda proxy integration
#   - Sufficient for this use case (no need for REST API
#     features like request transformation or caching)
#
# This is an architectural decision interviewers ask about:
# "Why HTTP API over REST API?"
# ============================================================

# --- HTTP API ---
resource "aws_apigatewayv2_api" "orders" {
  name          = "${var.project_name}-api-${var.environment}"
  protocol_type = "HTTP"
  description   = "Enterprise Order Processing API"

  # CORS configuration - allows browser applications to call the API.
  # In production, you'd restrict allowed_origins to your domain.
  cors_configuration {
    allow_origins = ["*"]
    allow_methods = ["GET", "POST", "OPTIONS"]
    allow_headers = ["Content-Type", "X-Idempotency-Key", "Authorization"]
    max_age       = 3600
  }

  tags = {
    Component = "API"
  }
}

# --- Stage ---
# Stages represent deployment environments (dev, staging, prod).
# Auto-deploy means every route change deploys immediately.
# In production, you'd disable auto_deploy and use CI/CD.
resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.orders.id
  name        = "$default"
  auto_deploy = true

  # Access logging - every API request gets logged.
  # This feeds into CloudWatch for monitoring and debugging.
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gateway.arn
    format = jsonencode({
      requestId        = "$context.requestId"
      ip               = "$context.identity.sourceIp"
      requestTime      = "$context.requestTime"
      httpMethod       = "$context.httpMethod"
      routeKey         = "$context.routeKey"
      status           = "$context.status"
      protocol         = "$context.protocol"
      responseLength   = "$context.responseLength"
      integrationError = "$context.integrationErrorMessage"
      errorMessage     = "$context.error.message"
    })
  }

  tags = {
    Component = "API"
  }
}

# --- CloudWatch Log Group for API Gateway ---
resource "aws_cloudwatch_log_group" "api_gateway" {
  name              = "/aws/apigateway/${var.project_name}-api-${var.environment}"
  retention_in_days = 14

  tags = {
    Component = "Observability"
  }
}

# --- Lambda Integrations ---
# Each integration connects an API route to a Lambda function.
# AWS_PROXY means API Gateway passes the entire HTTP request
# to Lambda and returns Lambda's response directly to the client.
# No request/response transformation — Lambda handles everything.

resource "aws_apigatewayv2_integration" "create_order" {
  api_id                 = aws_apigatewayv2_api.orders.id
  integration_type       = "AWS_PROXY"
  integration_uri        = var.create_order_invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_integration" "get_order" {
  api_id                 = aws_apigatewayv2_api.orders.id
  integration_type       = "AWS_PROXY"
  integration_uri        = var.get_order_invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

# --- Routes ---
# Routes map HTTP method + path to Lambda integrations.
# {orderId} is a path parameter - API Gateway extracts it
# and passes it in event.pathParameters.

resource "aws_apigatewayv2_route" "create_order" {
  api_id    = aws_apigatewayv2_api.orders.id
  route_key = "POST /orders"
  target    = "integrations/${aws_apigatewayv2_integration.create_order.id}"
}

resource "aws_apigatewayv2_route" "get_order" {
  api_id    = aws_apigatewayv2_api.orders.id
  route_key = "GET /orders/{orderId}"
  target    = "integrations/${aws_apigatewayv2_integration.get_order.id}"
}

resource "aws_apigatewayv2_route" "list_customer_orders" {
  api_id    = aws_apigatewayv2_api.orders.id
  route_key = "GET /orders"
  target    = "integrations/${aws_apigatewayv2_integration.get_order.id}"
}

# --- Lambda Permissions ---
# API Gateway needs explicit permission to invoke Lambda functions.
# Without this, API Gateway gets "Access Denied" when calling Lambda.
# This is a common gotcha that trips people up.

resource "aws_lambda_permission" "create_order" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.create_order_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.orders.execution_arn}/*/*"
}

resource "aws_lambda_permission" "get_order" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.get_order_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.orders.execution_arn}/*/*"
}