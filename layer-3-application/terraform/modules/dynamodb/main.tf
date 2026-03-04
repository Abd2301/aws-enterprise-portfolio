# ============================================================
# DynamoDB Tables for Enterprise Order Processing Platform
#
# Three tables serve distinct architectural purposes:
#   1. Orders       - CQRS write model (current order state)
#   2. EventStore   - Event sourcing (immutable event log)
#   3. Idempotency  - Duplicate request prevention
# ============================================================

# --- Orders Table (CQRS Write Model) ---
resource "aws_dynamodb_table" "orders" {
  name         = "${var.project_name}-orders-${var.environment}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "OrderId"

  attribute {
    name = "OrderId"
    type = "S"
  }

  attribute {
    name = "CustomerId"
    type = "S"
  }

  attribute {
    name = "OrderStatus"
    type = "S"
  }

  attribute {
    name = "CreatedAt"
    type = "S"
  }

  global_secondary_index {
    name            = "CustomerIndex"
    hash_key        = "CustomerId"
    range_key       = "CreatedAt"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "StatusIndex"
    hash_key        = "OrderStatus"
    range_key       = "CreatedAt"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }

  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  tags = {
    Component = "DataLayer"
    Pattern   = "CQRS-WriteModel"
  }
}

# --- Event Store Table (Event Sourcing) ---
resource "aws_dynamodb_table" "event_store" {
  name         = "${var.project_name}-event-store-${var.environment}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "OrderId"
  range_key    = "EventTimestamp"

  attribute {
    name = "OrderId"
    type = "S"
  }

  attribute {
    name = "EventTimestamp"
    type = "S"
  }

  attribute {
    name = "EventType"
    type = "S"
  }

  global_secondary_index {
    name            = "EventTypeIndex"
    hash_key        = "EventType"
    range_key       = "EventTimestamp"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Component = "DataLayer"
    Pattern   = "EventSourcing"
  }
}

# --- Idempotency Table ---
resource "aws_dynamodb_table" "idempotency" {
  name         = "${var.project_name}-idempotency-${var.environment}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "IdempotencyKey"

  attribute {
    name = "IdempotencyKey"
    type = "S"
  }

  ttl {
    attribute_name = "ExpiresAt"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Component = "DataLayer"
    Pattern   = "Idempotency"
  }
}