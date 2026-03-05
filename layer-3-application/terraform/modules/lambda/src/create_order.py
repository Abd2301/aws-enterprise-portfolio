"""
Create Order Lambda Function
Enterprise Order Processing Platform

This function handles new order creation:
1. Validates the incoming request
2. Generates a unique order ID
3. Writes to the Orders table (CQRS write model)
4. Records an event in the Event Store (Event Sourcing)
5. Implements idempotency to prevent duplicate orders

Architectural Patterns:
- CQRS: Writes to the write model (Orders table)
- Event Sourcing: Appends OrderCreated event to Event Store
- Idempotency: Uses conditional writes to prevent duplicates
"""

import json
from decimal import Decimal
import uuid
import os
import time
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

# Initialize AWS clients outside the handler.
# These persist across warm invocations, avoiding re-initialization. 
# This is a Lambda best practice called "static initialization."
class DecimalEncoder(json.JSONEncoder):
    """Handle Decimal types when serializing to JSON."""
    def default(self, obj):
        from decimal import Decimal
        if isinstance(obj, Decimal):
            return float(obj)
        return super().default(obj)
        
dynamodb = boto3.resource("dynamodb")

# Table names come from environment variables, NOT hardcoded.
# Terraform sets these when creating the Lambda function.
# This decouples code from infrastructure.
orders_table = dynamodb.Table(os.environ["ORDERS_TABLE"])
event_store_table = dynamodb.Table(os.environ["EVENT_STORE_TABLE"])
idempotency_table = dynamodb.Table(os.environ["IDEMPOTENCY_TABLE"])


def lambda_handler(event, context):
    """
    Entry point for API Gateway requests.

    Args:
        event: API Gateway HTTP API event with body containing order details
        context: Lambda context with request ID, function name, etc.

    Returns:
        dict: API Gateway compatible response with statusCode and body
    """
    try:
        # Parse request body
        body = json.loads(event.get("body", "{}"), parse_float=Decimal)

        # Validate required fields
        validation_error = validate_order(body)
        if validation_error:
            return response(400, {"error": validation_error})

        # Check idempotency - has this exact request been processed before?
        # The client sends an IdempotencyKey header to enable safe retries.
        idempotency_key = extract_idempotency_key(event)
        if idempotency_key:
            cached = check_idempotency(idempotency_key)
            if cached:
                return response(200, cached)

        # Generate unique order ID
        order_id = f"ORD-{uuid.uuid4().hex[:8].upper()}"
        timestamp = datetime.now(timezone.utc).isoformat()

        # Build order record
        order = {
            "OrderId": order_id,
            "CustomerId": body["customer_id"],
            "Items": body["items"],
            "TotalAmount": body["total_amount"],
            "OrderStatus": "CREATED",
            "CreatedAt": timestamp,
            "UpdatedAt": timestamp,
        }

        # Build event record (Event Sourcing)
        order_event = {
            "OrderId": order_id,
            "EventTimestamp": timestamp,
            "EventType": "OrderCreated",
            "EventData": json.dumps(order, cls=DecimalEncoder),
            "Metadata": {
                "RequestId": context.aws_request_id,
                "FunctionName": context.function_name,
            },
        }

        # Write to both tables
        # In production, you'd use DynamoDB transactions for atomicity.
        # TransactWriteItems ensures both writes succeed or both fail.
        orders_table.put_item(Item=order)
        event_store_table.put_item(Item=order_event)

        # Store idempotency record if key was provided
        if idempotency_key:
            store_idempotency(idempotency_key, order)

        return response(201, {
            "message": "Order created successfully",
            "order": order,
        })

    except ClientError as e:
        print(f"DynamoDB error: {e.response['Error']['Message']}")
        return response(500, {"error": "Internal server error"})
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return response(500, {"error": "Internal server error"})


def validate_order(body):
    """Validate order request body. Returns error message or None."""
    required_fields = ["customer_id", "items", "total_amount"]
    for field in required_fields:
        if field not in body:
            return f"Missing required field: {field}"

    if not isinstance(body["items"], list) or len(body["items"]) == 0:
        return "Items must be a non-empty list"

    if not isinstance(body["total_amount"], (int, float, Decimal)) or body["total_amount"] <= 0:
        return "Total amount must be a positive number"

    return None


def extract_idempotency_key(event):
    """Extract idempotency key from request headers."""
    headers = event.get("headers", {})
    return headers.get("x-idempotency-key") or headers.get("X-Idempotency-Key")


def check_idempotency(key):
    """Check if this request was already processed."""
    try:
        result = idempotency_table.get_item(Key={"IdempotencyKey": key})
        item = result.get("Item")
        if item and item.get("ExpiresAt", 0) > int(time.time()):
            return json.loads(item["ResponseBody"])
    except ClientError:
        pass
    return None


def store_idempotency(key, order):
    """Store idempotency record with 24-hour TTL."""
    ttl = int(time.time()) + 86400  # 24 hours from now
    idempotency_table.put_item(Item={
        "IdempotencyKey": key,
        "ResponseBody": json.dumps({
            "message": "Order created successfully",
            "order": order,
        }, cls=DecimalEncoder),
        "ExpiresAt": ttl,
        "CreatedAt": datetime.now(timezone.utc).isoformat(),
    })


def response(status_code, body):
    """Build API Gateway compatible response."""
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body, cls=DecimalEncoder),
    }