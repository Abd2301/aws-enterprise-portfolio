"""
Reverse Payment Lambda Function
Enterprise Order Processing Platform

Saga Compensation: Reverses a processed payment.
Called by Step Functions when a step AFTER payment fails.

Example: Payment succeeds, but inventory reservation fails.
Step Functions catches the error and calls this function
to refund the customer before marking the order as failed.

Compensation functions MUST be idempotent - they might be
called multiple times if Step Functions retries.
"""

import json
import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

dynamodb = boto3.resource("dynamodb")
orders_table = dynamodb.Table(os.environ["ORDERS_TABLE"])
event_store_table = dynamodb.Table(os.environ["EVENT_STORE_TABLE"])


def lambda_handler(event, context):
    """
    Reverse a payment as part of saga compensation.

    Args:
        event: Step Functions error context containing order details
        context: Lambda context

    Returns:
        dict: Compensation result
    """
    try:
        # Step Functions passes the original step's input on failure.
        # We need to handle both direct input and error-wrapped input.
        order_id = event.get("OrderId") or event.get("Cause", {}).get("OrderId")

        if not order_id:
            print(f"Cannot extract OrderId from event: {json.dumps(event)}")
            raise Exception("OrderId not found in compensation event")

        timestamp = datetime.now(timezone.utc).isoformat()

        # Idempotency check: only reverse if payment was actually processed.
        # This makes the compensation safe to retry.
        order = get_order(order_id)
        if not order:
            print(f"Order {order_id} not found, skipping compensation")
            return {"OrderId": order_id, "Status": "SKIPPED"}

        current_status = order.get("OrderStatus", "")
        if current_status in ["PAYMENT_REVERSED", "CREATED", "PAYMENT_FAILED"]:
            print(f"Order {order_id} status is {current_status}, no reversal needed")
            return {"OrderId": order_id, "Status": "ALREADY_COMPENSATED"}

        # Simulate payment reversal
        refund_id = f"REF-{order_id.split('-')[1]}-{context.aws_request_id[:8]}"

        update_order_status(order_id, "PAYMENT_REVERSED", timestamp)

        record_event(order_id, "PaymentReversed", {
            "refund_id": refund_id,
            "original_payment_id": event.get("PaymentId", "unknown"),
            "reason": "Saga compensation - downstream step failed",
        }, timestamp, context)

        return {
            "OrderId": order_id,
            "RefundId": refund_id,
            "Status": "PAYMENT_REVERSED",
        }

    except ClientError as e:
        print(f"DynamoDB error: {e.response['Error']['Message']}")
        raise
    except Exception as e:
        print(f"Payment reversal error: {str(e)}")
        raise


def get_order(order_id):
    """Fetch current order state."""
    try:
        result = orders_table.get_item(Key={"OrderId": order_id})
        return result.get("Item")
    except ClientError:
        return None


def update_order_status(order_id, status, timestamp):
    """Update order status in the write model."""
    orders_table.update_item(
        Key={"OrderId": order_id},
        UpdateExpression="SET OrderStatus = :s, UpdatedAt = :t",
        ExpressionAttributeValues={
            ":s": status,
            ":t": timestamp,
        },
    )


def record_event(order_id, event_type, event_data, timestamp, context):
    """Append immutable event to the event store."""
    event_store_table.put_item(Item={
        "OrderId": order_id,
        "EventTimestamp": timestamp,
        "EventType": event_type,
        "EventData": json.dumps(event_data, default=str),
        "Metadata": {
            "RequestId": context.aws_request_id,
            "FunctionName": context.function_name,
        },
    })