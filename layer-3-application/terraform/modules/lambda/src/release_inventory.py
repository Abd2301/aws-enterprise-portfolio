"""
Release Inventory Lambda Function
Enterprise Order Processing Platform

Saga Compensation: Releases previously reserved inventory.
Called by Step Functions when fulfillment fails after
inventory was already reserved.

Compensation chain on fulfillment failure:
1. release_inventory (this function) - undo step 2
2. reverse_payment - undo step 1

Like all compensation functions, this MUST be idempotent.
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
    Release inventory reservations as part of saga compensation.

    Args:
        event: Step Functions error context containing order details
        context: Lambda context

    Returns:
        dict: Compensation result passed to next compensation step
    """
    try:
        order_id = event.get("OrderId") or event.get("Cause", {}).get("OrderId")

        if not order_id:
            print(f"Cannot extract OrderId from event: {json.dumps(event)}")
            raise Exception("OrderId not found in compensation event")

        timestamp = datetime.now(timezone.utc).isoformat()

        # Idempotency: only release if inventory was actually reserved
        order = get_order(order_id)
        if not order:
            print(f"Order {order_id} not found, skipping compensation")
            return {"OrderId": order_id, "Status": "SKIPPED"}

        current_status = order.get("OrderStatus", "")
        if current_status in ["INVENTORY_RELEASED", "CREATED", "PAYMENT_PROCESSED"]:
            print(f"Order {order_id} status is {current_status}, no release needed")
            return {"OrderId": order_id, "Status": "ALREADY_COMPENSATED"}

        # Simulate releasing reserved inventory
        reservations = event.get("Reservations", [])

        update_order_status(order_id, "INVENTORY_RELEASED", timestamp)

        record_event(order_id, "InventoryReleased", {
            "reservations_released": reservations,
            "reason": "Saga compensation - downstream step failed",
        }, timestamp, context)

        # Pass order details to next compensation step (reverse_payment)
        return {
            "OrderId": order_id,
            "PaymentId": event.get("PaymentId"),
            "Status": "INVENTORY_RELEASED",
        }

    except ClientError as e:
        print(f"DynamoDB error: {e.response['Error']['Message']}")
        raise
    except Exception as e:
        print(f"Inventory release error: {str(e)}")
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

