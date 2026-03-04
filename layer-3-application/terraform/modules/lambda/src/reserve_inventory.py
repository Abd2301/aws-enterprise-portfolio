"""
Reserve Inventory Lambda Function
Enterprise Order Processing Platform

Saga Step 2: Reserves inventory for order items.
Called by Step Functions after successful payment.

If this step fails, the saga must compensate by:
1. Calling reverse_payment (undo step 1)

If a LATER step fails, the saga calls release_inventory
to undo this step.
"""

import json
import os
import random
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

dynamodb = boto3.resource("dynamodb")
orders_table = dynamodb.Table(os.environ["ORDERS_TABLE"])
event_store_table = dynamodb.Table(os.environ["EVENT_STORE_TABLE"])


def lambda_handler(event, context):
    """
    Reserve inventory for each item in the order.

    Args:
        event: Output from process_payment step
        context: Lambda context

    Returns:
        dict: Reservation result passed to fulfillment step
    """
    try:
        order_id = event["OrderId"]
        items = event.get("Items", [])
        timestamp = datetime.now(timezone.utc).isoformat()

        # Simulate inventory check and reservation
        # 95% success - failure triggers compensation of payment
        inventory_available = random.random() < 0.95

        if not inventory_available:
            record_event(order_id, "InventoryReservationFailed", {
                "reason": "Insufficient stock for one or more items",
                "items": items,
            }, timestamp, context)

            update_order_status(order_id, "INVENTORY_FAILED", timestamp)

            raise Exception(f"Inventory reservation failed for order {order_id}")

        # Generate reservation references for each item
        reservations = []
        for i, item in enumerate(items):
            reservations.append({
                "item_id": item.get("item_id", f"ITEM-{i}"),
                "quantity": item.get("quantity", 1),
                "reservation_id": f"RES-{order_id.split('-')[1]}-{i}",
            })

        update_order_status(order_id, "INVENTORY_RESERVED", timestamp)

        record_event(order_id, "InventoryReserved", {
            "reservations": reservations,
            "item_count": len(reservations),
        }, timestamp, context)

        # Pass everything forward to fulfillment step
        return {
            "OrderId": order_id,
            "PaymentId": event.get("PaymentId"),
            "TotalAmount": event.get("TotalAmount"),
            "CustomerId": event.get("CustomerId"),
            "Items": items,
            "Reservations": reservations,
            "Status": "INVENTORY_RESERVED",
        }

    except ClientError as e:
        print(f"DynamoDB error: {e.response['Error']['Message']}")
        raise
    except Exception as e:
        print(f"Inventory reservation error: {str(e)}")
        raise


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