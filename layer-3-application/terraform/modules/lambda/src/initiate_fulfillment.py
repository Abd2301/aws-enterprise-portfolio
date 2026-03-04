"""
Initiate Fulfillment Lambda Function
Enterprise Order Processing Platform

Saga Step 3 (Final): Initiates order fulfillment/shipping.
Called by Step Functions after successful inventory reservation.

This is the last step in the happy path. If this fails,
the saga compensates by:
1. Calling release_inventory (undo step 2)
2. Calling reverse_payment (undo step 1)

On success, the order reaches FULFILLED status - the saga completes.
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
    Initiate fulfillment for a fully paid, inventory-reserved order.

    Args:
        event: Output from reserve_inventory step
        context: Lambda context

    Returns:
        dict: Final saga result with fulfillment details
    """
    try:
        order_id = event["OrderId"]
        timestamp = datetime.now(timezone.utc).isoformat()

        # Simulate fulfillment initiation
        # 98% success - rare failures test full compensation chain
        fulfillment_successful = random.random() < 0.98

        if not fulfillment_successful:
            record_event(order_id, "FulfillmentFailed", {
                "reason": "Fulfillment center unavailable",
            }, timestamp, context)

            update_order_status(order_id, "FULFILLMENT_FAILED", timestamp)

            raise Exception(f"Fulfillment failed for order {order_id}")

        # Generate tracking info
        tracking_id = f"TRACK-{order_id.split('-')[1]}-{context.aws_request_id[:6]}"

        update_order_status(order_id, "FULFILLED", timestamp)

        record_event(order_id, "OrderFulfilled", {
            "tracking_id": tracking_id,
            "payment_id": event.get("PaymentId"),
            "reservations": event.get("Reservations", []),
            "estimated_delivery": "3-5 business days",
        }, timestamp, context)

        # Final saga output
        return {
            "OrderId": order_id,
            "PaymentId": event.get("PaymentId"),
            "TrackingId": tracking_id,
            "CustomerId": event.get("CustomerId"),
            "TotalAmount": event.get("TotalAmount"),
            "Status": "FULFILLED",
            "Message": "Order successfully processed and shipped",
        }

    except ClientError as e:
        print(f"DynamoDB error: {e.response['Error']['Message']}")
        raise
    except Exception as e:
        print(f"Fulfillment error: {str(e)}")
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