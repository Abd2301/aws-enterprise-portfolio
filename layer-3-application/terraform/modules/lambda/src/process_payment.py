"""
Process Payment Lambda Function
Enterprise Order Processing Platform

Saga Step 1: Processes payment for an order.
Called by Step Functions as part of the order saga.

In production, this would integrate with Stripe/PayPal.
Here we simulate payment processing with success/failure
scenarios to demonstrate the saga pattern.

If this step fails, no compensation needed (nothing charged yet).
If a LATER step fails, the saga calls reverse_payment to refund.
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
    Process payment for an order.

    Args:
        event: Step Functions input containing order details
        context: Lambda context

    Returns:
        dict: Payment result passed to the next saga step
    """
    try:
        order_id = event["OrderId"]
        total_amount = event["TotalAmount"]
        timestamp = datetime.now(timezone.utc).isoformat()

        # Simulate payment processing
        # 90% success rate - the 10% failure lets us demo saga compensation
        payment_successful = random.random() < 0.9

        if not payment_successful:
            # Record failure event
            record_event(order_id, "PaymentFailed", {
                "reason": "Payment declined by processor",
                "amount": total_amount,
            }, timestamp, context)

            update_order_status(order_id, "PAYMENT_FAILED", timestamp)

            raise Exception(f"Payment failed for order {order_id}")

        # Generate payment reference
        payment_id = f"PAY-{order_id.split('-')[1]}-{context.aws_request_id[:8]}"

        # Update order status
        update_order_status(order_id, "PAYMENT_PROCESSED", timestamp)

        # Record success event
        record_event(order_id, "PaymentProcessed", {
            "payment_id": payment_id,
            "amount": total_amount,
            "method": "simulated",
        }, timestamp, context)

        # Return data for next saga step
        return {
            "OrderId": order_id,
            "PaymentId": payment_id,
            "TotalAmount": total_amount,
            "Items": event.get("Items", []),
            "CustomerId": event.get("CustomerId"),
            "Status": "PAYMENT_PROCESSED",
        }

    except ClientError as e:
        print(f"DynamoDB error: {e.response['Error']['Message']}")
        raise
    except Exception as e:
        print(f"Payment processing error: {str(e)}")
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