"""
DynamoDB Stream Consumer Lambda
Enterprise Order Processing Platform

Reads order changes from DynamoDB Streams and publishes
events to EventBridge. This is the bridge between the
data layer and the event-driven layer.

Flow: Order changes → DynamoDB Stream → This Lambda → EventBridge
     → SQS (analytics) / SNS (notifications)

This is the CQRS pattern in action: the write model (Orders table)
emits changes, and downstream consumers react asynchronously.
"""

import json
import os
from datetime import datetime, timezone

import boto3

events_client = boto3.client("events")

EVENT_BUS_NAME = os.environ["EVENT_BUS_NAME"]


def lambda_handler(event, context):
    """
    Process DynamoDB Stream records and publish to EventBridge.

    Args:
        event: Contains Records[] from DynamoDB Stream.
               Each record has eventName (INSERT/MODIFY/REMOVE)
               and dynamodb (Keys, NewImage, OldImage).
        context: Lambda context
    """
    published = 0
    errors = 0

    for record in event.get("Records", []):
        try:
            # eventName tells us what happened:
            #   INSERT = new order created
            #   MODIFY = order status changed
            #   REMOVE = order deleted (shouldn't happen normally)
            event_name = record.get("eventName")

            # Skip removes - we don't delete orders
            if event_name == "REMOVE":
                continue

            # Extract the new state of the order
            new_image = record.get("dynamodb", {}).get("NewImage", {})
            old_image = record.get("dynamodb", {}).get("OldImage", {})

            if not new_image:
                continue

            # Convert DynamoDB JSON format to normal JSON
            # DynamoDB format: {"OrderId": {"S": "ORD-123"}}
            # Normal format:   {"OrderId": "ORD-123"}
            order = deserialize_dynamodb(new_image)
            old_order = deserialize_dynamodb(old_image) if old_image else {}

            # Build EventBridge event
            detail = {
                "orderId": order.get("OrderId", "unknown"),
                "customerId": order.get("CustomerId", "unknown"),
                "newStatus": order.get("OrderStatus", "unknown"),
                "oldStatus": old_order.get("OrderStatus", "none"),
                "totalAmount": str(order.get("TotalAmount", 0)),
                "eventName": event_name,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            # Publish to EventBridge
            events_client.put_events(
                Entries=[
                    {
                        "Source": "enterprise.orders",
                        "DetailType": "OrderStateChange",
                        "Detail": json.dumps(detail),
                        "EventBusName": EVENT_BUS_NAME,
                    }
                ]
            )

            published += 1
            print(f"Published event: {order.get('OrderId')} "
                  f"{old_order.get('OrderStatus', 'none')} -> "
                  f"{order.get('OrderStatus')}")

        except Exception as e:
            errors += 1
            print(f"Error processing record: {str(e)}")

    print(f"Processed {published} events, {errors} errors "
          f"from {len(event.get('Records', []))} records")

    return {"published": published, "errors": errors}


def deserialize_dynamodb(dynamodb_item):
    """
    Convert DynamoDB JSON to standard Python dict.

    DynamoDB returns typed values like {"S": "hello"}, {"N": "42"}.
    This converts them to plain Python types.
    """
    result = {}
    for key, value in dynamodb_item.items():
        if "S" in value:
            result[key] = value["S"]
        elif "N" in value:
            result[key] = value["N"]
        elif "BOOL" in value:
            result[key] = value["BOOL"]
        elif "L" in value:
            result[key] = [deserialize_dynamodb_value(v) for v in value["L"]]
        elif "M" in value:
            result[key] = deserialize_dynamodb(value["M"])
        elif "NULL" in value:
            result[key] = None
    return result


def deserialize_dynamodb_value(value):
    """Deserialize a single DynamoDB typed value."""
    if "S" in value:
        return value["S"]
    elif "N" in value:
        return value["N"]
    elif "M" in value:
        return deserialize_dynamodb(value["M"])
    elif "L" in value:
        return [deserialize_dynamodb_value(v) for v in value["L"]]
    return str(value)