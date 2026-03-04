"""
Get Order Lambda Function
Enterprise Order Processing Platform

Retrieves order details by OrderId or lists orders by CustomerId.
This reads from the CQRS write model (Orders table).

In a full CQRS implementation, reads would go to a separate
read-optimized table/cache. For this portfolio, we demonstrate
the pattern by reading from the write model with GSI queries,
then add the read model via DynamoDB Streams in Session 4.
"""

import json
import os

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

dynamodb = boto3.resource("dynamodb")
orders_table = dynamodb.Table(os.environ["ORDERS_TABLE"])


def lambda_handler(event, context):
    """
    Handles two access patterns:
    - GET /orders/{id}        → Single order by OrderId
    - GET /orders?customer=X  → All orders for a customer
    """
    try:
        # Extract path parameters and query strings
        path_params = event.get("pathParameters") or {}
        query_params = event.get("queryStringParameters") or {}

        order_id = path_params.get("orderId")
        customer_id = query_params.get("customer")

        if order_id:
            return get_single_order(order_id)
        elif customer_id:
            return get_customer_orders(customer_id)
        else:
            return response(400, {
                "error": "Provide orderId in path or customer in query string"
            })

    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return response(500, {"error": "Internal server error"})


def get_single_order(order_id):
    """Fetch a single order by partition key - O(1) lookup."""
    try:
        result = orders_table.get_item(Key={"OrderId": order_id})
        item = result.get("Item")

        if not item:
            return response(404, {"error": f"Order {order_id} not found"})

        return response(200, {"order": item})

    except ClientError as e:
        print(f"DynamoDB error: {e.response['Error']['Message']}")
        return response(500, {"error": "Internal server error"})


def get_customer_orders(customer_id):
    """
    Query orders by CustomerId using the GSI.

    This demonstrates why we created CustomerIndex:
    Without the GSI, we'd need a full table scan (expensive, slow).
    With the GSI, this is an O(1) partition lookup + sort key range.
    """
    try:
        result = orders_table.query(
            IndexName="CustomerIndex",
            KeyConditionExpression=Key("CustomerId").eq(customer_id),
            ScanIndexForward=False,  # Newest orders first
        )

        return response(200, {
            "orders": result.get("Items", []),
            "count": result.get("Count", 0),
        })

    except ClientError as e:
        print(f"DynamoDB error: {e.response['Error']['Message']}")
        return response(500, {"error": "Internal server error"})


def response(status_code, body):
    """Build API Gateway compatible response."""
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body, default=str),
    }