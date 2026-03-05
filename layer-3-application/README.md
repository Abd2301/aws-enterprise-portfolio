# Layer 3: Event-Driven Serverless Order Processing Platform

## Architecture Overview

This layer deploys a production-grade, event-driven order processing system built on AWS serverless services. It demonstrates four distributed systems patterns—**Saga Orchestration**, **CQRS**, **Event Sourcing**, and **Idempotency**—running inside the enterprise foundation established in Layers 1 and 2.

Every resource is deployed via **Terraform** with modular architecture and remote state management, representing the Infrastructure-as-Code practices expected in enterprise environments.

```
                              ┌─────────────────────────────────────────────────┐
                              │              Production VPC (Layer 2)           │
                              │              10.1.0.0/16                        │
┌──────────┐    HTTPS         │  ┌──────────────────────────────────────────┐   │
│  Client   │───────────────────→│  API Gateway (HTTP API)                  │   │
└──────────┘                  │  │  POST /orders    GET /orders/{id}        │   │
                              │  │  GET /orders?customer=X                  │   │
                              │  └──────────┬────────────────┬──────────────┘   │
                              │             │                │                  │
                              │             ▼                ▼                  │
                              │  ┌──────────────┐  ┌────────────────┐          │
                              │  │ create_order  │  │  get_order     │          │
                              │  │   Lambda      │  │   Lambda       │          │
                              │  └──────┬───────┘  └────────────────┘          │
                              │         │                                       │
                              │         ▼                                       │
                              │  ┌──────────────────────────────────────────┐   │
                              │  │         DynamoDB Tables                   │   │
                              │  │  ┌────────────┐ ┌───────────┐ ┌────────┐│   │
                              │  │  │   Orders   │ │EventStore │ │Idempot.││   │
                              │  │  │(CQRS Write)│ │(Evt Source)│ │(Dedup) ││   │
                              │  │  └─────┬──────┘ └───────────┘ └────────┘│   │
                              │  │        │ Streams                         │   │
                              │  └────────┼────────────────────────────────┘   │
                              │           ▼                                     │
                              │  ┌──────────────────┐                          │
                              │  │ Stream Consumer   │                          │
                              │  │    Lambda         │                          │
                              │  └────────┬─────────┘                          │
                              │           ▼                                     │
                              │  ┌──────────────────────────────────────────┐   │
                              │  │      EventBridge (Custom Bus)            │   │
                              │  │  ┌─────────────┐  ┌──────────────────┐  │   │
                              │  │  │ All Events  │  │ Completed/Failed │  │   │
                              │  │  │   Rule      │  │     Rule         │  │   │
                              │  │  └──────┬──────┘  └────────┬─────────┘  │   │
                              │  └─────────┼──────────────────┼────────────┘   │
                              │            ▼                  ▼                 │
                              │    ┌─────────────┐    ┌──────────────┐         │
                              │    │  SQS Queue  │    │  SNS Topic   │         │
                              │    │ (Analytics) │    │(Notifications)│         │
                              │    │     + DLQ   │    └──────────────┘         │
                              │    └─────────────┘                             │
                              │                                                 │
                              │  ┌──────────────────────────────────────────┐   │
                              │  │     Step Functions (Order Saga)          │   │
                              │  │                                          │   │
                              │  │  ProcessPayment ──→ ReserveInventory     │   │
                              │  │       │                    │              │   │
                              │  │       │              InitiateFulfillment  │   │
                              │  │       │                    │              │   │
                              │  │   On Failure:         On Failure:        │   │
                              │  │   MarkFailed     ReleaseInventory ──→    │   │
                              │  │                  ReversePayment          │   │
                              │  └──────────────────────────────────────────┘   │
                              │                                                 │
                              │  ┌──────────────────────────────────────────┐   │
                              │  │     CloudWatch Observability              │   │
                              │  │  Dashboard │ 3 Alarms │ X-Ray Tracing   │   │
                              │  └──────────────────────────────────────────┘   │
                              │                                                 │
                              │  VPC Gateway Endpoint (DynamoDB) ── Free,      │
                              │  traffic stays on AWS backbone                  │
                              └─────────────────────────────────────────────────┘
                                          │                    │
                                    Layer 1 SCPs          Layer 2 NACLs
                                    GuardDuty             Security Groups
                                    CloudTrail            VPC Flow Logs
```

---

## Distributed Systems Patterns

### 1. Saga Pattern (Orchestration)

**Problem:** Processing an order requires three independent operations—payment, inventory reservation, and fulfillment. In a monolithic system, a single database transaction guarantees all-or-nothing. In distributed systems, there is no single transaction boundary.

**Solution:** AWS Step Functions orchestrates the saga. Each step is a separate Lambda function. If any step fails, Step Functions executes compensating transactions in reverse order to maintain data consistency.

```
Happy Path:
  ProcessPayment → ReserveInventory → InitiateFulfillment → FULFILLED

Payment Fails:
  ProcessPayment FAILS → OrderFailed (nothing to undo)

Inventory Fails:
  ProcessPayment ✓ → ReserveInventory FAILS → ReversePayment → OrderFailed

Fulfillment Fails:
  ProcessPayment ✓ → ReserveInventory ✓ → InitiateFulfillment FAILS
    → ReleaseInventory → ReversePayment → OrderFailed
```

**Key design decisions:**
- **Standard Workflow** over Express for exactly-once execution semantics—critical for financial transactions
- **Retry with exponential backoff** on transient errors (Lambda throttling, service exceptions) before triggering compensation
- **Compensation functions are idempotent**—safe to retry if they fail, preventing inconsistent state
- **Aggressive retry on compensation** (3 attempts vs 2 for forward steps) because compensation must succeed to maintain consistency

### 2. CQRS (Command Query Responsibility Segregation)

**Problem:** Write operations (create/update orders) and read operations (query orders by customer, status) have different scaling characteristics and access patterns.

**Solution:** The Orders DynamoDB table serves as the write model. DynamoDB Streams capture every change and publish events to EventBridge, enabling future read-optimized projections. The current implementation uses GSIs (CustomerIndex, StatusIndex) on the write model for reads, with the architecture ready for a separate read model via the stream consumer.

**Key design decisions:**
- **GSIs on write model** as pragmatic starting point—separate read store adds complexity that isn't justified until read/write scaling diverges significantly
- **Stream with NEW_AND_OLD_IMAGES** provides both before and after state for change detection
- **Stream consumer publishes to EventBridge** rather than directly updating a read model, enabling multiple consumers without coupling

### 3. Event Sourcing

**Problem:** Traditional CRUD overwrites previous state. You lose the history of how an order reached its current state, making debugging, auditing, and compliance difficult.

**Solution:** Every state change is recorded as an immutable event in the EventStore table. The order's current state can be reconstructed by replaying its events. The event store provides a complete audit trail with timestamps, function metadata, and full event data.

```
OrderId: ORD-D8F5583C
──────────────────────────────────────────────────
EventType          │ Timestamp
──────────────────────────────────────────────────
OrderCreated       │ 2026-03-05T08:48:21Z
PaymentProcessed   │ 2026-03-05T08:49:15Z
InventoryReserved  │ 2026-03-05T08:49:16Z
OrderFulfilled     │ 2026-03-05T08:49:17Z
```

**Key design decisions:**
- **Partition key = OrderId, Sort key = EventTimestamp** enables efficient per-order event replay
- **EventTypeIndex GSI** supports cross-order queries ("show all PaymentFailed events today") for operational debugging
- **Events are append-only**—no updates, no deletes. Immutability is the foundation of the audit trail

### 4. Idempotency

**Problem:** In distributed systems with at-least-once delivery (SQS, network retries, user double-clicks), the same request can arrive multiple times. Without protection, this causes duplicate orders, double charges, or repeated inventory deductions.

**Solution:** Clients send an `X-Idempotency-Key` header. The Lambda function checks the Idempotency DynamoDB table before processing. If the key exists and hasn't expired, it returns the cached result. If not, it processes the request and stores the result.

**Key design decisions:**
- **DynamoDB conditional writes** prevent race conditions—two simultaneous requests with the same key can't both succeed
- **24-hour TTL** automatically cleans expired keys, keeping the table small with zero operational overhead
- **Idempotency is opt-in** via header—internal service-to-service calls can use request IDs as idempotency keys

---

## Infrastructure as Code (Terraform)

### Module Architecture

```
terraform/
├── main.tf                          # Provider, backend, module orchestration
├── variables.tf                     # Root-level input variables
├── outputs.tf                       # Root-level outputs
├── cloudwatch.tf                    # Dashboard and alarms (cross-module)
├── environments/
│   └── production.tfvars            # Production values (gitignored)
└── modules/
    ├── dynamodb/                    # Data layer
    │   ├── main.tf                  #   3 tables, GSIs, streams, PITR
    │   ├── variables.tf             #   Inputs: project_name, environment
    │   └── outputs.tf               #   Outputs: table names, ARNs, stream ARN
    ├── lambda/                      # Compute layer
    │   ├── main.tf                  #   7 functions, IAM role, SG, VPC endpoint
    │   ├── variables.tf             #   Inputs: VPC, subnets, table ARNs
    │   ├── outputs.tf               #   Outputs: function ARNs, invoke ARNs
    │   └── src/                     #   Python function source code
    │       ├── create_order.py
    │       ├── get_order.py
    │       ├── process_payment.py
    │       ├── reserve_inventory.py
    │       ├── initiate_fulfillment.py
    │       ├── reverse_payment.py
    │       └── release_inventory.py
    ├── api-gateway/                 # API layer
    │   ├── main.tf                  #   HTTP API, routes, integrations
    │   ├── variables.tf             #   Inputs: Lambda invoke ARNs
    │   └── outputs.tf               #   Outputs: endpoint URL, API ID
    ├── step-functions/              # Orchestration layer
    │   ├── main.tf                  #   State machine, IAM role, logging
    │   ├── variables.tf             #   Inputs: Lambda ARNs for saga steps
    │   ├── outputs.tf               #   Outputs: state machine ARN
    │   └── order_saga.json          #   ASL state machine definition
    └── events/                      # Event-driven layer
        ├── main.tf                  #   EventBridge, SQS, SNS, stream consumer
        ├── variables.tf             #   Inputs: stream ARN, Lambda role ARN
        ├── outputs.tf               #   Outputs: bus name, queue URL, topic ARN
        └── src/
            └── stream_consumer.py   #   DynamoDB Stream → EventBridge bridge
```

### Module Composition

Modules connect through outputs and inputs—no module directly references another. The root `main.tf` orchestrates the data flow:

```
DynamoDB Module                    Lambda Module
  outputs:                           inputs:
    orders_table_arn ──────────────→ orders_table_arn
    orders_table_name ─────────────→ orders_table_name
    orders_stream_arn ──┐            outputs:
                        │              create_order_invoke_arn ──→ API Gateway Module
                        │              process_payment_arn ──────→ Step Functions Module
                        └──────────────────────────────────────→ Events Module
```

### Remote State Management

```
┌─────────────────────────────────┐
│  Management Account (574337396853)  │
│                                     │
│  S3: enterprise-terraform-state-*   │
│    └── layer-3/terraform.tfstate    │
│        (encrypted, versioned)       │
│                                     │
│  DynamoDB: enterprise-terraform-locks│
│    (state locking for concurrency)  │
└─────────────────────────────────┘
```

State stored in the Management account following the same governance separation pattern as Layer 1. State files are encrypted at rest, versioned for rollback, and locked during operations to prevent concurrent modifications.

### Resource Count

| Module | Resources | Key Components |
|---|---|---|
| DynamoDB | 3 | Orders table, EventStore table, Idempotency table |
| Lambda | 18 | 7 functions, IAM role/policy, security group, VPC endpoint, 7 log groups, zip archives |
| API Gateway | 10 | HTTP API, stage, 2 integrations, 3 routes, 2 permissions, log group |
| Step Functions | 4 | State machine, IAM role/policy, log group |
| Events | 14 | EventBridge bus, 2 rules, 2 targets, SQS + DLQ, SNS, policies, Lambda + mapping |
| CloudWatch | 4 | Dashboard, 3 alarms |
| **Total** | **53+** | Managed by Terraform with remote state |

---

## Integration with Layer 1 (Governance) and Layer 2 (Network)

This is not a standalone serverless project—it runs on the enterprise foundation built in previous layers:

### Layer 2 Integration (Network)
- Lambda functions deploy into **Production VPC private application subnets** (10.1.11.0/24, 10.1.12.0/24, 10.1.13.0/24) across three Availability Zones
- **DynamoDB VPC Gateway Endpoint** keeps data traffic on the AWS backbone—free, faster, more secure than NAT Gateway routing
- **Security group** controls Lambda network egress
- **Network ACLs** enforce subnet-level access control (required port 443 outbound for DynamoDB endpoint access)
- **VPC Flow Logs** capture Lambda network traffic for analysis in the Log Archive account

### Layer 1 Integration (Governance)
- **Service Control Policies** enforce encryption on DynamoDB tables and S3 buckets
- **GuardDuty** monitors Lambda network connections and API activity
- **CloudTrail** logs all Lambda deployments, API Gateway changes, and DynamoDB operations
- **Security Hub** aggregates serverless security findings
- **AWS Config** tracks Lambda configurations and compliance

---

## API Reference

### Create Order
```
POST /orders
Headers: Content-Type: application/json
         X-Idempotency-Key: <optional-unique-key>

Body:
{
  "customer_id": "CUST-001",
  "items": [
    {"item_id": "LAPTOP-01", "quantity": 1, "price": 999.99}
  ],
  "total_amount": 999.99
}

Response (201):
{
  "message": "Order created successfully",
  "order": {
    "OrderId": "ORD-D0AFEF43",
    "OrderStatus": "CREATED",
    ...
  }
}
```

### Get Order
```
GET /orders/{orderId}

Response (200):
{
  "order": {
    "OrderId": "ORD-D0AFEF43",
    "OrderStatus": "FULFILLED",
    "CustomerId": "CUST-001",
    ...
  }
}
```

### List Customer Orders
```
GET /orders?customer=CUST-001

Response (200):
{
  "orders": [...],
  "count": 3
}
```

---

## Observability

### CloudWatch Dashboard
Single-pane-of-glass view covering:
- API Gateway request rates, latency (avg and p99), 4xx/5xx errors
- Lambda invocations and errors per function
- Step Functions execution counts (started, succeeded, failed)
- DynamoDB consumed read/write capacity
- SQS queue depth and DLQ depth

### Alarms
| Alarm | Condition | Significance |
|---|---|---|
| API 5xx Errors | >5 errors in 2 consecutive minutes | Application or infrastructure failure |
| Saga Failures | >3 failures in 5 minutes | Distributed transaction issues |
| DLQ Messages | >0 messages | Event processing failure requiring investigation |

### X-Ray Tracing
Active tracing enabled on all Lambda functions for end-to-end distributed tracing across API Gateway → Lambda → DynamoDB → Step Functions.

---

## Cost Analysis

| Resource | Monthly Cost | Notes |
|---|---|---|
| Lambda (8 functions) | ~$0.00 | Free tier: 1M requests/month |
| API Gateway (HTTP API) | ~$0.00 | Free tier: 1M requests/month |
| DynamoDB (3 tables) | ~$0.00 | On-demand: pay per request, free tier covers demo usage |
| Step Functions | ~$0.00 | Free tier: 4,000 state transitions/month |
| EventBridge | ~$0.00 | Free tier: custom events |
| SQS + SNS | ~$0.00 | Free tier: 1M requests/month |
| DynamoDB VPC Endpoint | $0.00 | Gateway endpoints are free |
| CloudWatch | ~$2.00 | Dashboard + log storage beyond free tier |
| NAT Gateway (Layer 2) | ~$32.00 | Primary cost driver—inherited from Layer 2 |
| **Total Layer 3** | **~$2.00** | Serverless scales to zero |

**Comparison to EC2-based architecture:** An equivalent system with EC2 instances, ALB, and RDS would cost approximately $200/month with no auto-scaling to zero. Serverless reduces cost by 99% at low traffic.

---

## Deployment

### Prerequisites
- Terraform >= 1.5.0
- AWS CLI v2 with SSO configured
- Production account access (`production-admin` profile)

### Deploy
```bash
cd layer-3-application/terraform
aws sso login --profile production-admin
terraform init
terraform plan -var-file=environments/production.tfvars
terraform apply -var-file=environments/production.tfvars
```

### Destroy
```bash
terraform destroy -var-file=environments/production.tfvars
```

---

## Architectural Decisions

| Decision | Choice | Rationale |
|---|---|---|
| IaC Tool | Terraform | Most marketable skill, cloud-agnostic, strong module system |
| API Type | HTTP API v2 | 71% cheaper than REST API, lower latency, sufficient features |
| DynamoDB Mode | On-Demand | Scales to zero cost, no capacity planning for unpredictable loads |
| Table Design | Separate tables | Clarity over optimization—each table maps to a distinct pattern |
| Saga Type | Orchestration (Step Functions) | Easier debugging, visual execution history vs choreography |
| Workflow Type | Standard | Exactly-once execution for financial transactions |
| Stream View | NEW_AND_OLD_IMAGES | Full change context for audit trail and read model updates |
| VPC Deployment | Lambda in VPC | Security requirement—access private resources through security groups |
| DynamoDB Access | VPC Gateway Endpoint | Free, faster, more secure than NAT Gateway routing |
| Log Retention | 14 days | Balance between debugging capability and cost |
| State Backend | S3 + DynamoDB in Management Account | Governance separation—state is a management concern |

---

## Lessons Learned

1. **DynamoDB Decimal handling** — Python's `json.loads` produces floats, DynamoDB requires Decimal types. Use `parse_float=Decimal` and a custom JSON encoder for serialization.

2. **NACL statelessness** — VPC Lambda functions need outbound port 443 explicitly allowed in NACLs. Security groups are stateful (return traffic automatic), NACLs are not. This Layer 2 + Layer 3 integration issue is a real enterprise debugging scenario.

3. **VPC Gateway Endpoints** — Free alternative to routing DynamoDB traffic through NAT Gateway. Reduces latency and cost simultaneously. Should be default for DynamoDB and S3 in any VPC with Lambda functions.

4. **Lambda permissions model** — Both IAM execution roles (what Lambda can do) AND resource-based policies (who can invoke Lambda) are required. API Gateway needs explicit `aws_lambda_permission` to invoke functions.

5. **Terraform module composition** — Outputs from one module flow as inputs to another through the root module. No module directly references another—loose coupling at the infrastructure level mirrors microservice principles.

6. **Terraform state migration** — Moving from local to remote state is a single `terraform init -migrate-state` command. Start local for speed, migrate to S3 + DynamoDB locking for team collaboration.

7. **Compensation idempotency** — Saga compensation functions must check current state before acting. Without this, retried compensations could reverse a payment twice or release inventory that was never reserved.