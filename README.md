# Enterprise AWS Foundation

A production-grade, three-layer AWS platform demonstrating how Fortune 500 organizations structure cloud infrastructure at scale. This project goes beyond single-account tutorials to prove enterprise architectural thinking across multi-account governance, hybrid cloud networking, and event-driven serverless applications.

**What makes this different:** Most portfolio projects show isolated services in a single account. This platform proves understanding of organizational governance, security orchestration, hybrid integration, and distributed systems architecture — capabilities that separate enterprise architects from junior engineers.

---

## Three-Layer Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  LAYER 3 — EVENT-DRIVEN SERVERLESS APPLICATION                             │
│                                                                             │
│  ┌─────────┐   ┌─────────────┐   ┌──────────────┐   ┌──────────────────┐  │
│  │   API    │──→│   Lambda    │──→│  DynamoDB    │──→│  EventBridge     │  │
│  │ Gateway  │   │ (8 functions│   │ (3 tables)   │   │  SQS / SNS      │  │
│  │ HTTP API │   │  in VPC)    │   │ Streams/GSIs │   │  Event Backbone  │  │
│  └─────────┘   └──────┬──────┘   └──────────────┘   └──────────────────┘  │
│                        │                                                    │
│                 ┌──────┴──────┐                                             │
│                 │    Step     │  Saga: Payment → Inventory → Fulfillment   │
│                 │  Functions  │  Compensation: Reverse Payment, Release     │
│                 │   (Saga)    │  Patterns: CQRS, Event Sourcing, Idempot.  │
│                 └─────────────┘                                             │
│                                                                             │
│  Deployed via Terraform │ 5 modules │ 67 resources │ Remote state in S3    │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  LAYER 2 — HYBRID CLOUD CONNECTIVITY & NETWORK ARCHITECTURE               │
│                                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ Production   │  │ Development  │  │   Network    │  │  On-Premises  │   │
│  │ VPC          │  │ VPC          │  │   VPC        │  │  (Simulated)  │   │
│  │ 10.1.0.0/16  │  │ 10.2.0.0/16  │  │ 10.3.0.0/16  │  │ 192.168.0.0  │   │
│  │ 3-tier / 3AZ │  │ 3-tier / 2AZ │  │ Network Hub  │  │ strongSwan   │   │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘   │
│         │                  │                  │                  │           │
│         └──────────────────┴────────┬─────────┘                  │           │
│                                     │                            │           │
│                          ┌──────────┴──────────┐                 │           │
│                          │   Transit Gateway   │─── VPN Tunnels ─┘           │
│                          │   Hub-and-Spoke     │   (IPSec / Static)          │
│                          │   Route Isolation   │                             │
│                          └─────────────────────┘                             │
│                                                                             │
│  Route 53 Resolver │ Security Groups │ NACLs │ VPC Flow Logs │ DNS Zones   │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  LAYER 1 — ZERO TRUST MULTI-ACCOUNT GOVERNANCE                            │
│                                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │Management│  │ Security │  │   Log    │  │  Network │  │Production│    │
│  │ Account  │  │ Tooling  │  │ Archive  │  │ Account  │  │ Account  │    │
│  │  (Root)  │  │(GuardDuty│  │(CloudTrl │  │  (TGW,   │  │ (Workload│    │
│  │  Org Mgmt│  │ Sec Hub) │  │ FlowLogs)│  │  VPN)    │  │  + App)  │    │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │
│        │                                                                    │
│        ├── 7 Accounts across 4 Organizational Units                        │
│        ├── 5 Service Control Policies (encryption, region lock, root deny) │
│        ├── AWS Control Tower with preventive + detective guardrails         │
│        ├── IAM Identity Center (SSO) with 4 permission sets                │
│        ├── GuardDuty + Security Hub + Config + CloudTrail (org-wide)       │
│        └── Automated threat response (EventBridge → Lambda → SNS)          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## How the Layers Integrate

This isn't three separate projects — it's one cohesive platform where each layer depends on the ones below it.

**Layer 3 runs on Layer 2:** Lambda functions deploy into Production VPC private subnets, access DynamoDB through a VPC Gateway Endpoint, and are governed by the security groups and NACLs built in Layer 2. VPC Flow Logs capture all Lambda network traffic.

**Layer 2 runs on Layer 1:** Network resources deploy in the Network Account from the Infrastructure OU. VPC Flow Logs aggregate in the Log Archive Account. SCPs enforce encryption on all network resources. CloudTrail logs every configuration change.

**Layer 1 monitors everything:** GuardDuty analyzes Lambda network connections and API activity. Security Hub aggregates findings from all layers. Config tracks resource configurations across accounts. CloudTrail captures every API call organization-wide. Automated response can isolate compromised resources within seconds.

---

## Technical Highlights

### Distributed Systems Patterns

| Pattern | Implementation | Why It Matters |
|---|---|---|
| **Saga Orchestration** | Step Functions coordinating payment → inventory → fulfillment with compensating transactions on failure | Shows understanding of distributed transactions without a shared database |
| **CQRS** | DynamoDB write model with Streams feeding EventBridge for read-side consumers | Demonstrates read/write scaling independence |
| **Event Sourcing** | Immutable EventStore table recording every state change with timestamps | Proves audit trail design for regulated industries |
| **Idempotency** | DynamoDB conditional writes with TTL-based key expiration | Essential for at-least-once delivery systems |
| **Event-Driven Architecture** | DynamoDB Streams → Lambda → EventBridge → SQS/SNS | Decoupled consumers, zero code changes to add new subscribers |

### Enterprise Patterns

| Pattern | Implementation |
|---|---|
| **Multi-Account Strategy** | 7 accounts across 4 OUs with hard security boundaries |
| **Hub-and-Spoke Networking** | Transit Gateway connecting VPCs with route table isolation |
| **Hybrid Connectivity** | Site-to-Site VPN with dual IPSec tunnels to simulated on-premises |
| **Hybrid DNS** | Route 53 Resolver with inbound/outbound endpoints and conditional forwarding |
| **Defense in Depth** | SCPs → Security Groups → NACLs → VPC Endpoints (4 layers of network security) |
| **Centralized Logging** | CloudTrail + VPC Flow Logs aggregated in dedicated Log Archive account |
| **Automated Remediation** | GuardDuty findings trigger Lambda-based EC2 isolation within seconds |
| **Infrastructure as Code** | Terraform with modular architecture, remote state, and environment separation |

### AWS Services Used (25+)

**Governance:** Organizations, Control Tower, IAM Identity Center, Service Control Policies

**Security:** GuardDuty, Security Hub, Config (8 rules), CloudTrail, IAM Access Analyzer

**Networking:** VPC (3), Transit Gateway, Site-to-Site VPN, Route 53 (PHZ + Resolver), NAT Gateway, VPC Endpoints

**Compute:** Lambda (8 functions deployed in VPC)

**API:** API Gateway HTTP API v2

**Database:** DynamoDB (3 tables with Streams, GSIs, TTL, Point-in-Time Recovery)

**Orchestration:** Step Functions (Standard Workflow with saga pattern)

**Messaging:** EventBridge (custom bus), SQS (with DLQ), SNS

**Observability:** CloudWatch (Logs, Metrics, Dashboard, Alarms), X-Ray

**IaC:** Terraform (5 modules, 67 managed resources, S3 remote state with DynamoDB locking)

---

## Repository Structure

```
aws-enterprise-portfolio/
│
├── layer-1-governance/              # Multi-account governance foundation
│   └── README.md                    # SCPs, Control Tower, security services
│
├── layer-2-infrastructure/          # Hybrid cloud network architecture
│   └── README.md                    # VPCs, Transit Gateway, VPN, DNS, security
│
├── layer-3-application/             # Event-driven serverless platform
│   ├── README.md                    # Detailed Layer 3 documentation
│   └── terraform/
│       ├── main.tf                  # Provider config + module orchestration
│       ├── variables.tf             # Input variable definitions
│       ├── outputs.tf               # Root-level outputs
│       ├── cloudwatch.tf            # Dashboard and alarms
│       ├── environments/
│       │   └── production.tfvars    # Production values (gitignored)
│       └── modules/
│           ├── dynamodb/            # 3 tables: Orders, EventStore, Idempotency
│           ├── lambda/              # 8 functions + IAM + SG + VPC endpoint
│           │   └── src/             # Python source code
│           ├── api-gateway/         # HTTP API with 3 routes
│           ├── step-functions/      # Order saga state machine
│           │   └── order_saga.json  # ASL definition
│           └── events/              # EventBridge + SQS + SNS + stream consumer
│               └── src/             # Stream consumer Lambda code
│
├── LICENSE
└── README.md                        # This file
```

---

## Key Architectural Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Account strategy | 7 accounts / 4 OUs | Hard security boundaries between workloads; blast radius control |
| Networking model | Transit Gateway hub-and-spoke | Eliminates VPC peering mesh complexity; centralized routing |
| VPN routing | Static over BGP | Pragmatic trade-off — BGP added complexity without portfolio value |
| IaC tool | Terraform | Most marketable skill; cloud-agnostic; strong module ecosystem |
| API type | HTTP API v2 over REST API | 71% cost reduction; lower latency; sufficient for Lambda proxy |
| DynamoDB mode | On-Demand | Scales to zero cost; no capacity planning for unpredictable loads |
| Table design | Separate tables per pattern | Clarity over optimization; each table maps to a distinct pattern |
| Saga type | Orchestration over choreography | Visual debugging; centralized error handling; execution history |
| Workflow type | Standard over Express | Exactly-once execution for financial transactions |
| VPC Lambda | Deployed in private subnets | Security requirement — access private resources through SG chaining |
| DynamoDB access | VPC Gateway Endpoint | Free; faster; traffic stays on AWS backbone |
| State backend | S3 + DynamoDB in Management Account | State is a governance concern, not application concern |
| Cost strategy | Build → screenshot → delete expensive resources | Proves capability without ongoing burn |

---

## Cost Analysis

| Layer | Build Cost | Purpose |
|---|---|---|
| Layer 1 | ~$30 | Security services, Config rules, GuardDuty across 6 accounts |
| Layer 2 | ~$70 | Transit Gateway, VPN, NAT Gateways, Resolver endpoints |
| Layer 3 | ~$2-5 | Serverless — almost entirely within free tiers |
| **Total** | **~$102-105** | **Well under $400 budget** |

Ongoing monthly cost of ~$69-74 is primarily NAT Gateway ($32) and Route 53 Resolver endpoints ($24). All Layer 3 serverless resources cost near-zero at rest.

**Cost optimization applied:** Transit Gateway and VPN deleted after screenshots ($72/month saved). Two extra NAT Gateways deleted. DynamoDB On-Demand instead of provisioned capacity. 14-day CloudWatch log retention. HTTP API v2 instead of REST API (71% savings).

---

## Deployment

### Prerequisites
- AWS CLI v2 with SSO configured
- Terraform >= 1.5.0
- Access to Production account via `production-admin` SSO profile

### Layer 3 Deployment
```bash
cd layer-3-application/terraform
aws sso login --profile production-admin
terraform init
terraform plan -var-file=environments/production.tfvars
terraform apply -var-file=environments/production.tfvars
```

### Verify
```bash
# Create an order
curl -s -X POST $(terraform output -raw api_endpoint)/orders \
  -H "Content-Type: application/json" \
  -d '{"customer_id":"CUST-001","items":[{"item_id":"LAPTOP-01","quantity":1,"price":999.99}],"total_amount":999.99}'

# Run the saga
aws stepfunctions start-execution \
  --state-machine-arn $(terraform output -raw state_machine_arn) \
  --input '{"OrderId":"<from-above>","CustomerId":"CUST-001","Items":[{"item_id":"LAPTOP-01","quantity":1}],"TotalAmount":999.99}'
```

---

## Lessons Learned

**Technical discoveries from building, not reading:**

1. **DynamoDB rejects Python floats** — requires `Decimal` types. Use `json.loads(body, parse_float=Decimal)` and a custom encoder for serialization. Every Python developer hits this.

2. **NACLs are stateless** — VPC Lambda needs explicit outbound port 443 in NACLs, even though security groups automatically allow return traffic. This Layer 2 + Layer 3 integration issue took real debugging to find.

3. **VPC Gateway Endpoints** should be default for any VPC with Lambda — free, faster, and more secure than routing DynamoDB/S3 traffic through NAT Gateway.

4. **Lambda needs two types of permissions** — IAM execution roles (what Lambda can do) AND resource-based policies (who can invoke Lambda). Missing the `aws_lambda_permission` for API Gateway results in silent 500 errors.

5. **Saga compensation must be idempotent** — compensation functions check current state before acting. Without this, retried compensations reverse payments twice or release unreserved inventory.

6. **Static routing was the right call over BGP** — BGP troubleshooting consumed hours with diminishing portfolio returns. Pragmatic trade-offs over perfection is how real architects think.

7. **Terraform state migration is seamless** — `terraform init -migrate-state` moves from local to S3 remote state in one command. Start local for speed, migrate when ready for collaboration.

8. **SCP propagation takes 5-10 minutes** — testing immediately after attaching an SCP to an OU gives false negatives. Real enterprise architects know to wait.

---

## What This Proves

| Capability | Evidence |
|---|---|
| Multi-account strategy | 7 accounts, 4 OUs, 5 SCPs, cross-account resource sharing |
| Zero Trust implementation | Encryption everywhere, GuardDuty detection, automated response, least-privilege IAM |
| Hybrid cloud architecture | Transit Gateway hub-and-spoke, Site-to-Site VPN, Route 53 hybrid DNS |
| Distributed systems design | Saga, CQRS, Event Sourcing, Idempotency — implemented, not just discussed |
| Infrastructure as Code | Terraform modules, remote state, environment separation |
| Security automation | GuardDuty → EventBridge → Lambda remediation in seconds |
| Cost engineering | $102 total spend; build-document-delete strategy; serverless for near-zero ongoing |
| Operational readiness | CloudWatch dashboard, alarms, X-Ray tracing, centralized logging |

---

*Built in 6 days. 25+ AWS services. 7 accounts. 67 Terraform-managed resources. 4 distributed systems patterns. One integrated platform.*