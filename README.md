# AWS Multi-Account Foundation

A three-layer AWS platform built across 7 accounts: multi-account governance, hybrid network connectivity, and an event-driven serverless application running on top of both. Each layer depends on the one below it, so the project covers how governance, networking and application design fit together rather than treating them as separate exercises.

Built on a personal budget of about $105, using a build, verify, screenshot, then tear down approach for the expensive components.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  LAYER 3 - EVENT-DRIVEN SERVERLESS APPLICATION                              │
│                                                                             │
│  ┌──────────┐   ┌─────────────┐   ┌──────────────┐   ┌──────────────────┐   │
│  │   API    │──→│   Lambda    │──→│  DynamoDB    │──→│  EventBridge     │   │
│  │ Gateway  │   │ (8 functions│   │ (3 tables)   │   │  SQS / SNS       │   │
│  │ HTTP API │   │  in VPC)    │   │ Streams/GSIs │   │                  │   │
│  └──────────┘   └──────┬──────┘   └──────────────┘   └──────────────────┘   │
│                        │                                                    │
│                 ┌──────┴──────┐                                             │
│                 │    Step     │  Saga: Payment → Inventory → Fulfillment    │
│                 │  Functions  │  Compensation: Reverse Payment, Release     │
│                 └─────────────┘                                             │
│                                                                             │
│  Terraform │ 5 modules │ 67 resources │ Remote state in S3                  │
├─────────────────────────────────────────────────────────────────────────────┤
│  LAYER 2 - HYBRID CONNECTIVITY AND NETWORKING                               │
│                                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Production   │  │ Development  │  │   Network    │  │ On-Premises  │     │
│  │ VPC          │  │ VPC          │  │   VPC        │  │ (Simulated)  │     │
│  │ 10.1.0.0/16  │  │ 10.2.0.0/16  │  │ 10.3.0.0/16  │  │ 192.168.0.0  │     │
│  │ 3-tier / 3AZ │  │ 3-tier / 2AZ │  │ Network Hub  │  │ strongSwan   │     │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘     │
│         └─────────────────┴────────┬────────┘                 │             │
│                          ┌─────────┴───────────┐              │             │
│                          │   Transit Gateway   │── VPN ───────┘             │
│                          │   Hub-and-Spoke     │  (IPSec / Static)          │
│                          └─────────────────────┘                            │
│                                                                             │
│  Route 53 Resolver │ Security Groups │ NACLs │ VPC Flow Logs                │
├─────────────────────────────────────────────────────────────────────────────┤
│  LAYER 1 - MULTI-ACCOUNT GOVERNANCE                                         │
│                                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │Management│  │ Security │  │   Log    │  │ Network  │  │Production│       │
│  │ Account  │  │ Tooling  │  │ Archive  │  │ Account  │  │ Account  │       │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
│                                                                             │
│  7 accounts, 4 OUs │ 5 SCPs │ Control Tower guardrails                      │
│  IAM Identity Center (4 permission sets)                                    │
│  GuardDuty, Security Hub, Config, CloudTrail (org-wide)                     │
│  Automated threat response: EventBridge, Lambda, SNS                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## How the Layers Connect

**Layer 3 runs on Layer 2.** Lambda functions run in private subnets of the Production VPC, reach DynamoDB through a VPC Gateway Endpoint, and sit behind the security groups and NACLs from Layer 2. VPC Flow Logs capture their traffic.

**Layer 2 runs on Layer 1.** Network resources live in the Network account under the Infrastructure OU. Flow Logs land in the Log Archive account, SCPs enforce encryption on network resources, and CloudTrail records every configuration change.

**Layer 1 watches everything.** GuardDuty analyses Lambda network activity and API calls, Security Hub aggregates findings from all layers, and Config tracks resource state across accounts. A GuardDuty finding triggers an EventBridge rule that invokes a Lambda to isolate the affected EC2 instance, typically in under 60 seconds.

---

## What Is in This Repo

| Layer | How it was built | What is here |
|---|---|---|
| Layer 1 - Governance | Control Tower, Organizations and Identity Center, configured through the console | Design notes, SCP policies, screenshots |
| Layer 2 - Networking | Built and verified, then torn down to stop ongoing cost | Design notes, network layout, screenshots |
| Layer 3 - Application | Terraform | Full Terraform modules and Python Lambda source |

Layers 1 and 2 were deleted after testing because Transit Gateway, VPN and NAT Gateways cost roughly $70 a month to keep running. The screenshots in each layer folder are the record of the working setup.

---

## Design Patterns

### Application

| Pattern | Implementation |
|---|---|
| Saga orchestration | Step Functions coordinating payment, inventory and fulfilment, with compensating steps on failure |
| CQRS | DynamoDB write model, with Streams feeding EventBridge for read-side consumers |
| Event sourcing | Immutable EventStore table recording each state change with timestamps |
| Idempotency | DynamoDB conditional writes with TTL-based key expiry |
| Event-driven flow | DynamoDB Streams to Lambda to EventBridge to SQS/SNS |

### Platform

| Pattern | Implementation |
|---|---|
| Multi-account strategy | 7 accounts across 4 OUs, separating workloads and limiting blast radius |
| Hub-and-spoke networking | Transit Gateway with route table isolation between VPCs |
| Hybrid connectivity | Site-to-Site VPN with dual IPSec tunnels to a simulated on-premises network |
| Hybrid DNS | Route 53 Resolver inbound and outbound endpoints with conditional forwarding |
| Layered network security | SCPs, security groups, NACLs and VPC endpoints |
| Centralised logging | CloudTrail and VPC Flow Logs aggregated in a dedicated Log Archive account |
| Automated remediation | GuardDuty findings trigger Lambda-based EC2 isolation |

### AWS Services Used

**Governance:** Organizations, Control Tower, IAM Identity Center, Service Control Policies
**Security:** GuardDuty, Security Hub, Config (8 rules), CloudTrail, IAM Access Analyzer
**Networking:** VPC, Transit Gateway, Site-to-Site VPN, Route 53 (private hosted zones and Resolver), NAT Gateway, VPC Endpoints
**Compute and API:** Lambda (8 functions in VPC), API Gateway HTTP API
**Data:** DynamoDB (3 tables with Streams, GSIs, TTL and point-in-time recovery)
**Orchestration and messaging:** Step Functions, EventBridge, SQS with DLQ, SNS
**Observability:** CloudWatch (logs, metrics, dashboard, alarms), X-Ray
**IaC:** Terraform (5 modules, 67 resources, S3 remote state with DynamoDB locking)

---

## Repository Structure

```
aws-enterprise-portfolio/
├── layer-1-governance/
│   ├── README.md                  # SCPs, Control Tower, security services
│   └── screenshots/
├── layer-2-infrastructure/
│   ├── README.md                  # VPCs, Transit Gateway, VPN, DNS
│   └── screenshots/
├── layer-3-application/
│   ├── README.md
│   └── terraform/
│       ├── main.tf
│       ├── variables.tf
│       ├── outputs.tf
│       ├── cloudwatch.tf
│       ├── environments/
│       │   └── production.tfvars  # gitignored
│       └── modules/
│           ├── dynamodb/          # Orders, EventStore, Idempotency tables
│           ├── lambda/            # 8 functions, IAM, security group, VPC endpoint
│           ├── api-gateway/       # HTTP API with 3 routes
│           ├── step-functions/    # Order saga state machine
│           └── events/            # EventBridge, SQS, SNS, stream consumer
├── LICENSE
└── README.md
```

---

## Key Decisions

| Decision | Choice | Reason |
|---|---|---|
| Account strategy | 7 accounts, 4 OUs | Hard boundaries between workloads and a smaller blast radius |
| Networking model | Transit Gateway hub-and-spoke | Avoids a VPC peering mesh and keeps routing central |
| VPN routing | Static instead of BGP | BGP added troubleshooting time without changing what the project demonstrates |
| IaC tool | Terraform | Widely used, cloud-agnostic, good module ecosystem |
| API type | HTTP API instead of REST API | Lower cost and latency, and enough for a Lambda proxy |
| DynamoDB capacity | On-demand | Scales to zero cost with no capacity planning |
| Saga style | Orchestration instead of choreography | Easier to debug, central error handling, visible execution history |
| Workflow type | Standard instead of Express | Exactly-once execution for payment steps |
| Lambda placement | Private subnets | Reach private resources through security group chaining |
| DynamoDB access | VPC Gateway Endpoint | Free, faster, and keeps traffic off the NAT Gateway |
| Terraform state | S3 and DynamoDB in the Management account | State is treated as a governance concern |
| Cost approach | Build, verify, screenshot, tear down | Shows the setup working without a monthly bill |

---

## Cost

| Layer | Build cost | Main drivers |
|---|---|---|
| Layer 1 | ~$30 | GuardDuty, Config rules and security services across 6 accounts |
| Layer 2 | ~$70 | Transit Gateway, VPN, NAT Gateways, Resolver endpoints |
| Layer 3 | ~$2-5 | Mostly within free tier |
| **Total** | **~$102-105** | |

Running everything continuously would cost around $69-74 a month, mostly NAT Gateway ($32) and Route 53 Resolver endpoints ($24). To keep costs down I deleted Transit Gateway and VPN after testing, removed two extra NAT Gateways, used DynamoDB on-demand, set CloudWatch log retention to 14 days, and chose HTTP API over REST API.

---

## Deploying Layer 3

**Prerequisites:** AWS CLI v2 with SSO configured, Terraform 1.5 or later, and access to the Production account through a `production-admin` SSO profile.

```bash
cd layer-3-application/terraform
aws sso login --profile production-admin
terraform init
terraform plan -var-file=environments/production.tfvars
terraform apply -var-file=environments/production.tfvars
```

**Verify:**

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

1. **DynamoDB rejects Python floats.** It needs `Decimal` types, so parse with `json.loads(body, parse_float=Decimal)` and use a custom encoder when serialising.

2. **NACLs are stateless.** Lambda in a VPC needed an explicit outbound rule for port 443 in the NACL, even though security groups allow return traffic automatically. This one took real debugging because it sits between Layer 2 and Layer 3.

3. **VPC Gateway Endpoints should be the default** for any VPC running Lambda. They are free, faster, and keep DynamoDB and S3 traffic off the NAT Gateway.

4. **Lambda needs two kinds of permission.** The execution role controls what Lambda can do, and a resource-based policy controls who can invoke it. Without `aws_lambda_permission` for API Gateway, requests fail with a 500 and no obvious error.

5. **Saga compensation has to be idempotent.** Compensation functions check current state before acting, otherwise a retry can reverse a payment twice or release inventory that was never reserved.

6. **Static routing was the right trade-off.** BGP troubleshooting on the simulated on-premises side was taking hours without adding much to the project, so I switched to static routes.

7. **Terraform state migration is simple.** `terraform init -migrate-state` moves local state to S3 in one step, so starting locally and migrating later works fine.

8. **SCPs take 5-10 minutes to propagate.** Testing straight after attaching one to an OU gives misleading results.

---

## License

MIT
