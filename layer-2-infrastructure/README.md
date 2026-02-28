# Layer 2: Hybrid Cloud Network Architecture
## Enterprise AWS Portfolio — Abdul Ahad

![AWS](https://img.shields.io/badge/AWS-Hybrid_Cloud-orange) ![Status](https://img.shields.io/badge/Status-Complete-green) ![Layer](https://img.shields.io/badge/Layer-2_of_3-blue)

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Network Design](#network-design)
3. [VPC Architecture](#vpc-architecture)
4. [Transit Gateway](#transit-gateway)
5. [Site-to-Site VPN](#site-to-site-vpn)
6. [DNS Architecture](#dns-architecture)
7. [Security Controls](#security-controls)
8. [VPC Flow Logs](#vpc-flow-logs)
9. [Infrastructure as Code](#infrastructure-as-code)
10. [Architecture Decision Records](#architecture-decision-records)
11. [Cost Analysis](#cost-analysis)
12. [Failure Mode Analysis](#failure-mode-analysis)
13. [Interview Talking Points](#interview-talking-points)

---

## Architecture Overview

This layer implements a **Fortune 500-grade hybrid cloud network** connecting three AWS accounts (Production, Development, Network) with a simulated on-premises data center through a Transit Gateway hub-and-spoke topology.

```
                         ┌─────────────────────────────────────────┐
                         │         AWS Organizations                │
                         │                                          │
  ┌──────────────┐        │  ┌──────────────┐  ┌──────────────┐    │
  │  On-Premises │        │  │  Production  │  │ Development  │    │
  │  Simulated   │        │  │   Account    │  │   Account    │    │
  │  192.168.0.0 │        │  │  10.1.0.0/16 │  │  10.2.0.0/16│    │
  │     /16      │        │  └──────┬───────┘  └──────┬───────┘    │
  │              │        │         │                  │            │
  │  strongSwan  │        │         └────────┬─────────┘            │
  │  EC2 Ubuntu  │        │                  │                      │
  └──────┬───────┘        │         ┌────────▼────────┐             │
         │                │         │  Network Account │             │
         │  IPSec VPN     │         │  Transit Gateway │             │
         │  AES-256       │         │   10.3.0.0/16   │             │
         └────────────────┼────────►│  Enterprise-TGW  │             │
                          │         │   ASN: 64512     │             │
                          │         └─────────────────┘             │
                          └─────────────────────────────────────────┘
```

### Key Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Network topology | Hub-and-spoke via TGW | Scales to 100s of VPCs without mesh complexity |
| Routing | Static (portfolio) / BGP ready | Static for simplicity; BGP for production scale |
| VPN | Site-to-Site IPSec | Industry standard, AWS native, dual-tunnel HA |
| DNS | Route 53 Private Hosted Zones + Resolver | Hybrid DNS resolution across VPN |
| Isolation | Separate TGW route tables | Blast radius control — Dev cannot reach Prod |
| NAT | 3x NAT Gateways (1 per AZ) | True HA production pattern |

---

## Network Design

### IP Address Space

| Network | CIDR | Account | Purpose |
|---|---|---|---|
| Production | `10.1.0.0/16` | Production (159326043807) | Production workloads |
| Development | `10.2.0.0/16` | Development (928100078165) | Development workloads |
| Network | `10.3.0.0/16` | Network (468695259266) | Transit Gateway hub |
| On-Premises | `192.168.0.0/16` | Management (574337396853) | Simulated data center |

### Traffic Flow Matrix

| Source | Destination | Allowed | Path |
|---|---|---|---|
| Production | Internet | ✅ | NAT Gateway → IGW |
| Production | Development | ❌ | Blocked at TGW route table |
| Production | On-Premises | ✅ | TGW → VPN → strongSwan |
| Development | Internet | ✅ | NAT Gateway → IGW |
| Development | Production | ❌ | Blocked at TGW route table |
| Development | On-Premises | ✅ | TGW → VPN → strongSwan |
| On-Premises | Production | ✅ | VPN → TGW → Production VPC |
| On-Premises | Development | ✅ | VPN → TGW → Development VPC |

---

## VPC Architecture

### Production VPC (`10.1.0.0/16`) — 3 Availability Zones

```
Production VPC (10.1.0.0/16)
│
├── us-east-1a
│   ├── Public:  10.1.1.0/24    (Production-Public-1A)
│   ├── App:     10.1.11.0/24   (Production-App-1A)
│   ├── DB:      10.1.21.0/24   (Production-DB-1A)
│   └── TGW:     10.1.255.0/28  (Production-TGW-1A)
│
├── us-east-1b
│   ├── Public:  10.1.2.0/24    (Production-Public-1B)
│   ├── App:     10.1.12.0/24   (Production-App-1B)
│   ├── DB:      10.1.22.0/24   (Production-DB-1B)
│   └── TGW:     10.1.255.16/28 (Production-TGW-1B)
│
└── us-east-1c
    ├── Public:  10.1.3.0/24    (Production-Public-1C)
    ├── App:     10.1.13.0/24   (Production-App-1C)
    ├── DB:      10.1.23.0/24   (Production-DB-1C)
    └── TGW:     10.1.255.32/28 (Production-TGW-1C)
```

**Route Tables:**

| Route Table | Subnet | Routes |
|---|---|---|
| Production-Public-RT | All 3 public subnets | `0.0.0.0/0` → IGW |
| Production-App-RT-1A | App-1A | `0.0.0.0/0` → NAT-1A, `10.2.0.0/16` → TGW, `10.3.0.0/16` → TGW, `192.168.0.0/16` → TGW |
| Production-App-RT-1B | App-1B | `0.0.0.0/0` → NAT-1B, `10.2.0.0/16` → TGW, `10.3.0.0/16` → TGW, `192.168.0.0/16` → TGW |
| Production-App-RT-1C | App-1C | `0.0.0.0/0` → NAT-1C, `10.2.0.0/16` → TGW, `10.3.0.0/16` → TGW, `192.168.0.0/16` → TGW |
| Production-DB-RT | All 3 DB subnets | `10.2.0.0/16` → TGW, `10.3.0.0/16` → TGW, `192.168.0.0/16` → TGW |
| Production-TGW-RT | All 3 TGW subnets | Local only |

**NAT Gateways (3 — one per AZ for true HA):**

| NAT Gateway | Subnet | Elastic IP |
|---|---|---|
| Production-NAT-1A | Production-Public-1A | Auto-assigned |
| Production-NAT-1B | Production-Public-1B | Auto-assigned |
| Production-NAT-1C | Production-Public-1C | Auto-assigned |

> **Why 3 NAT Gateways?** In a real production environment, if us-east-1a goes down, app servers in us-east-1b and us-east-1c should still reach the internet through their own NAT Gateways. Single NAT Gateway creates a single point of failure.

---

### Development VPC (`10.2.0.0/16`) — 2 Availability Zones

```
Development VPC (10.2.0.0/16)
│
├── us-east-1a
│   ├── Public:  10.2.1.0/24    (Development-Public-1A)
│   ├── App:     10.2.11.0/24   (Development-App-1A)
│   ├── DB:      10.2.21.0/24   (Development-DB-1A)
│   └── TGW:     10.2.255.0/28  (Development-TGW-1A)
│
└── us-east-1b
    ├── Public:  10.2.2.0/24    (Development-Public-1B)
    ├── App:     10.2.12.0/24   (Development-App-1B)
    ├── DB:      10.2.22.0/24   (Development-DB-1B)
    └── TGW:     10.2.255.16/28 (Development-TGW-1B)
```

> **Why 2 AZs for Development?** Cost optimization. Dev environments don't need the same HA as production. 2 AZs provides redundancy for testing without tripling the NAT Gateway cost.

---

### Network VPC (`10.3.0.0/16`) — Transit Gateway Hub

```
Network VPC (10.3.0.0/16)
│
├── us-east-1a
│   ├── Public:  10.3.1.0/24    (Network-Public-1A)
│   └── TGW:     10.3.255.0/28  (Network-TGW-1A)
│
└── us-east-1b
    ├── Public:  10.3.2.0/24    (Network-Public-1B)
    └── TGW:     10.3.255.16/28 (Network-TGW-1B)
```

> **Why a dedicated Network account?** Following AWS Landing Zone best practices, network infrastructure (TGW, VPN, DNS Resolvers) lives in its own account. This prevents workload teams from accidentally modifying core network resources and enables centralized network governance via SCPs.

---

### On-Premises VPC (`192.168.0.0/16`) — Simulated Data Center

```
OnPrem VPC (192.168.0.0/16) — Management Account
│
└── us-east-1a
    ├── Public:  192.168.1.0/24  (OnPrem-Public-1A) ← strongSwan EC2
    └── Private: 192.168.2.0/24  (OnPrem-Private-1A)
```

**strongSwan EC2:**
- Instance type: `t2.micro` (Ubuntu 24.04 LTS)
- Source/destination check: **Disabled** (required for VPN routing)
- IPSec implementation: strongSwan 5.9.13
- Encryption: AES-256-CBC with SHA-1 HMAC

---

## Transit Gateway

### Configuration

| Parameter | Value |
|---|---|
| Name | Enterprise-TGW |
| ASN | 64512 |
| DNS Support | Enabled |
| VPN ECMP Support | Enabled |
| Default route table association | Disabled |
| Default route table propagation | Disabled |

> **Why disable default route table?** Disabling defaults forces explicit route table design. This is the enterprise pattern — every attachment must be deliberately associated with a route table, preventing accidental connectivity between environments.

### Attachments

| Attachment | Account | Resource | State |
|---|---|---|---|
| TGW-Attach-Production | Production | Production-VPC | Available |
| TGW-Attach-Development | Development | Development-VPC | Available |
| TGW-Attach-Network | Network | Network-VPC | Available |
| VPN-attachment | Network | OnPrem-to-AWS-VPN | Available |

### Route Tables — Isolation Design

**TGW-Production-RT:**

| CIDR | Attachment | Type |
|---|---|---|
| `10.1.0.0/16` | TGW-Attach-Production | Propagated |
| `10.3.0.0/16` | TGW-Attach-Network | Propagated |
| `192.168.0.0/16` | VPN-attachment | Static |

**TGW-Development-RT:**

| CIDR | Attachment | Type |
|---|---|---|
| `10.2.0.0/16` | TGW-Attach-Development | Propagated |
| `10.3.0.0/16` | TGW-Attach-Network | Propagated |
| `192.168.0.0/16` | VPN-attachment | Static |

> **Key Insight:** Production and Development route tables deliberately exclude each other's CIDRs. A developer in the Development account cannot reach a production database even if they know its IP address — the TGW will drop the packet.

### RAM Sharing

The Transit Gateway is shared to Production and Development accounts via AWS Resource Access Manager (RAM):

- Resource share: `TGW-Share`
- Principals: `159326043807` (Production), `928100078165` (Development)
- Permission: `AWSRAMDefaultPermissionTransitGateway`

---

## Site-to-Site VPN

### Configuration

| Parameter | Value |
|---|---|
| VPN Name | OnPrem-to-AWS-VPN |
| Target Gateway | Enterprise-TGW |
| Customer Gateway | OnPrem-Customer-GW (34.201.114.172) |
| Routing | Static |
| Static Routes | `192.168.0.0/16` |

### Tunnel Configuration

| | Tunnel 1 | Tunnel 2 |
|---|---|---|
| AWS Outside IP | 34.192.200.163 | 34.239.216.3 |
| Inside CIDR | 169.254.10.0/30 | 169.254.11.0/30 |
| Encryption | AES-256-CBC | AES-256-CBC |
| Status | **UP** ✅ | **UP** ✅ |

### strongSwan Configuration (`/etc/ipsec.conf`)

```
conn tunnel1
    left=%defaultroute
    leftid=34.201.114.172
    leftsubnet=192.168.0.0/16
    right=34.192.200.163
    rightsubnet=10.0.0.0/8
    ike=aes256-sha1-modp1024!
    esp=aes256-sha1-modp1024!
    auto=start
    keyexchange=ikev1

conn tunnel2
    left=%defaultroute
    leftid=34.201.114.172
    leftsubnet=192.168.0.0/16
    right=34.239.216.3
    rightsubnet=10.0.0.0/8
    ike=aes256-sha1-modp1024!
    esp=aes256-sha1-modp1024!
    auto=start
    keyexchange=ikev1
```

> **Why two tunnels?** AWS always provisions two VPN tunnels per connection for high availability. If one AWS VPN endpoint undergoes maintenance, traffic automatically fails over to the second tunnel. This is AWS-managed redundancy.

> **Why static routing instead of BGP?** For this portfolio implementation, static routing was chosen for simplicity. In a production environment with hundreds of VPCs, BGP dynamic routing would be preferred so routes propagate automatically without manual route table updates. The architectural understanding matters more than the implementation choice.

---

## DNS Architecture

### Private Hosted Zones

| Zone | Zone ID | Associated VPC | Purpose |
|---|---|---|---|
| `prod.aws.internal` | Z07401471Q0JI4CSAS9QM | Production-VPC | Production service discovery |
| `dev.aws.internal` | Z1009780EDEY41NXGIPO | Development-VPC | Development service discovery |
| `shared.aws.internal` | Z0743339UTFDL8757Y2B | Network-VPC | Shared services |

### Sample DNS Records

| Record | Type | Value | Purpose |
|---|---|---|---|
| `app.prod.aws.internal` | A | `10.1.11.10` | Production application |
| `app.dev.aws.internal` | A | `10.2.11.10` | Development application |
| `bastion.shared.aws.internal` | A | `10.3.1.10` | Shared bastion host |

### Cross-Account VPC Association

Private Hosted Zones are managed in the Network account but associated with VPCs in other accounts using a two-step authorization process:

```bash
# Step 1: Network account authorizes the association
aws route53 create-vpc-association-authorization \
  --hosted-zone-id Z07401471Q0JI4CSAS9QM \
  --vpc VPCRegion=us-east-1,VPCId=vpc-0a8603b7252882ecf

# Step 2: Production account accepts the association
aws route53 associate-vpc-with-hosted-zone \
  --hosted-zone-id Z07401471Q0JI4CSAS9QM \
  --vpc VPCRegion=us-east-1,VPCId=vpc-0a8603b7252882ecf
```

### Route 53 Resolver Endpoints

**Inbound Endpoint** (`Enterprise-Inbound-Resolver`):
- Allows on-premises DNS queries → AWS Private Hosted Zones
- Deployed in Network-VPC (us-east-1a, us-east-1b)
- Security group allows UDP/TCP 53 from `10.0.0.0/8` and `192.168.0.0/16`

**Outbound Endpoint** (`Enterprise-Outbound-Resolver`):
- Allows AWS DNS queries → on-premises DNS servers
- Deployed in Network-VPC (us-east-1a, us-east-1b)

**Resolver Rule** (`OnPrem-DNS-Rule`):
- Domain: `corp.example.com`
- Target: `192.168.1.195:53` (strongSwan EC2 acting as DNS)
- Associated with: Network-VPC, Production-VPC, Development-VPC
- Shared via RAM to Production and Development accounts

```
DNS Query Flow (On-Premises → AWS):
On-Prem host → Resolver Inbound Endpoint → Route 53 → prod.aws.internal → 10.1.11.10

DNS Query Flow (AWS → On-Premises):
AWS Lambda → Resolver Outbound Endpoint → OnPrem-DNS-Rule → 192.168.1.195 → corp.example.com
```

---

## Security Controls

### Security Groups

**Production Account:**

| Security Group | Inbound | Outbound | Purpose |
|---|---|---|---|
| Production-ALB-SG | 443 from `0.0.0.0/0`, 80 from `0.0.0.0/0` | All | Internet-facing load balancer |
| Production-App-SG | 8080 from `Production-ALB-SG` | All | Application tier |
| Production-DB-SG | 3306 from `Production-App-SG`, 5432 from `Production-App-SG` | None | Database tier |

**Development Account:**

| Security Group | Inbound | Outbound | Purpose |
|---|---|---|---|
| Development-ALB-SG | 443, 80 from `0.0.0.0/0` | All | Dev load balancer |
| Development-App-SG | 8080 from `Development-ALB-SG`, 22 from My IP | All | Dev application tier |
| Development-DB-SG | 3306, 5432 from `Development-App-SG` | None | Dev database tier |

> **Security Group Chaining:** Notice DB-SG references App-SG as its source, not a CIDR. This means only instances attached to App-SG can reach the database — a new EC2 instance even in the same subnet cannot access the DB unless it has the App-SG attached. This is a key enterprise security pattern.

### Network ACLs (Production)

**Production-Public-NACL:**

| Rule | Protocol | Port | Source | Action |
|---|---|---|---|---|
| 100 | TCP | 443 | `0.0.0.0/0` | Allow |
| 110 | TCP | 80 | `0.0.0.0/0` | Allow |
| 120 | TCP | 1024-65535 | `0.0.0.0/0` | Allow |
| * | All | All | `0.0.0.0/0` | Deny |

**Production-App-NACL:**

| Rule | Protocol | Port | Source | Action |
|---|---|---|---|---|
| 100 | TCP | 8080 | `10.1.0.0/16` | Allow |
| 110 | All | All | `10.0.0.0/8` | Allow |
| 120 | TCP | 1024-65535 | `0.0.0.0/0` | Allow |
| * | All | All | `0.0.0.0/0` | Deny |

**Production-DB-NACL:**

| Rule | Protocol | Port | Source | Action |
|---|---|---|---|---|
| 100-150 | TCP | 3306/5432 | App subnets | Allow |
| 160 | TCP | 1024-65535 | `10.1.0.0/16` | Allow |
| * | All | All | `0.0.0.0/0` | Deny |

> **Defense in Depth:** Security Groups are stateful (return traffic automatic) while NACLs are stateless (must explicitly allow return traffic via ephemeral ports 1024-65535). Using both creates two independent layers of network security.

---

## VPC Flow Logs

### Configuration

| Setting | Value |
|---|---|
| VPCs monitored | Production-VPC, Development-VPC |
| Traffic filter | ALL (accepted + rejected) |
| Aggregation interval | 1 minute |
| Destination | S3 — Log Archive account |
| S3 Bucket | `enterprise-vpc-flowlogs-740595473930` |
| Format | AWS default |

### Bucket Policy (Security Hardened)

```json
{
  "Statement": [
    {
      "Sid": "AWSLogDeliveryWrite",
      "Effect": "Allow",
      "Principal": { "Service": "delivery.logs.amazonaws.com" },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::enterprise-vpc-flowlogs-740595473930/AWSLogs/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control",
          "aws:SourceOrgID": "o-m7561sx0ic"
        }
      }
    }
  ]
}
```

> **Why restrict to SourceOrgID?** Adding `aws:SourceOrgID` prevents any AWS account outside your organization from writing to this bucket, even if they somehow obtain the bucket ARN. This is a defense against confused deputy attacks.

### Integration with Layer 1

Flow Logs land in the **Log Archive account** (740595473930) which was established in Layer 1. This demonstrates the governance layer working — centralized logging enforced by organizational structure, not just configuration.

GuardDuty (enabled in Layer 1) automatically analyzes VPC Flow Logs to detect:
- Port scanning attempts
- Unusual traffic patterns
- Known malicious IP communication
- Cryptomining activity

---

## Infrastructure as Code

### CloudFormation Template

See `layer2/vpc/production-vpc.yaml` for the complete Production VPC CloudFormation template.

Key outputs exported for cross-stack reference:

```yaml
Outputs:
  VpcId:
    Export:
      Name: Production-VPC-ID
  AppSubnets:
    Export:
      Name: Production-App-Subnets
  DBSubnets:
    Export:
      Name: Production-DB-Subnets
```

These exports allow Layer 3 (serverless application) stacks to reference the network infrastructure without hardcoding resource IDs.

---

## Architecture Decision Records

### ADR-001: Hub-and-Spoke vs Full Mesh

**Decision:** Hub-and-spoke Transit Gateway topology

**Context:** Multiple VPCs need to communicate. Two options: VPC Peering (mesh) or Transit Gateway (hub-and-spoke).

**Reasoning:**
- VPC Peering requires N*(N-1)/2 connections. With 10 VPCs that's 45 peering connections to manage.
- Transit Gateway requires N connections. With 10 VPCs that's 10 attachments.
- TGW supports transitive routing; VPC peering does not.
- TGW enables centralized network monitoring and policy enforcement.

**Consequence:** Higher base cost ($0.05/hr for TGW + $0.05/hr per attachment) but dramatically lower operational complexity at scale.

---

### ADR-002: Separate TGW Route Tables for Environment Isolation

**Decision:** Two TGW route tables (Production and Development) instead of one shared table

**Context:** Need to prevent Development from accessing Production while sharing common on-premises connectivity.

**Reasoning:**
- Single route table would require NACL/SG-level blocking which is error-prone
- Separate route tables enforce isolation at the network layer — packets are dropped before reaching destination
- Follows principle of least privilege at the network level
- Simplifies audit — clearly shows what can reach what

**Consequence:** More route table management but significantly stronger isolation guarantees.

---

### ADR-003: Static Routing vs BGP for VPN

**Decision:** Static routing for portfolio; BGP recommended for production

**Context:** Site-to-Site VPN requires routing between on-premises and AWS.

**Reasoning:**
- Static routing is simpler to configure and debug
- For a portfolio with fixed CIDRs, static routes are perfectly adequate
- BGP dynamic routing adds complexity (BGP daemon, ASN management, route filtering)

**Production Recommendation:** Use BGP with route filtering to prevent on-premises from advertising default routes into AWS. BGP automatically propagates routes as new VPCs are added without manual route table updates.

**Consequence:** Manual route table updates required when adding new VPC CIDRs to VPN routes.

---

### ADR-004: Dedicated Network Account

**Decision:** Dedicated Network account for Transit Gateway and shared network services

**Context:** Where should Transit Gateway, VPN, and DNS Resolvers live?

**Reasoning:**
- Separation of duties: network team manages Network account, app teams manage their accounts
- SCPs can restrict TGW deletion to only the Network account
- Centralized visibility for network operations
- AWS Landing Zone and Control Tower best practice

**Consequence:** Cross-account TGW attachment complexity (RAM sharing required) but significantly better governance.

---

## Cost Analysis

### Layer 2 Resource Costs

| Resource | Unit Cost | Quantity | Daily Cost |
|---|---|---|---|
| NAT Gateway hours | $0.045/hr | 3 | $3.24 |
| NAT Gateway data | $0.045/GB | Variable | ~$0.50 |
| Transit Gateway hours | $0.05/hr | 1 | $1.20 |
| TGW attachments | $0.05/hr | 4 | $4.80 |
| VPN Connection | $0.05/hr | 1 | $1.20 |
| Route 53 Resolver | $0.125/hr per endpoint | 2 | $6.00 |
| Route 53 Hosted Zones | $0.50/zone/month | 3 | $0.05 |
| VPC Flow Logs (S3) | $0.023/GB | Variable | ~$0.10 |
| EC2 t2.micro | Free tier | 1 | $0.00 |

**Peak daily cost (all resources running): ~$17.09/day**

### Cost Optimization Applied

1. **TGW deleted after documentation** — saves $7.20/day
2. **VPN deleted after documentation** — saves $1.20/day
3. **EC2 terminated after VPN testing** — saves ~$0.00 (free tier)
4. **Single NAT Gateway for Dev** — saves $3.24/day vs 3 NAT GWs
5. **No NAT Gateway in Network account** — saves $1.08/day

**Ongoing Layer 2 cost (essential services only): ~$9.24/day**

---

## Failure Mode Analysis

### Scenario 1: Single NAT Gateway Failure (Development)

**Impact:** All Development private subnets lose internet access
**Detection:** CloudWatch alarm on NAT Gateway ErrorPortAllocation metric
**Recovery:** Deploy second NAT Gateway in us-east-1b, update Development-App-RT
**Prevention:** Use multiple NAT Gateways (implemented in Production, cost trade-off in Dev)
**RTO:** ~5 minutes with automation

---

### Scenario 2: VPN Tunnel 1 Failure

**Impact:** None — traffic automatically fails over to Tunnel 2
**Detection:** CloudWatch VPN tunnel state metric
**Recovery:** Automatic (AWS-managed failover)
**Prevention:** Dual tunnel architecture already implemented
**Note:** Both tunnels must fail for connectivity loss

---

### Scenario 3: Transit Gateway Attachment Failure

**Impact:** Affected VPC loses all cross-VPC and VPN connectivity
**Detection:** TGW attachment state change CloudWatch event
**Recovery:** Delete and recreate attachment, update route tables
**RTO:** ~10 minutes
**Note:** VPC's internet access (via NAT/IGW) unaffected

---

### Scenario 4: DNS Resolution Failure (Resolver Endpoint Down)

**Impact:** On-premises cannot resolve AWS internal hostnames
**Detection:** Route 53 Resolver endpoint health metric
**Recovery:** Resolver endpoints are HA across 2 AZs by design
**Prevention:** Inbound/Outbound endpoints use 2 IPs in different AZs

---

### Scenario 5: Production/Development Accidental Connectivity

**Impact:** Development can access Production (security breach)
**Prevention:** TGW route table isolation (enforced at network layer, not SG/NACL)
**Verification:** Run `traceroute 10.1.11.10` from Development — should timeout at TGW
**Additional:** SCPs prevent modification of TGW route tables from workload accounts

---

## Interview Talking Points

### "Walk me through your network architecture"

> "I built a hub-and-spoke topology using AWS Transit Gateway as the central routing hub. Production and Development VPCs connect as spokes, along with a Network VPC that hosts shared services. The key design principle was blast radius control — I created separate TGW route tables for Production and Development, which prevents them from ever reaching each other even if security groups are misconfigured. This is enforced at the network layer, not the application layer."

---

### "How did you handle hybrid connectivity?"

> "I deployed a Site-to-Site VPN connecting a simulated on-premises environment to the Transit Gateway. The VPN uses dual IPSec tunnels for high availability — if one AWS VPN endpoint undergoes maintenance, traffic fails over automatically to the second tunnel. I implemented static routing for simplicity, but in a production environment I'd use BGP so routes propagate dynamically as new VPCs are added, eliminating manual route table updates across potentially hundreds of accounts."

---

### "What's the difference between Security Groups and NACLs?"

> "Security Groups are stateful and operate at the instance level — return traffic is automatically allowed. NACLs are stateless and operate at the subnet level — you must explicitly allow both inbound and outbound including ephemeral ports 1024-65535. I use both for defense in depth. Security Groups enforce who can talk to what, while NACLs provide a subnet-level backstop. I also chain Security Groups — my DB security group references the App security group as its source, not a CIDR block. This means only instances with the App-SG attached can reach the database, regardless of IP address."

---

### "How does your DNS work across accounts?"

> "I used Route 53 Private Hosted Zones with cross-account VPC association. The zones live in the Network account but are associated with VPCs in Production and Development accounts using a two-step authorization process — the Network account authorizes the association, then the target account accepts it. For hybrid DNS, I deployed Route 53 Resolver endpoints — inbound for on-premises to query AWS, outbound with forwarding rules to query on-premises DNS. The resolver rules are shared via RAM so all accounts benefit from centralized DNS configuration."

---

## Related Layers

- **[Layer 1 — Multi-Account Governance](../layer1/README.md):** Organizations, Control Tower, GuardDuty, Security Hub, automated threat response
- **[Layer 3 — Serverless Application](../layer3/README.md):** Lambda, DynamoDB, API Gateway, event-driven architecture *(coming soon)*

---

*Built as part of Enterprise AWS Architecture Portfolio by Abdul Ahad*
