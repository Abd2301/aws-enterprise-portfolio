# Layer 1: Zero Trust Multi-Account Governance

> **Enterprise AWS Portfolio Project** | Principal Cloud Architect Portfolio  
> **Status:** ✅ Complete | **Region:** us-east-1 (primary), us-west-2 (secondary)  
> **Total Cost:** ~$25-35 | **Time to Build:** ~2 days

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Account Structure](#account-structure)
3. [Service Control Policies](#service-control-policies)
4. [AWS Control Tower](#aws-control-tower)
5. [IAM Identity Center](#iam-identity-center)
6. [Security Services](#security-services)
7. [Automated Threat Response](#automated-threat-response)
8. [Architecture Decisions & Tradeoffs](#architecture-decisions--tradeoffs)
9. [Interview Talking Points](#interview-talking-points)
10. [Cost Breakdown](#cost-breakdown)
11. [Layer 2 Preview](#layer-2-preview)

---

## Architecture Overview

Layer 1 establishes a **Zero Trust governance foundation** across 7 AWS accounts modeled after Fortune 500 enterprise patterns. The architecture answers three fundamental security questions:

- **Who can do what?** — IAM Identity Center with least-privilege permission sets
- **What is the maximum they can ever do?** — Service Control Policies as hard boundaries
- **Is anything going wrong right now?** — GuardDuty, Security Hub, Config, CloudTrail with automated response

```
┌─────────────────────────────────────────────────────────────┐
│                    AWS Organizations                         │
│                   Management Account                         │
│              (Control Tower, Identity Center)                │
├──────────────┬──────────────────────┬───────────────────────┤
│ Security OU  │  Infrastructure OU   │     Workload OU        │
│              │                      │                        │
│ ┌──────────┐ │  ┌───────────────┐   │  ┌────────────────┐   │
│ │  Audit   │ │  │    Network    │   │  │  Development   │   │
│ └──────────┘ │  └───────────────┘   │  └────────────────┘   │
│ ┌──────────┐ │                      │  ┌────────────────┐   │
│ │  Log-    │ │                      │  │   Production   │   │
│ │ Archive  │ │                      │  └────────────────┘   │
│ └──────────┘ │                      │                        │
│ ┌──────────┐ │                      │                        │
│ │Security- │ │                      │                        │
│ │ Tooling  │ │                      │                        │
│ └──────────┘ │                      │                        │
└──────────────┴──────────────────────┴───────────────────────┘
```

---

## Account Structure

### Account Inventory

| Account Name | Account ID | Email | OU | Purpose |
|-------------|------------|-------|----|---------|
| Aayushman (Management) | 574337396853 | aayushman2702@gmail.com | Root | Control Tower, Organizations, Identity Center |
| Network | 468695259266 | awsnetwork@gmail.com | Infrastructure | VPCs, Transit Gateway, VPN (Layer 2) |
| Audit | 869576899438 | awsaudit@gmail.com | Security | Read-only compliance access |
| Log-Archive | 740595473930 | awslogarchive@gmail.com | Security | Centralized immutable log storage |
| Security-Tooling | 011138603115 | awssecurity@gmail.com | Security | GuardDuty/Security Hub/Config delegated admin |
| Development | 928100078165 | awsdevelopment@gmail.com | Workload | Non-production workloads |
| Production | 159326043807 | awsproduction@gmail.com | Workload | Production workloads |

### Why This Structure?

**Blast radius containment** — A security incident in Production cannot spread to Security or Infrastructure accounts. Account boundaries are the strongest isolation mechanism in AWS.

**Separation of duties** — Security team operates in Security-Tooling. Developers operate in Workload accounts. Logs live in a dedicated account no workload can touch.

**Compliance alignment** — Maps directly to CIS AWS Foundations Benchmark multi-account requirements and AWS Security Reference Architecture.

---

## Service Control Policies

SCPs are the governance backbone. They define the **maximum possible permissions** in any member account — even an account administrator cannot exceed what an SCP allows.

> **Key principle:** SCPs do NOT grant permissions. They only restrict what is possible. Both the SCP and IAM policy must allow an action for it to succeed.

> **Important:** SCPs do NOT apply to the management account. This is why we never run workloads there.

### SCP 1 — Deny-Root-Account-Usage

**Attached to:** Security OU, Infrastructure OU, Workload OU

**Purpose:** Root credentials in any member account are rendered useless. Even if an attacker obtains root credentials, they cannot perform any actions.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyRootAccountActions",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:root"
        }
      }
    }
  ]
}
```

**Key concepts:**
- `aws:PrincipalArn` — global condition key identifying the caller
- `arn:aws:iam::*:root` — wildcard matches root in ANY account
- `StringLike` — required because of the `*` wildcard in the ARN

---

### SCP 2 — Deny-Non-Approved-Regions

**Attached to:** Workload OU only

**Purpose:** Restricts resource creation to us-east-1 and us-west-2. Prevents data residency violations and reduces attack surface.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyNonApprovedRegions",
      "Effect": "Deny",
      "NotAction": [
        "iam:*",
        "organizations:*",
        "route53:*",
        "budgets:*",
        "waf:*",
        "cloudfront:*",
        "sts:*",
        "support:*",
        "trustedadvisor:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": [
            "us-east-1",
            "us-west-2"
          ]
        }
      }
    }
  ]
}
```

**Key concepts:**
- `NotAction` — exempts global services (IAM, Route53, CloudFront) that have no region. Using NotAction is safer than Action because new global services are automatically exempt.
- `aws:RequestedRegion` — captures the target region of any API call
- `StringNotEquals` — fires deny when region is NOT in the approved list

---

### SCP 3 — Enforce-Encryption-At-Rest

**Attached to:** Security OU, Infrastructure OU, Workload OU

**Purpose:** No unencrypted data can be stored anywhere in the organization. Enforces compliance with PCI-DSS, HIPAA, SOC2 encryption requirements.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnencryptedS3",
      "Effect": "Deny",
      "Action": "s3:PutObject",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": ["aws:kms", "AES256"]
        }
      }
    },
    {
      "Sid": "DenyUnencryptedEBS",
      "Effect": "Deny",
      "Action": "ec2:CreateVolume",
      "Resource": "*",
      "Condition": {
        "Bool": {
          "ec2:Encrypted": "false"
        }
      }
    },
    {
      "Sid": "DenyUnencryptedRDS",
      "Effect": "Deny",
      "Action": "rds:CreateDBInstance",
      "Resource": "*",
      "Condition": {
        "Bool": {
          "rds:StorageEncrypted": "false"
        }
      }
    }
  ]
}
```

**Key concepts:**
- Each statement targets the specific "creation" API for each service
- `s3:x-amz-server-side-encryption` — the request header that specifies encryption type
- `Bool` condition operator — used for true/false conditions on EBS and RDS

---

### SCP 4 — Protect-Security-Services

**Attached to:** Security OU, Infrastructure OU, Workload OU

**Purpose:** Even a compromised administrator account cannot disable security monitoring. GuardDuty, CloudTrail, Config, and Security Hub cannot be turned off.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ProtectSecurityServices",
      "Effect": "Deny",
      "Action": [
        "guardduty:DeleteDetector",
        "guardduty:DisassociateFromMasterAccount",
        "guardduty:StopMonitoringMembers",
        "guardduty:DisableOrganizationAdminAccount",
        "securityhub:DisableSecurityHub",
        "securityhub:DisassociateFromMasterAccount",
        "config:DeleteConfigurationRecorder",
        "config:DeleteDeliveryChannel",
        "config:StopConfigurationRecorder",
        "cloudtrail:DeleteTrail",
        "cloudtrail:StopLogging",
        "cloudtrail:UpdateTrail"
      ],
      "Resource": "*"
    }
  ]
}
```

**Key concepts:**
- No Condition block — unconditional deny. Nobody, ever, under any circumstance.
- Each action is specifically the "turn off" or "disconnect" API for each security service
- Attackers' first move after compromising an account is killing audit trails — this prevents that

---

### SCP 5 — Deny-Public-Resource-Exposure

**Attached to:** Workload OU only

**Purpose:** Prevents accidental public exposure of sensitive resources. Blocks making S3 buckets public, RDS snapshots public, and AMIs public.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyPublicRDSSnapshot",
      "Effect": "Deny",
      "Action": "rds:ModifyDBSnapshotAttribute",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "rds:AttributeName": "restore",
          "rds:AttributeValue": "all"
        }
      }
    },
    {
      "Sid": "DenyPublicAMI",
      "Effect": "Deny",
      "Action": "ec2:ModifyImageAttribute",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "ec2:Add/group": "all"
        }
      }
    }
  ]
}
```

**Key concepts:**
- Each statement targets the specific API that makes a resource public
- Making an RDS snapshot public means anyone with an AWS account can copy your database
- Making an AMI public means anyone can launch a copy of your server image

---

## AWS Control Tower

### What Was Deployed

Control Tower automates a secure multi-account landing zone. Instead of manually configuring security baselines in every account, Control Tower enforces standards automatically.

| Configuration | Value |
|--------------|-------|
| Home Region | us-east-1 |
| Additional Region | us-west-2 |
| Preventive Controls | 93 active |
| Foundational OU | Security |
| CloudTrail Administrator | Log-Archive (740595473930) |
| Config Aggregator | Security-Tooling (011138603115) |
| IAM Identity Center | Managed by Control Tower |

### Registered OUs

| OU | Baseline Status | Accounts |
|----|----------------|---------|
| Infrastructure | ✅ Enabled | 1 (Network) |
| Security | ✅ Controls enabled | 3 (Audit, Log-Archive, Security-Tooling) |
| Workload | ✅ Enabled | 2 (Development, Production) |

### Guardrails Explained

Control Tower guardrails come in two types:

**Preventive Guardrails (SCP-based)** — Block actions before they happen. Example: Prevent member accounts from leaving the organization. These are enforced and cannot be bypassed by anyone in a member account.

**Detective Guardrails (Config-based)** — Detect violations after they happen and report them. Example: Detect if CloudTrail is disabled. These generate findings in Security Hub.

> **Interview distinction:** SCPs you write are custom guardrails YOU define. Control Tower guardrails are AWS-curated best practices on top of yours. They work together — 93 Control Tower guardrails + 5 custom SCPs = comprehensive governance.

### Auto-Enrollment

Control Tower automatically applies baseline configurations to every new account enrolled in registered OUs. No manual setup required per account — governance scales automatically.

---

## IAM Identity Center

### Overview

IAM Identity Center replaces per-account IAM users with centralized identity management. One user, one password, access to all accounts with appropriate permissions.

| Configuration | Value |
|--------------|-------|
| Instance ID | ssoins-72235adc081d000f |
| SSO Portal URL | https://d-906603dc08.awsapps.com/start |
| Identity Source | Identity Center directory |
| Primary Region | us-east-1 |
| Organization ID | o-m7561sx0ic |

### Permission Sets

| Permission Set | Base Policy | Session Duration | Used For |
|---------------|-------------|-----------------|---------|
| AWSAdministratorAccess | AdministratorAccess | 4 hours | Full admin — short session due to high privilege |
| AWSPowerUserAccess | PowerUserAccess | 8 hours | Developers — full access except IAM/Organizations |
| SecurityAuditor (custom) | SecurityAudit | 8 hours | Security team — read-only across all security services |
| AWSReadOnlyAccess | ViewOnlyAccess | 8 hours | Observers — view only, no changes |

> **Why 4-hour session for CloudAdmin?** If someone walks away from an active CloudAdmin session, the blast radius is enormous. Shorter sessions force re-authentication more frequently for high-privilege access.

### Account Assignments

| Account | User | Permission Set | Rationale |
|---------|------|---------------|-----------|
| Network | awsnetwork | AdministratorAccess | Building Layer 2 infrastructure requires full admin |
| Development | awsadmin | PowerUserAccess | Deploy and test apps, no IAM/Org changes |
| Production | awsadmin | ReadOnlyAccess | Never casually admin prod — view only by default |
| Security-Tooling | awsadmin | SecurityAuditor | View security findings, cannot modify security config |
| Log-Archive | awsadmin | ReadOnlyAccess | Can view logs, never modify them |
| Audit | awsadmin | ReadOnlyAccess | Compliance viewing only |

> **Real enterprise pattern:** In production this would be federated with Active Directory or Okta. The permission set architecture is identical — only the identity source changes. When an employee leaves, you delete them once in Identity Center and access to all accounts is revoked instantly.

---

## Security Services

All security services follow the **delegated administrator pattern** — Security-Tooling account is the central management point for the entire organization.

```
Management Account
    └── Delegates admin to Security-Tooling
            └── Security-Tooling manages all member accounts
                    ├── Development (monitored)
                    ├── Production (monitored)
                    ├── Network (monitored)
                    ├── Log-Archive (monitored)
                    └── Audit (monitored)
```

> **Why this pattern?** If an attacker compromises a workload account, they cannot see or modify the security findings about their own activity. The findings live in a separate account they don't have access to.

---

### Amazon GuardDuty

**What it does:** Continuously analyzes CloudTrail logs, VPC Flow Logs, and DNS logs using machine learning to detect threats automatically.

**What it detects:**
- Cryptocurrency mining on EC2 instances
- Credentials used from unusual locations
- Instances communicating with known malware C2 servers
- Port scanning and reconnaissance
- Unusual S3 data access patterns

| Configuration | Value |
|--------------|-------|
| Delegated Administrator | Security-Tooling (011138603115) |
| Member Accounts | 6 (all enrolled) |
| Auto-enable New Accounts | ON |
| S3 Protection | Enabled |
| Free Trial | 30 days active |

**Sample findings generated** — 40+ finding types tested and verified working.

---

### AWS Security Hub

**What it does:** Aggregates findings from all security services into a single dashboard with compliance scoring against industry standards.

| Configuration | Value |
|--------------|-------|
| Delegated Administrator | Security-Tooling (011138603115) |
| Home Region (Aggregation) | us-east-1 |
| Additional Region | us-west-2 |
| Policy Name | Enterprise-Security-Baseline |
| Resources Tracked | 493 |
| Total Findings | 4,100+ |
| Account Coverage | All 7 accounts |

**Compliance Standards Enabled:**
- AWS Foundational Security Best Practices (FSBP)
- CIS AWS Foundations Benchmark
- CSPM posture management (us-east-1, us-west-2)

> **Why both standards?** CIS Benchmark is what external auditors check for SOC2 compliance. FSBP is AWS's own best practices. Together they give comprehensive coverage — catching issues that one standard alone would miss.

---

### AWS Config

**What it does:** Continuously records the configuration of every AWS resource and evaluates it against compliance rules. Answers "what changed, when, and is it compliant?"

| Configuration | Value |
|--------------|-------|
| Recorder | Running in all accounts (Control Tower managed) |
| Aggregator | aws-controltower-ConfigAggregatorForOrganization |
| Aggregator Location | Security-Tooling |
| Recording Frequency | Daily (cost optimized) |

**8 Custom Config Rules Deployed:**

| Rule | What It Checks | Compliance Status |
|------|---------------|-------------------|
| cloud-trail-cloud-watch-logs-enabled | CloudTrail streaming to CloudWatch Logs | Noncompliant (detected gap) |
| encrypted-volumes | All EBS volumes encrypted | Evaluating |
| iam-password-policy | Strong password policy enforced | Noncompliant (detected gap) |
| rds-storage-encrypted | All RDS instances encrypted | Evaluating |
| root-account-mfa-enabled | Root account has MFA | ✅ Compliant |
| s3-bucket-logging-enabled | S3 access logging enabled | Evaluating |
| s3-bucket-public-read-prohibited | No public S3 buckets | Evaluating |
| vpc-flow-logs-enabled | VPC Flow Logs enabled | Evaluating |

> **Note on noncompliant findings:** The two noncompliant findings (CloudTrail/CloudWatch integration and IAM password policy) prove Config is actively detecting real issues. This is exactly the value of continuous compliance monitoring — finding gaps you didn't know existed.

---

### AWS CloudTrail

**What it does:** Records every API call across the entire organization — every console click, CLI command, SDK call.

| Configuration | Value |
|--------------|-------|
| Trail Name | aws-controltower-BaselineCloudTrail |
| Type | Organization trail (covers all accounts) |
| Multi-Region | Yes |
| Management Events | Read + Write |
| S3 Destination | Log-Archive account |
| Log File Validation | Enabled |

> **Log file validation** creates a cryptographic hash of every log file. If anyone tampers with a log file, the validation will fail — proving tampering occurred. Critical for compliance and forensics.

---

### IAM Access Analyzer

**What it does:** Continuously scans resource policies to identify any resources shared outside your AWS Organization — catching accidental public access or cross-account exposure.

| Configuration | Value |
|--------------|-------|
| Analyzer Name | OrgAccessAnalyzer |
| Zone of Trust | AWS Organization (o-m7561sx0ic) |
| Finding Type | External access (free tier) |
| Region | us-east-1 |

**Resources analyzed:**
- S3 buckets
- IAM roles
- KMS keys
- Lambda functions
- SQS queues
- Secrets Manager secrets
- SNS topics

> **Zone of trust** = your entire AWS Organization. Any resource shared outside this zone generates a finding. This prevents the kind of accidental S3 data exposures that regularly make security headlines.

---

## Automated Threat Response

The most differentiating component of Layer 1. When GuardDuty detects a high-severity threat, the system automatically responds in **under 60 seconds** — no human intervention required.

### Architecture

```
GuardDuty Finding (severity >= 7)
           │
           ▼
    EventBridge Rule
    (GuardDutyHighSeverityResponse)
           │
           ▼
    Lambda Function
    (ThreatResponseFunction)
           │
    ┌──────┴──────┐
    ▼             ▼
EC2 Compromise  IAM Compromise
    │             │
Isolate Instance  Deactivate Key
(replace SG      (status = Inactive,
with deny-all)    preserves evidence)
    │             │
    └──────┬──────┘
           ▼
    SNS Notification
    (email to security team)
```

### Components

**SNS Topic: SecurityAlerts**
- Protocol: Email
- Endpoint: awssecurity@gmail.com
- Purpose: Real-time notifications for all automated actions

**Lambda Function: ThreatResponseFunction**
- Runtime: Python 3.12
- Memory: 128 MB
- Execution Role: LambdaThreatResponseRole
- Environment Variable: SNS_TOPIC_ARN

**Execution Role Policies:**
- AmazonEC2FullAccess
- IAMFullAccess
- AmazonSNSFullAccess
- AWSSecurityHubFullAccess
- AWSLambdaBasicExecutionRole

**EventBridge Rule: GuardDutyHighSeverityResponse**

```json
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"],
  "detail": {
    "severity": [
      {"numeric": [">=", 7]}
    ]
  }
}
```

### Remediation Logic

**EC2 Instance Compromise:**
1. Retrieve instance's VPC ID
2. Create new security group with zero inbound/outbound rules
3. Remove default outbound allow rule
4. Replace instance's security groups with isolation SG
5. Send SNS notification with instance ID and actions taken

**IAM Credential Compromise:**
1. Extract access key ID and username from finding
2. Set access key status to `Inactive` (deactivate, not delete — preserves forensic evidence)
3. Send SNS notification with key ID and actions taken

> **Why deactivate instead of delete?** Deletion destroys forensic evidence needed to understand the full scope of compromise. Deactivation stops the attacker immediately while preserving the audit trail.

### Test Results

Successfully tested with simulated HIGH severity finding:
- ✅ Lambda executed in 2.4 seconds
- ✅ Finding parsed correctly (severity 8, UnauthorizedAccess type)
- ✅ Remediation attempted
- ✅ SNS notification sent
- ✅ Email delivered to security team inbox

---

## Architecture Decisions & Tradeoffs

### Decision 1: Daily vs Continuous Config Recording

**Chose:** Daily recording

**Why:** Continuous recording charges per configuration item recorded — with many resource types across 7 accounts this adds up quickly. Daily recording gives one compliance snapshot per day at 90% cost reduction.

**Production reality:** Enterprise environments use continuous recording for real-time compliance. The architecture supports it — just change the frequency setting.

---

### Decision 2: Severity Threshold for Automated Response

**Chose:** Severity >= 7 (HIGH only)

**Why:** Automating on all findings would cause alert fatigue and risk isolating legitimate resources. Medium severity (4-6) goes to a ticketing queue for human review. Low severity (1-3) is aggregated for trend analysis.

**Production reality:** Some enterprises automate Medium severity with less destructive actions (tag instance, create ticket) while reserving full isolation for HIGH severity.

---

### Decision 3: Deactivate vs Delete IAM Keys

**Chose:** Deactivate (set status = Inactive)

**Why:** Preserves forensic evidence. Security team needs to investigate which services the key accessed, what data was exfiltrated, and whether other credentials were compromised. Deletion makes this harder.

---

### Decision 4: Log-Archive as Separate Account

**Chose:** Dedicated Log-Archive account separate from Security-Tooling

**Why:** Defense in depth for logs. Security-Tooling runs active security tooling — if it were compromised, an attacker couldn't modify logs stored in a completely separate account with no workload access. Logs must outlive any compromise.

---

### Decision 5: SecurityAuditor Custom Permission Set

**Chose:** Custom permission set using AWS SecurityAudit managed policy

**Why:** AWS doesn't have a pre-built "SecurityAuditor" Identity Center permission set. SecurityAudit managed policy gives read access to all security-relevant services without write permissions — perfect for the security team's day-to-day work of reviewing findings without modifying configurations.

---

## Interview Talking Points

### 30-Second Pitch
*"Layer 1 establishes a Zero Trust governance foundation across 7 AWS accounts. Service Control Policies create hard permission boundaries that even account administrators can't bypass. Control Tower enforces 93 preventive guardrails automatically. GuardDuty, Security Hub, and Config provide continuous threat detection and compliance monitoring through a delegated administrator pattern — all findings centralized in a dedicated Security-Tooling account. When GuardDuty detects a high-severity threat, an EventBridge-triggered Lambda automatically isolates the compromised resource within seconds — reducing mean time to contain from hours to under one minute."*

---

### Common Interview Questions

**Q: Why multi-account instead of a single account with VPCs?**

A: Account boundaries provide blast radius containment that VPCs cannot. An IAM misconfiguration in Production cannot affect Security accounts. SCPs apply at the account level. Compliance teams can audit specific accounts independently. The cost is minimal; the security benefit is significant.

---

**Q: What's the difference between SCPs and IAM policies?**

A: SCPs define the maximum possible permissions — even an account's root user can't exceed them. IAM policies grant permissions within that boundary. Both must allow an action for it to succeed. SCPs don't grant permissions; they only restrict. Critically, SCPs don't apply to the management account, which is why we never run workloads there.

---

**Q: How do you prevent security monitoring from being disabled after a compromise?**

A: The Protect-Security-Services SCP explicitly denies the specific API calls that disable GuardDuty, CloudTrail, Config, and Security Hub. These are unconditional denies — no condition block, no exceptions. Even a compromised administrator with full IAM permissions cannot call `guardduty:DeleteDetector` or `cloudtrail:StopLogging`.

---

**Q: How does the delegated administrator pattern work?**

A: The management account designates Security-Tooling as the delegated administrator for GuardDuty, Security Hub, and Config. Security-Tooling then automatically enrolls all member accounts and aggregates all findings centrally. An attacker who compromises a workload account sees their own activity generating findings — but can't access Security-Tooling to see or delete those findings.

---

**Q: How do you access Production securely?**

A: Day-to-day access to Production is ReadOnly via Identity Center. When production changes are needed, we assume a specific permission set scoped to exactly the required actions. Every access is temporary (session-based STS tokens), every action is logged in CloudTrail, and CloudTrail cannot be disabled due to the SCP.

---

**Q: What happens when GuardDuty detects a compromised EC2 instance?**

A: Within 60 seconds: EventBridge fires on the HIGH severity finding, Lambda creates a new security group with zero rules, removes the instance from all existing security groups and adds the isolation SG, and sends an email to the security team. The instance loses all network connectivity — it can't exfiltrate data or receive commands — while remaining running for forensic investigation.

---

## Cost Breakdown

| Service | Monthly Cost | Notes |
|---------|-------------|-------|
| AWS Organizations | $0 | Free |
| Control Tower | $0 | Free |
| IAM Identity Center | $0 | Free |
| GuardDuty | $0 | 30-day free trial per account |
| Security Hub | $0 | 30-day free trial for essential capabilities |
| AWS Config | ~$5-8 | Daily recording, 8 rules, 7 accounts |
| CloudTrail | $0 | First management event trail free |
| IAM Access Analyzer | $0 | External access analysis free tier |
| S3 (log storage) | ~$1-2 | Minimal log data |
| Lambda | $0 | Well within free tier |
| EventBridge | $0 | Free for AWS service events |
| SNS | $0 | Free tier |
| **Total** | **~$6-10/month** | After free trials expire |

**Layer 1 build cost (one-time):** ~$25-35

---

## Repository Structure

```
aws-enterprise-portfolio/
├── layer-1-governance/
│   ├── README.md                    ← This file
│   ├── scps/
│   │   ├── deny-root-account.json
│   │   ├── deny-non-approved-regions.json
│   │   ├── enforce-encryption-at-rest.json
│   │   ├── protect-security-services.json
│   │   └── deny-public-resource-exposure.json
│   ├── lambda/
│   │   └── threat-response/
│   │       └── lambda_function.py
│   ├── eventbridge/
│   │   └── guardduty-high-severity-rule.json
│   └── screenshots/
│       ├── 01-organisations-OUs-created.png
│       ├── 02-all-accounts-created.png
│       ├── 03-portfolio-budget.png
│       ├── 04-all-scps-created.png
│       ├── 05-control-tower-setup-completed.png
│       ├── 06-control-tower-after-ou-registration.png
│       ├── 07-guardduty-enabled-for-all-6-accounts.png
│       ├── 08-sample-findings.png
│       ├── 09-security-hub-account-coverage.png
│       ├── 10-non-compliant-resource-found-in-config.png
│       ├── 11-cloud-trail-enabled-and-working.png
│       ├── 12-eventbridge-rules-with-pattern.png
│       ├── 13-iam-identity-center-accounts-overview.png
│       ├── 14-lambda-cloudwatch-execution-logs.png
│       ├── 15-sns-email-notification-received.png
│       ├── 16-config-rules-all-8.png
│       └── 17-iam-access-analyzer.png
├── layer-2-networking/
│   └── README.md                    ← Coming next
└── layer-3-serverless/
    └── README.md                    ← Coming later
```

---

*Built as part of an enterprise AWS architecture portfolio demonstrating Fortune 500-level governance, security, and operational excellence.*
