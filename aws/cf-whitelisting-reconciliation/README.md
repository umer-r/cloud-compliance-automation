# Automated Cloudflare Origin Protection

Automated synchronization of Cloudflare edge proxy IP ranges with **AWS Customer-Managed Prefix Lists**, powered by **AWS Lambda**, **Amazon EventBridge Scheduler**, and **Amazon SNS**.

---

## 1. Problem Statement & Motivation

### The Direct-to-Origin (D2O) Threat
When organizations place an Application Load Balancer (ALB) or EC2 web instances behind Cloudflare's Web Application Firewall (WAF) and DDoS protection, their origin infrastructure is often inadvertently left vulnerable:
* If Security Groups permit inbound traffic on ports `80` / `443` from `0.0.0.0/0`, attackers can discover the origin's public IP address (via DNS history, SSL certificate search engines like Censys/Shodan, or header leaks) and **bypass Cloudflare WAF entirely**.
* Attackers can then launch volumetric DDoS attacks, exploit zero-day web application vulnerabilities, or execute brute-force attacks directly against the origin server.

### Why 0.0.0.0/0 Must Never Be Allowed
To achieve true origin isolation, **all ingress traffic to ALBs or public-facing instances must be restricted exclusively to Cloudflare's published reverse-proxy IP ranges**.

### The Operational Challenge
Cloudflare's proxy IP ranges are dynamic. While changes are infrequent, Cloudflare periodically provisions new IP blocks or retires old ones. 
* Hardcoding IP CIDRs manually in Security Groups is brittle, subject to human error, and limits scalability across multiple VPCs or accounts.
* Stale entries cause sudden service outages when Cloudflare routes traffic through unwhitelisted IPs.
* Manually updating Security Groups across multiple environments leads to configuration drift.

### The Solution: AWS Managed Prefix Lists + Serverless Automation
This project implements an automated, self-healing perimeter security control:
1. **AWS Managed Prefix Lists** define the single source of truth for Cloudflare IPv4 and IPv6 CIDRs.
2. An **EventBridge Scheduler** triggers an **AWS Lambda function** at regular intervals.
3. The Lambda function safely reconciles Cloudflare's published CIDRs against the AWS Managed Prefix Lists with **zero downtime** and **fail-closed safeguards**.
4. A `last_updated` tag tracks the exact timestamp of modifications directly on each prefix list.
5. An **Amazon SNS topic** pushes security alerts to SecOps/DevOps teams **only when proxy IP changes are detected and applied**.

---

## 2. Compliance & Governance Framework Mapping

Implementing origin lockdown via managed prefix lists and automated reconciliation addresses core requirements across major industry security standards:

| Framework | Control / Requirement | Implementation Details |
| :--- | :--- | :--- |
| **CIS AWS Foundations Benchmark v1.4 / v2.0 / v3.0** | **Control 5.2 / 5.3**: Ensure no security groups allow ingress from `0.0.0.0/0` to remote administration or sensitive ports. <br><br>*(Security Best Practice extension)*: Principle of Least Privilege (PoLP) on ingress boundaries. | Replaces broad `0.0.0.0/0` internet rules on HTTP (`80`) and HTTPS (`443`) with customer-managed prefix lists restricted strictly to verified Cloudflare reverse proxies. |
| **SOC 2 Type II (Trust Services Criteria)** | **CC6.6**: Logical boundaries, perimeter protection, firewalls, and network segmentation.<br>**CC6.7**: Transmission of data and boundary defenses.<br>**CC7.1 / CC7.2**: Infrastructure configuration change detection and vulnerability mitigation. | Enforces strict network perimeter defense by disallowing untrusted ingress. Automated tagging (`last_updated`) and real-time SNS change notifications provide verifiable audit evidence for configuration management. |
| **PCI-DSS v4.0** | **Requirement 1.2 & 1.3**: Network Security Controls (NSCs) must restrict inbound and outbound traffic to only what is necessary, forbidding direct inbound connections from untrusted networks into internal components. | Guarantees that public traffic must pass through an authorized intermediate inspection proxy (Cloudflare WAF) before reaching the Cardholder Data Environment (CDE). |
| **NIST SP 800-53 Rev. 5** | **SC-7**: Boundary Protection.<br>**AC-4**: Information Flow Enforcement.<br>**CM-3**: Configuration Change Control. | Protects system boundaries via controlled external interfaces, enforces strict flow policies based on authorized origin addresses, and documents all changes via tags and SNS audit events. |
| **AWS Well-Architected Framework (Security Pillar)** | **SEC05**: Protecting Network Resources.<br>**SEC03**: Managing Permissions (Least Privilege). | Implements defense-in-depth, centralized firewall management, and automation to avoid human operational error. |

---

## 3. Architecture & Data Flow

![workflow diagram](https://raw.githubusercontent.com/umer-r/cloud-compliance-automation/refs/heads/main/aws/cf-whitelisting-reconciliation/docs/workflow_diagram.jpeg)

---

## 4. Key Design Principles & Safety Safeguards

### 1. Fail-Closed Error Handling (`FailClosedError`)
* If the Cloudflare API request times out, returns a non-200 HTTP status code, returns malformed JSON, or returns an empty CIDR list, the function raises `FailClosedError` immediately.
* **No mutations are applied to AWS prefix lists**, ensuring existing valid rules remain intact.

### 2. Safety Removal Threshold (`SAFETY_THRESHOLD`)
* Cloudflare rarely removes more than 1 or 2 CIDRs at a time. If an upstream glitch, API corruption, or misconfiguration returns a truncated list of CIDRs, a naive sync script would purge valid IPs and knock your application offline.
* The `SAFETY_THRESHOLD` setting (default: `3`) aborts the entire reconciliation if removals exceed this limit, preserving operational uptime.

### 3. Atomic Overlap & Zero Traffic Interruption
* AWS allows adding and removing entries in a single call to `ec2:ModifyManagedPrefixList`.
* By applying `AddEntries` and `RemoveEntries` together, traffic overlap remains continuous with zero packet drops.

### 4. Noise-Free SNS Alerting
* Cloudflare IPs change infrequently. Sending notifications on every scheduler run creates alert fatigue.
* The SNS notification is dispatched **only when changes occur** (`to_add` or `to_remove` is non-empty).
* The SNS payload includes an executive summary and a detailed JSON breakdown (version numbers, added CIDRs, removed CIDRs, and timestamps).

---

## 5. Environment Variables

Configure these environment variables in your AWS Lambda function configuration:

| Variable | Required | Default | Description |
| :--- | :---: | :---: | :--- |
| `PREFIX_LIST_ID_V4` | Optional* | None | AWS Managed Prefix List ID for IPv4 (e.g., `pl-abc`). |
| `PREFIX_LIST_ID_V6` | Optional* | None | AWS Managed Prefix List ID for IPv6 (e.g., `pl-xyz`). |
| `SNS_TOPIC_ARN` | Optional | None | ARN of the Amazon SNS topic to publish alerts when IP changes are reconciled. |
| `SAFETY_THRESHOLD` | Optional | `3` | Maximum number of CIDR removals permitted in a single run before failing closed. |
| `AWS_REGION` | Optional | `eu-west-2` | AWS region where the prefix lists and Lambda function reside. |

*\*Note: At least one of `PREFIX_LIST_ID_V4` or `PREFIX_LIST_ID_V6` must be defined.*

---

## 6. IAM Permissions

The Lambda execution role requires minimum privileges to inspect and modify only the targeted prefix lists, publish to the designated SNS topic, and write CloudWatch logs:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "CloudWatchLogs",
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:aws:logs:eu-west-2:<acc_id>:log-group:/aws/lambda/cf-whitelisting-reconciliation",
                "arn:aws:logs:eu-west-2:<acc_id>:log-group:/aws/lambda/cf-whitelisting-reconciliation:*"
            ]
        },
        {
            "Sid": "DescribePrefixLists",
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeManagedPrefixLists",
                "ec2:GetManagedPrefixListEntries"
            ],
            "Resource": "*"
        },
        {
            "Sid": "ModifyCloudflarePrefixLists",
            "Effect": "Allow",
            "Action": [
                "ec2:ModifyManagedPrefixList",
                "ec2:CreateTags"
            ],
            "Resource": [
                "arn:aws:ec2:eu-west-2:<acc_id>:prefix-list/pl-id",
                "arn:aws:ec2:eu-west-2:<acc_id>:prefix-list/pl-id"
            ]
        },
        {
            "Sid": "PublishToSNSTopic",
            "Effect": "Allow",
            "Action": [
                "sns:Publish"
            ],
            "Resource": [
                "arn:aws:sns:eu-west-2:<acc_id>:<sns-topic>"
            ]
        }
    ]
}
```

---

## 7. Deployment Options

### Console Deployment

#### Step 1: Create the Managed Prefix Lists
Create two Customer-Managed Prefix Lists in the AWS VPC Console (or via AWS CLI):
* **Cloudflare-IPv4**: Address family `IPv4`, Max entries `30` (Cloudflare currently has ~15-20 IPv4 CIDRs).
* **Cloudflare-IPv6**: Address family `IPv6`, Max entries `15` (Cloudflare currently has ~7 IPv6 CIDRs).

#### Step 2: Create the Amazon SNS Topic
1. Create a Standard SNS Topic (e.g., `cloudflare-prefix-list-updates`).
2. Subscribe your SecOps distribution list, Slack webhook integration, or PagerDuty service to the topic.
3. Note the Topic ARN.

#### Step 3: Deploy the Lambda Function
1. Create a Python 3.11+ Lambda function named `cf-whitelisting-reconciliation`.
2. Attach an IAM role using the policy template in [`cf-whitelisting-reconciliation-lambda-role.json`](./cf-whitelisting-reconciliation-lambda-role.json) (replace `<acc_id>` with your AWS Account ID).
3. Paste the contents of [`lambda_function.py`](./lambda_function.py).
4. Configure the environment variables (`PREFIX_LIST_ID_V4`, `PREFIX_LIST_ID_V6`, `SNS_TOPIC_ARN`, etc.).
5. Set the Lambda timeout to `30 seconds`.

#### Step 4: Configure EventBridge Scheduler
1. Navigate to **Amazon EventBridge** > **Schedules**.
2. Create a recurring schedule (e.g., `rate(6 hours)` or `cron(0 0 * * ? *)`).
3. Set the target to your Lambda function `cf-whitelisting-reconciliation`.

---

## 8. Enforce in Security Groups

Once prefix lists are provisioned (via CloudFormation or manually):
1. Open the Security Group attached to your ALB or EC2 origin.
2. Remove any existing inbound rules permitting `0.0.0.0/0` on ports `80` and `443`.
3. Add inbound rules:
   * **HTTPS (443)** -> Source: Custom -> Choose `pl-xxxxxxxx` (Cloudflare IPv4 Prefix List).
   * **HTTPS (443)** -> Source: Custom -> Choose `pl-yyyyyyyy` (Cloudflare IPv6 Prefix List).
   * *(Optional)* **HTTP (80)** -> Same prefix lists if redirecting HTTP to HTTPS at the origin.

---

## 9. Example SNS Notification Payload

When Cloudflare publishes a new CIDR range, subscribers receive a formatted notification:

```text
Subject: [Security Alert] Cloudflare Prefix List Updated (IPV4)

Cloudflare Managed Prefix List Reconciliation Alert
==================================================
Timestamp (UTC): 2026-09-13T12:45:00Z
Status         : Successfully updated 1 prefix list(s) (IPV4)

Changes Applied:
[IPV4 Prefix List: pl-xxxxxxxx]
  - Version Change: 3 -> 4
  - Added CIDRs (1): 198.41.128.0/17
  - Removed CIDRs (0): None
  - Tagged timestamp: 2026-09-13T12:45:00Z

Details (JSON):
[
  {
    "family": "ipv4",
    "prefix_list_id": "pl-xxxxxxxx",
    "version_before": 3,
    "version_after": 4,
    "current_count": 15,
    "desired_count": 16,
    "unchanged": 15,
    "to_add": [
      "198.41.128.0/17"
    ],
    "to_remove": [],
    "action": "modified",
    "last_updated": "2026-09-13T12:45:00Z"
  }
]
```
