# AWS Security — Cloud Security Architecture & Automation

![AWS](https://img.shields.io/badge/AWS-232F3E?style=for-the-badge&logo=amazon-aws&logoColor=white)
![Security](https://img.shields.io/badge/Security-FF0000?style=for-the-badge&logo=amazon-aws&logoColor=white)
![Terraform](https://img.shields.io/badge/Terraform-7B42BC?style=for-the-badge&logo=terraform&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg)

> Production-ready AWS security architectures, IAM policies, GuardDuty configurations, CloudFormation/Terraform templates, Sigma detection rules, and compliance automation aligned with NIST 800-53, CIS Benchmarks, and AWS Well-Architected Security Pillar.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Repository Structure](#repository-structure)
- [IAM Security](#iam-security)
- [GuardDuty & Threat Detection](#guardduty--threat-detection)
- [CloudTrail & Logging](#cloudtrail--logging)
- [Network Security](#network-security)
- [Sigma Detection Rules](#sigma-detection-rules)
- [Compliance Automation](#compliance-automation)
- [Infrastructure as Code](#infrastructure-as-code)
- [Incident Response](#incident-response)
- [Contributing](#contributing)

---

## Overview

This repository provides a comprehensive AWS security framework covering identity management, threat detection, logging, network segmentation, compliance automation, and incident response for enterprise and government cloud environments.

### Security Domains Covered

| Domain | AWS Services | Focus Area |
|---|---|---|
| **Identity & Access** | IAM, Organizations, SSO, STS | Least privilege, role-based access, federation |
| **Detection** | GuardDuty, Security Hub, Detective | Threat detection, anomaly analysis |
| **Logging & Monitoring** | CloudTrail, CloudWatch, VPC Flow Logs | Centralized logging, alerting |
| **Network Security** | VPC, Security Groups, NACLs, WAF | Segmentation, DDoS protection |
| **Data Protection** | KMS, Secrets Manager, Macie | Encryption, secret management, data classification |
| **Compliance** | Config, Audit Manager, Security Hub | CIS, NIST 800-53, SOC 2, PCI-DSS |
| **Incident Response** | Lambda, Step Functions, EventBridge | Automated response playbooks |

---

## Architecture

### AWS Security Reference Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     AWS Organizations                            │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                  Management Account                       │   │
│  │  ┌─────────┐ ┌──────────┐ ┌────────────┐ ┌───────────┐  │   │
│  │  │   IAM   │ │CloudTrail│ │  AWS Config│ │ Org Policies│ │   │
│  │  │ Identity│ │  (Org)   │ │  (Org)     │ │   SCPs     │  │   │
│  │  │ Center  │ │          │ │            │ │            │  │   │
│  │  └─────────┘ └──────────┘ └────────────┘ └───────────┘  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌─────────────────────┐  ┌─────────────────────────────────┐   │
│  │   Security Account  │  │      Log Archive Account         │   │
│  │ ┌─────────────────┐ │  │ ┌─────────────┐ ┌────────────┐  │   │
│  │ │  GuardDuty      │ │  │ │ CloudTrail  │ │ VPC Flow   │  │   │
│  │ │  (Delegated)    │ │  │ │   S3 Bucket │ │ Logs Bucket│  │   │
│  │ │  Security Hub   │ │  │ │             │ │            │  │   │
│  │ │  Detective      │ │  │ │ Config      │ │ GuardDuty  │  │   │
│  │ │  Macie          │ │  │ │ Snapshots   │ │ Findings   │  │   │
│  │ └─────────────────┘ │  │ └─────────────┘ └────────────┘  │   │
│  └─────────────────────┘  └─────────────────────────────────┘   │
│                                                                  │
│  ┌─────────────────────┐  ┌─────────────────────────────────┐   │
│  │  Production Account │  │    Development Account           │   │
│  │  ┌──────┐ ┌──────┐  │  │  ┌──────┐ ┌──────┐             │   │
│  │  │ VPC  │ │ WAF  │  │  │  │ VPC  │ │ IAM  │             │   │
│  │  │ EC2  │ │ KMS  │  │  │  │ EC2  │ │ Roles│             │   │
│  │  │ RDS  │ │ S3   │  │  │  │ S3   │ │      │             │   │
│  │  └──────┘ └──────┘  │  │  └──────┘ └──────┘             │   │
│  └─────────────────────┘  └─────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Repository Structure

```
aws-security/
├── README.md
├── iam/
│   ├── policies/
│   │   ├── least-privilege-admin.json
│   │   ├── security-audit-readonly.json
│   │   ├── s3-restricted-access.json
│   │   ├── deny-root-account.json
│   │   └── enforce-mfa.json
│   ├── roles/
│   │   ├── incident-response-role.json
│   │   ├── security-audit-role.json
│   │   └── cross-account-role.json
│   ├── scp/
│   │   ├── deny-regions.json
│   │   ├── deny-leave-org.json
│   │   ├── require-encryption.json
│   │   └── deny-public-s3.json
│   └── docs/
│       └── iam-best-practices.md
├── guardduty/
│   ├── threat-intel-lists/
│   │   └── custom-threat-ips.txt
│   ├── suppression-rules/
│   │   └── guardduty-suppressions.json
│   ├── notification/
│   │   └── guardduty-eventbridge-rule.json
│   └── docs/
│       └── guardduty-operations.md
├── cloudtrail/
│   ├── configurations/
│   │   └── org-trail-config.json
│   ├── athena-queries/
│   │   ├── unauthorized-api-calls.sql
│   │   ├── iam-changes.sql
│   │   ├── console-logins.sql
│   │   ├── s3-data-events.sql
│   │   └── security-group-changes.sql
│   └── docs/
│       └── cloudtrail-analysis.md
├── network/
│   ├── vpc/
│   │   └── secure-vpc-template.yaml
│   ├── security-groups/
│   │   └── baseline-security-groups.yaml
│   ├── nacls/
│   │   └── network-acl-rules.yaml
│   └── waf/
│       └── waf-rules.json
├── sigma-rules/
│   ├── cloudtrail/
│   │   ├── aws-root-account-usage.yml
│   │   ├── aws-iam-user-creation.yml
│   │   ├── aws-s3-public-access.yml
│   │   ├── aws-security-group-modification.yml
│   │   ├── aws-cloudtrail-disabled.yml
│   │   ├── aws-unauthorized-api-call.yml
│   │   ├── aws-console-login-without-mfa.yml
│   │   └── aws-ec2-keypair-created.yml
│   └── guardduty/
│       ├── aws-guardduty-high-severity.yml
│       └── aws-guardduty-crypto-mining.yml
├── compliance/
│   ├── cis-benchmark/
│   │   ├── cis-aws-checks.sh
│   │   └── cis-remediation-guide.md
│   ├── nist-800-53/
│   │   └── nist-control-mapping.md
│   └── config-rules/
│       └── custom-config-rules.yaml
├── terraform/
│   ├── modules/
│   │   ├── guardduty/
│   │   │   └── main.tf
│   │   ├── cloudtrail/
│   │   │   └── main.tf
│   │   ├── security-hub/
│   │   │   └── main.tf
│   │   └── vpc-security/
│   │       └── main.tf
│   └── environments/
│       ├── production/
│       │   └── main.tf
│       └── development/
│           └── main.tf
├── incident-response/
│   ├── playbooks/
│   │   ├── compromised-iam-credentials.md
│   │   ├── compromised-ec2-instance.md
│   │   ├── s3-data-breach.md
│   │   └── ransomware-response.md
│   └── lambda/
│       ├── auto-remediate-sg.py
│       ├── auto-disable-iam-key.py
│       └── quarantine-ec2-instance.py
└── docs/
    ├── security-architecture.md
    ├── logging-strategy.md
    └── shared-responsibility.md
```

---

## IAM Security

### Service Control Policies (SCPs)

SCPs are organization-level guardrails that restrict what member accounts can do:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyRootAccountUsage",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:root"
        }
      }
    },
    {
      "Sid": "DenyLeavingOrganization",
      "Effect": "Deny",
      "Action": "organizations:LeaveOrganization",
      "Resource": "*"
    },
    {
      "Sid": "RequireIMDSv2",
      "Effect": "Deny",
      "Action": "ec2:RunInstances",
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": {
        "StringNotEquals": {
          "ec2:MetadataHttpTokens": "required"
        }
      }
    }
  ]
}
```

### IAM Best Practices Checklist

| # | Practice | Priority |
|---|---|---|
| 1 | Enable MFA on all IAM users (hardware for root) | Critical |
| 2 | Never use root account for daily operations | Critical |
| 3 | Implement least privilege with IAM Access Analyzer | High |
| 4 | Rotate access keys every 90 days | High |
| 5 | Use IAM roles instead of long-term credentials | High |
| 6 | Enable AWS SSO for centralized access management | High |
| 7 | Use permission boundaries for delegated admin | Medium |
| 8 | Monitor with CloudTrail and set up alerts | Critical |
| 9 | Review IAM policies quarterly | Medium |
| 10 | Tag all IAM resources for governance | Medium |

---

## GuardDuty & Threat Detection

### GuardDuty Finding Types (Key Threats)

| Finding | Severity | Description | Response |
|---|---|---|---|
| UnauthorizedAccess:IAMUser/MaliciousIPCaller | High | API call from known malicious IP | Investigate source, rotate credentials |
| Recon:EC2/PortProbeUnprotectedPort | Medium | Port scan on unprotected EC2 port | Review security groups, block source |
| CryptoCurrency:EC2/BitcoinTool.B!DNS | High | EC2 querying crypto mining domains | Isolate instance, investigate compromise |
| Trojan:EC2/BlackholeTraffic | High | EC2 sending traffic to black hole IPs | Quarantine instance immediately |
| UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B | Medium | Console login from unusual location | Verify with user, review CloudTrail |
| Exfiltration:S3/AnomalousBehavior | High | Unusual S3 data access patterns | Review S3 access logs, check for breach |
| Impact:EC2/WinRMBruteForce | High | WinRM brute force attempt | Block source IP, patch/harden instance |

---

## Sigma Detection Rules

### Example: Root Account Usage Detection

```yaml
title: AWS Root Account Usage
id: aws-root-001
status: stable
level: critical
description: Detects any usage of the AWS root account, which should be reserved for emergency access only.
author: Shakil Md. Rezwanul Bari
date: 2024/01/15
references:
    - https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
    - https://d1.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        userIdentity.type: Root
        userIdentity.invokedBy: ''
    filter_service:
        eventType: AwsServiceEvent
    condition: selection and not filter_service
falsepositives:
    - Emergency break-glass access (should be rare and documented)
    - Initial account setup
tags:
    - attack.initial_access
    - attack.privilege_escalation
    - attack.t1078.004
```

### Example: CloudTrail Disabled

```yaml
title: AWS CloudTrail Logging Disabled
id: aws-ct-001
status: stable
level: critical
description: Detects when CloudTrail logging is stopped or deleted, which may indicate an attacker covering their tracks.
author: Shakil Md. Rezwanul Bari
date: 2024/01/15
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventName:
            - StopLogging
            - DeleteTrail
            - UpdateTrail
    condition: selection
falsepositives:
    - Authorized trail maintenance (rare)
tags:
    - attack.defense_evasion
    - attack.t1562.008
```

---

## Incident Response

### Compromised IAM Credentials Playbook

```
┌─────────────────────────────────────────────┐
│        PHASE 1: DETECTION & TRIAGE          │
│  1. Alert from GuardDuty/CloudTrail         │
│  2. Identify affected IAM principal         │
│  3. Assess scope of unauthorized activity   │
└───────────────────┬─────────────────────────┘
                    │
┌───────────────────▼─────────────────────────┐
│        PHASE 2: CONTAINMENT                 │
│  1. Disable compromised access keys         │
│  2. Revoke active sessions (inline deny)    │
│  3. Attach quarantine policy to user/role   │
│  4. Preserve CloudTrail logs                │
└───────────────────┬─────────────────────────┘
                    │
┌───────────────────▼─────────────────────────┐
│        PHASE 3: INVESTIGATION               │
│  1. Query CloudTrail for all actions taken   │
│  2. Identify resource modifications          │
│  3. Check for persistence mechanisms         │
│  4. Review IAM changes and new credentials   │
└───────────────────┬─────────────────────────┘
                    │
┌───────────────────▼─────────────────────────┐
│        PHASE 4: REMEDIATION                 │
│  1. Rotate all credentials                  │
│  2. Remove unauthorized resources           │
│  3. Patch access vectors                    │
│  4. Update IAM policies                     │
└───────────────────┬─────────────────────────┘
                    │
┌───────────────────▼─────────────────────────┐
│        PHASE 5: LESSONS LEARNED             │
│  1. Document timeline and root cause        │
│  2. Update detection rules                  │
│  3. Implement preventive controls           │
│  4. Conduct post-incident review            │
└─────────────────────────────────────────────┘
```

---

## Compliance Automation

### CIS AWS Foundations Benchmark Mapping

| CIS Control | AWS Service | Auto-Remediation |
|---|---|---|
| 1.1 - Avoid root account use | CloudTrail + EventBridge | Alert + notify |
| 1.4 - Rotate access keys ≤ 90 days | IAM Access Analyzer | Lambda auto-disable |
| 1.10 - Enable MFA on all IAM users | Config Rule | Alert + notify |
| 2.1 - Enable CloudTrail in all regions | CloudTrail (org trail) | Preventive (SCP) |
| 2.6 - Enable S3 bucket access logging | Config Rule | Lambda auto-enable |
| 2.9 - Enable VPC Flow Logs | Config Rule | Lambda auto-enable |
| 3.1-3.14 - CloudWatch metric alarms | CloudWatch + SNS | Auto-alerting |
| 4.1 - No security groups allow 0.0.0.0/0 ingress | Config Rule | Lambda auto-remediate |

---

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests.

## License

This project is licensed under the MIT License.

---

> **Maintained by [Shakil Md. Rezwanul Bari](https://github.com/mrezwanulbari)** — Cybersecurity & Cloud Security Engineer focused on critical infrastructure protection and national cybersecurity.
