# =============================================================================
# AWS GuardDuty Terraform Module
# =============================================================================
# Enables GuardDuty with S3 protection, EKS audit log monitoring,
# and SNS notifications for high-severity findings.
# =============================================================================

variable "enable_s3_protection" {
  description = "Enable S3 data event monitoring"
  type        = bool
  default     = true
}

variable "enable_eks_protection" {
  description = "Enable EKS audit log monitoring"
  type        = bool
  default     = true
}

variable "enable_malware_protection" {
  description = "Enable malware protection for EC2"
  type        = bool
  default     = true
}

variable "notification_email" {
  description = "Email address for GuardDuty finding notifications"
  type        = string
}

variable "finding_publishing_frequency" {
  description = "Frequency of finding export: FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS"
  type        = string
  default     = "FIFTEEN_MINUTES"
}

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default     = {}
}

# --- GuardDuty Detector ---
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = var.finding_publishing_frequency

  datasources {
    s3_logs {
      enable = var.enable_s3_protection
    }
    kubernetes {
      audit_logs {
        enable = var.enable_eks_protection
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = var.enable_malware_protection
        }
      }
    }
  }

  tags = merge(var.tags, {
    Service = "GuardDuty"
    Purpose = "Threat Detection"
  })
}

# --- SNS Topic for Notifications ---
resource "aws_sns_topic" "guardduty_alerts" {
  name = "guardduty-high-severity-findings"
  tags = var.tags
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# --- EventBridge Rule for High Severity Findings ---
resource "aws_cloudwatch_event_rule" "guardduty_high" {
  name        = "guardduty-high-severity-findings"
  description = "Triggers on GuardDuty findings with severity >= 7.0"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [
        { numeric = [">=", 7.0] }
      ]
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_high.name
  target_id = "guardduty-to-sns"
  arn       = aws_sns_topic.guardduty_alerts.arn
}

# --- Outputs ---
output "detector_id" {
  description = "GuardDuty detector ID"
  value       = aws_guardduty_detector.main.id
}

output "sns_topic_arn" {
  description = "SNS topic ARN for GuardDuty alerts"
  value       = aws_sns_topic.guardduty_alerts.arn
}
