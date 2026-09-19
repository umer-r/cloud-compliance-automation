variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "AWS region for resources"
}

variable "prefix_list_name_ipv4" {
  type        = string
  default     = "pl-cloudflare-ipv4"
  description = "Name for the IPv4 Customer-Managed Prefix List"
}

variable "prefix_list_name_ipv6" {
  type        = string
  default     = "pl-cloudflare-ipv6"
  description = "Name for the IPv6 Customer-Managed Prefix List"
}

variable "max_entries_ipv4" {
  type        = number
  default     = 30
  description = "Maximum entry capacity for IPv4 prefix list (Cloudflare currently has ~15 CIDRs)"
}

variable "max_entries_ipv6" {
  type        = number
  default     = 15
  description = "Maximum entry capacity for IPv6 prefix list (Cloudflare currently has ~7 CIDRs)"
}

variable "utilise_sns" {
  type        = bool
  default     = true
  description = "Set to true to enable SNS notifications on IP updates, or false to completely disable SNS alerting"
}

variable "create_sns" {
  type        = bool
  default     = true
  description = "If utilise_sns is true, set to true to create a new SNS topic, or false to use an existing SNS topic ARN"
}

variable "existing_sns_topic_arn" {
  type        = string
  default     = ""
  description = "ARN of the existing SNS topic (required if utilise_sns is true and create_sns is false)"
}

variable "sns_topic_name" {
  type        = string
  default     = "sns-cloudflare-pl-updates"
  description = "Name of the SNS topic to create if utilise_sns and create_sns are true"
}

variable "safety_threshold" {
  type        = number
  default     = 3
  description = "Maximum allowed CIDR removals per reconciliation before failing closed"
}

variable "schedule_expression" {
  type        = string
  default     = "rate(6 hours)"
  description = "EventBridge Scheduler schedule expression (e.g., rate(6 hours) or cron(0 0 * * ? *))"
}

variable "lambda_function_name" {
  type        = string
  default     = "cf-whitelisting-reconciliation"
  description = "Name of the reconciliation Lambda function"
}

variable "log_retention_days" {
  type        = number
  default     = 30
  description = "Number of days to retain CloudWatch logs"
}
