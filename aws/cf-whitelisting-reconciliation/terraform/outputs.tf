output "prefix_list_ipv4_id" {
  description = "Managed Prefix List ID for IPv4 (attach to Security Groups on port 80/443)"
  value       = aws_ec2_managed_prefix_list.ipv4.id
}

output "prefix_list_ipv4_arn" {
  description = "Managed Prefix List ARN for IPv4"
  value       = aws_ec2_managed_prefix_list.ipv4.arn
}

output "prefix_list_ipv6_id" {
  description = "Managed Prefix List ID for IPv6 (attach to Security Groups on port 80/443)"
  value       = aws_ec2_managed_prefix_list.ipv6.id
}

output "prefix_list_ipv6_arn" {
  description = "Managed Prefix List ARN for IPv6"
  value       = aws_ec2_managed_prefix_list.ipv6.arn
}

output "sns_topic_arn" {
  description = "Amazon SNS Topic ARN receiving alerts on Cloudflare IP range changes"
  value       = local.target_sns_topic_arn
}

output "lambda_function_arn" {
  description = "Reconciliation Lambda Function ARN"
  value       = aws_lambda_function.reconcile.arn
}

output "scheduler_schedule_arn" {
  description = "Amazon EventBridge Scheduler Schedule ARN"
  value       = aws_scheduler_schedule.reconcile.arn
}
