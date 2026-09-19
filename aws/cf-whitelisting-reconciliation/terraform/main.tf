data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# package the production lambda_function.py into a zip archive
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../lambda_function.py"
  output_path = "${path.module}/lambda_function.zip"
}

locals {
  target_sns_topic_arn = var.utilise_sns ? (
    var.create_sns ? aws_sns_topic.cf_updates[0].arn : var.existing_sns_topic_arn
  ) : ""
}

# Customer-Managed Prefix Lists
resource "aws_ec2_managed_prefix_list" "ipv4" {
  name           = var.prefix_list_name_ipv4
  address_family = "IPv4"
  max_entries    = var.max_entries_ipv4

  tags = {
    Name = var.prefix_list_name_ipv4
  }
}

resource "aws_ec2_managed_prefix_list" "ipv6" {
  name           = var.prefix_list_name_ipv6
  address_family = "IPv6"
  max_entries    = var.max_entries_ipv6

  tags = {
    Name = var.prefix_list_name_ipv6
  }
}

# Amazon SNS Topic (Created only if utilise_sns=true and create_sns=true)
resource "aws_sns_topic" "cf_updates" {
  count        = var.utilise_sns && var.create_sns ? 1 : 0
  name         = var.sns_topic_name
  display_name = "Cloudflare Prefix List Reconcile Alerts"
}

# CloudWatch Log Group for Lambda Function
resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${var.lambda_function_name}"
  retention_in_days = var.log_retention_days
}

# IAM Execution Role & Policies for Lambda Function
resource "aws_iam_role" "lambda_exec" {
  name = "${var.lambda_function_name}-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_logs" {
  name = "CloudWatchLogsAccess"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          aws_cloudwatch_log_group.lambda.arn,
          "${aws_cloudwatch_log_group.lambda.arn}:*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_prefix_lists" {
  name = "PrefixListsAccess"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DescribePrefixLists"
        Effect = "Allow"
        Action = [
          "ec2:DescribeManagedPrefixLists",
          "ec2:GetManagedPrefixListEntries"
        ]
        Resource = "*"
      },
      {
        Sid    = "ModifyManagedPrefixLists"
        Effect = "Allow"
        Action = [
          "ec2:ModifyManagedPrefixList",
          "ec2:CreateTags"
        ]
        Resource = [
          aws_ec2_managed_prefix_list.ipv4.arn,
          aws_ec2_managed_prefix_list.ipv6.arn
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_sns" {
  count = var.utilise_sns && (var.create_sns || var.existing_sns_topic_arn != "") ? 1 : 0
  name  = "PublishToSNSTopicAccess"
  role  = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = local.target_sns_topic_arn
      }
    ]
  })
}

# AWS Lambda Reconciliation Function
resource "aws_lambda_function" "reconcile" {
  function_name    = var.lambda_function_name
  description      = "Safely synchronizes Cloudflare proxy IPs into AWS Managed Prefix Lists with fail-closed checks"
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 128
  role             = aws_iam_role.lambda_exec.arn

  environment {
    variables = {
      PREFIX_LIST_ID_V4 = aws_ec2_managed_prefix_list.ipv4.id
      PREFIX_LIST_ID_V6 = aws_ec2_managed_prefix_list.ipv6.id
      SNS_TOPIC_ARN     = local.target_sns_topic_arn
      SAFETY_THRESHOLD  = tostring(var.safety_threshold)
      AWS_REGION        = var.aws_region
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda,
    aws_iam_role_policy.lambda_logs
  ]
}

# EventBridge Scheduler Execution Role & Policy
resource "aws_iam_role" "scheduler" {
  name = "${var.lambda_function_name}-scheduler-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "scheduler.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "scheduler_invoke" {
  name = "InvokeLambdaFunction"
  role = aws_iam_role.scheduler.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "lambda:InvokeFunction"
        Resource = aws_lambda_function.reconcile.arn
      }
    ]
  })
}

# EventBridge Scheduler Schedule
resource "aws_scheduler_schedule" "reconcile" {
  name        = "${var.lambda_function_name}-schedule"
  description = "Periodic schedule triggering Cloudflare prefix list reconciliation"

  schedule_expression = var.schedule_expression

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_lambda_function.reconcile.arn
    role_arn = aws_iam_role.scheduler.arn

    retry_policy {
      maximum_retry_attempts       = 2
      maximum_event_age_in_seconds = 3600
    }
  }
}
