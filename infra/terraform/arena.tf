# ------------------------------------------------------------------ public arena API
# Runs attempts against an in-memory copy of the shop: the real Bedrock Guardrail, the
# compiled Cedar policies and the simulated boundary. It has no access to the sandbox
# resources at all, so the arena can be public.

resource "aws_s3_bucket" "arena" {
  bucket_prefix = "${local.name}-arena-"
  force_destroy = true
}

resource "aws_dynamodb_table" "arena_rate" {
  name         = "${local.name}-arena-rate"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  attribute {
    name = "id"
    type = "S"
  }
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
}

resource "aws_iam_role" "arena" {
  name = "${local.name}-arena"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "arena" {
  name = "arena"
  role = aws_iam_role.arena.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"], Resource = "${aws_s3_bucket.arena.arn}/*" },
      { Effect = "Allow", Action = ["s3:ListBucket"], Resource = aws_s3_bucket.arena.arn },
      { Effect = "Allow", Action = ["dynamodb:UpdateItem"], Resource = aws_dynamodb_table.arena_rate.arn },
      { Effect = "Allow", Action = ["bedrock:ApplyGuardrail"], Resource = aws_bedrock_guardrail.agent.guardrail_arn },
      { Effect = "Allow", Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], Resource = "*" },
    ]
  })
}

resource "aws_lambda_function" "arena" {
  function_name    = "${local.name}-arena"
  role             = aws_iam_role.arena.arn
  runtime          = "python3.12"
  architectures    = ["x86_64"]
  handler          = "breakme.arena_api.handler"
  filename         = data.archive_file.tool_api.output_path
  source_code_hash = data.archive_file.tool_api.output_base64sha256
  timeout          = 60
  memory_size      = 1024
  reserved_concurrent_executions = 5
  environment {
    variables = {
      BREAKME_ARENA_BUCKET      = aws_s3_bucket.arena.id
      BREAKME_RATE_TABLE        = aws_dynamodb_table.arena_rate.name
      BREAKME_GUARDRAIL_ID      = aws_bedrock_guardrail.agent.guardrail_id
      BREAKME_GUARDRAIL_VERSION = aws_bedrock_guardrail_version.agent.version
      BREAKME_RESULTS           = "/tmp/results"
    }
  }
}

resource "aws_apigatewayv2_api" "arena" {
  name          = "${local.name}-arena"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "arena" {
  api_id                 = aws_apigatewayv2_api.arena.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.arena.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "arena" {
  for_each  = toset(["GET /api/feed", "GET /api/summary", "GET /api/leaderboard", "POST /api/arena", "POST /api/campaign"])
  api_id    = aws_apigatewayv2_api.arena.id
  route_key = each.value
  target    = "integrations/${aws_apigatewayv2_integration.arena.id}"
}

resource "aws_apigatewayv2_stage" "arena" {
  api_id      = aws_apigatewayv2_api.arena.id
  name        = "$default"
  auto_deploy = true
  default_route_settings {
    throttling_burst_limit = 10
    throttling_rate_limit  = 5
  }
}

resource "aws_lambda_permission" "arena" {
  statement_id  = "apigw"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.arena.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.arena.execution_arn}/*/*"
}

resource "aws_wafv2_web_acl" "arena" {
  provider = aws.us_east_1
  name     = "${local.name}-arena"
  scope    = "CLOUDFRONT"
  default_action {
    allow {}
  }
  rule {
    name     = "rate-per-ip"
    priority = 1
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = 300
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-per-ip"
      sampled_requests_enabled   = true
    }
  }
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name}-arena"
    sampled_requests_enabled   = true
  }
}

provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}
