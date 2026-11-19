# ------------------------------------------------------------------ state
resource "aws_dynamodb_table" "state" {
  for_each     = { sessions = "id", approvals = "id", tickets = "id", events = "pk" }
  name         = "${local.name}-${each.key}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = each.value
  range_key    = each.key == "events" ? "ts" : null

  attribute {
    name = each.value
    type = "S"
  }
  dynamic "attribute" {
    for_each = each.key == "events" ? [1] : []
    content {
      name = "ts"
      type = "N"
    }
  }
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
}

resource "aws_sns_topic" "approvals" {
  name = "${local.name}-approvals"
}

resource "aws_sns_topic_subscription" "approvals_email" {
  count     = var.approval_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.approvals.arn
  protocol  = "email"
  endpoint  = var.approval_email
}

# ------------------------------------------------------------------ Tool API Lambda
# Built by `make lambda` into build/tool_api (breakme package + generated/ + cedarpy wheel).
data "archive_file" "tool_api" {
  type        = "zip"
  source_dir  = "${path.module}/../../build/tool_api"
  output_path = "${path.module}/../../build/tool_api.zip"
}

resource "aws_lambda_function" "tools" {
  function_name    = "${local.name}-tool-api"
  role             = aws_iam_role.tool.arn
  runtime          = "python3.12"
  architectures    = ["x86_64"]
  handler          = "breakme.tool_api.handler"
  filename         = data.archive_file.tool_api.output_path
  source_code_hash = data.archive_file.tool_api.output_base64sha256
  timeout          = 30
  memory_size      = 512
  environment {
    variables = {
      BREAKME_GUARDRAIL_ID       = aws_bedrock_guardrail.agent.guardrail_id
      BREAKME_GUARDRAIL_VERSION  = aws_bedrock_guardrail_version.agent.version
      BREAKME_APPROVER_SECRET    = var.approver_secret
      BREAKME_APPROVAL_TOPIC_ARN = aws_sns_topic.approvals.arn
      BREAKME_SESSIONS_TABLE     = aws_dynamodb_table.state["sessions"].name
      BREAKME_APPROVALS_TABLE    = aws_dynamodb_table.state["approvals"].name
      BREAKME_EVENTS_TABLE       = aws_dynamodb_table.state["events"].name
      BREAKME_TICKETS_TABLE      = aws_dynamodb_table.state["tickets"].name
      BREAKME_RESOURCE_MAP       = jsonencode(local.resource_map)
    }
  }
}

resource "aws_apigatewayv2_api" "tools" {
  name          = "${local.name}-tools"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "tools" {
  api_id                 = aws_apigatewayv2_api.tools.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.tools.invoke_arn
  payload_format_version = "2.0"
}

# Tool calls: IAM (SigV4) auth - only the exec host role can call them.
resource "aws_apigatewayv2_route" "tools" {
  api_id             = aws_apigatewayv2_api.tools.id
  route_key          = "POST /tools/{name}"
  target             = "integrations/${aws_apigatewayv2_integration.tools.id}"
  authorization_type = "AWS_IAM"
}

# Approval channel: authenticated by the approver HMAC inside the Lambda (Slack app posts here).
resource "aws_apigatewayv2_route" "approve" {
  api_id    = aws_apigatewayv2_api.tools.id
  route_key = "POST /approvals/{id}"
  target    = "integrations/${aws_apigatewayv2_integration.tools.id}"
}

resource "aws_apigatewayv2_route" "read" {
  for_each           = toset(["GET /approvals", "GET /events"])
  api_id             = aws_apigatewayv2_api.tools.id
  route_key          = each.value
  target             = "integrations/${aws_apigatewayv2_integration.tools.id}"
  authorization_type = "AWS_IAM"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.tools.id
  name        = "$default"
  auto_deploy = true
  default_route_settings {
    throttling_burst_limit = 20
    throttling_rate_limit  = 10
  }
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "apigw"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.tools.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.tools.execution_arn}/*/*"
}
