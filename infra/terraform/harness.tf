# ------------------------------------------------------------------ AgentCore harness execution role
# The harness runs the blue agent's loop in a microVM. Its role may call the model and
# write logs - nothing else. Every AWS action the agent takes goes through inline tools,
# which our client routes to the Tool API (Cedar + IAM boundary). So even the harness's
# built-in shell, if it were ever reached, holds no credentials that can touch the shop.

resource "aws_iam_role" "harness" {
  name = "${local.name}-harness"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "bedrock-agentcore.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.account_id }
        ArnLike      = { "aws:SourceArn" = "arn:aws:bedrock-agentcore:${var.region}:${local.account_id}:*" }
      }
    }]
  })
}

resource "aws_iam_role_policy" "harness" {
  name = "model-and-logs-only"
  role = aws_iam_role.harness.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "InvokeModel", Effect = "Allow",
        Action   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
        Resource = ["arn:aws:bedrock:*::foundation-model/*", "arn:aws:bedrock:*:${local.account_id}:inference-profile/*"] },
      { Sid = "Logs", Effect = "Allow",
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
        Resource = "arn:aws:logs:${var.region}:${local.account_id}:log-group:/aws/bedrock-agentcore/*" },
      { Sid = "Traces", Effect = "Allow",
        Action   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords", "cloudwatch:PutMetricData"],
        Resource = "*" },
      # Belt and braces: nothing else, even if someone attaches a broader policy later.
      { Sid = "DenyEverythingElse", Effect = "Deny",
        NotAction = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream", "logs:*", "xray:*",
                     "cloudwatch:PutMetricData", "bedrock-agentcore:*", "ecr:GetAuthorizationToken",
                     "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
        Resource = "*" },
    ]
  })
}

output "harness_role_arn" {
  description = "Pass to: python -m breakme harness-create --role-arn <this>"
  value       = aws_iam_role.harness.arn
}
