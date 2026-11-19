# ------------------------------------------------------------------ layer 4
# The permissions boundary compiled from rules.yaml. Attached to every role that can
# touch the sandbox on the agent's behalf. A fooled model cannot exceed it.
resource "aws_iam_policy" "boundary" {
  name        = "${local.name}-agent-boundary"
  description = "Compiled from rules/rules.yaml - hard ceiling for anything the agent can cause."
  policy      = local.iam_boundary
}

# ------------------------------------------------------------------ tool role (Tool API Lambda)
resource "aws_iam_role" "tool" {
  name                 = "${local.name}-tool"
  permissions_boundary = aws_iam_policy.boundary.arn
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

# Identity policy is deliberately broad on the allowed surface; the boundary is what limits it.
resource "aws_iam_role_policy" "tool" {
  name = "tool-surface"
  role = aws_iam_role.tool.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = jsondecode(local.iam_boundary).Statement[0].Action, Resource = "*" },
      { Effect = "Allow", Action = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query", "dynamodb:Scan"],
      Resource = [for t in aws_dynamodb_table.state : t.arn] },
      { Effect = "Allow", Action = ["sns:Publish"], Resource = aws_sns_topic.approvals.arn },
      { Effect = "Allow", Action = ["bedrock:ApplyGuardrail"], Resource = aws_bedrock_guardrail.agent.guardrail_arn },
      { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:CreateLogGroup"], Resource = "*" },
    ]
  })
}

# ------------------------------------------------------------------ exec host role
# The Managed Agent can run shell commands on its exec host. So the host gets NO AWS
# permissions except invoking the Tool API: every path to AWS goes through Cedar.
resource "aws_iam_role" "exec_host" {
  name = "${local.name}-exec-host"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "exec_host" {
  name = "invoke-tool-api-only"
  role = aws_iam_role.exec_host.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "execute-api:Invoke",
      Resource = "${aws_apigatewayv2_api.tools.execution_arn}/*/POST/tools/*" },
      # BMA exec-server: register this host as the session's environment and hold the connection.
      # Action names from the AWS example bundle (self-hosted CDK stack).
      { Effect = "Allow", Action = ["bedrock-mantle:RegisterEnvironment", "bedrock-mantle:ConnectEnvironment",
      "bedrock-mantle:GetAgentSession"], Resource = "*" },
      # Pull the repo + BMA bundle from the deploy bucket (read-only).
      { Effect = "Allow", Action = ["s3:GetObject"], Resource = "${aws_s3_bucket.deploy.arn}/*" },
      { Effect = "Allow", Action = ["s3:ListBucket"], Resource = aws_s3_bucket.deploy.arn },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "exec_host_ssm" {
  role       = aws_iam_role.exec_host.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "exec_host" {
  name = "${local.name}-exec-host"
  role = aws_iam_role.exec_host.name
}

# ------------------------------------------------------------------ BMA session role
# Assumed by Bedrock Managed Agents for model inference only.
resource "aws_iam_role" "bma_session" {
  name = "${local.name}-bma-session"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "bedrock-mantle.amazonaws.com" }, Action = "sts:AssumeRole",
    Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } } }]
  })
}

resource "aws_iam_role_policy" "bma_session" {
  name = "inference"
  role = aws_iam_role.bma_session.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["bedrock-mantle:CreateInference"], Resource = "*" }]
  })
}

# ------------------------------------------------------------------ SCP (optional, management account)
resource "aws_organizations_policy" "scp" {
  count       = var.scp_target_id == "" ? 0 : 1
  name        = "${local.name}-sandbox-guard"
  description = "Compiled from rules/rules.yaml"
  type        = "SERVICE_CONTROL_POLICY"
  content     = local.scp
}

resource "aws_organizations_policy_attachment" "scp" {
  count     = var.scp_target_id == "" ? 0 : 1
  policy_id = aws_organizations_policy.scp[0].id
  target_id = var.scp_target_id
}
