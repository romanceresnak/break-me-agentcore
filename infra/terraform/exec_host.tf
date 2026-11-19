# ------------------------------------------------------------------ Managed Agent exec host
# Runs `codex exec-server` (from the BMA example bundle) and the BREAK ME MCP server.
# No SSH: access via SSM Session Manager. Egress only (BMA endpoint + Tool API).

resource "aws_security_group" "exec_host" {
  name        = "${local.name}-exec-host"
  description = "BMA exec host: no inbound, HTTPS outbound only"
  vpc_id      = aws_vpc.main.id
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "exec_host" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = var.exec_host_instance_type
  subnet_id              = aws_subnet.public[0].id
  iam_instance_profile   = aws_iam_instance_profile.exec_host.name
  vpc_security_group_ids = [aws_security_group.exec_host.id]
  metadata_options {
    http_tokens = "required"
  }
  user_data = <<-EOT
    #!/bin/bash
    set -euo pipefail
    dnf install -y python3.12 python3.12-pip git nodejs
    mkdir -p /opt/break-me/workspace/skills
    cat > /etc/profile.d/break-me.sh <<EOF
    export BREAKME_TOOL_API_URL=${aws_apigatewayv2_stage.default.invoke_url}
    export AWS_REGION=${var.region}
    export BMA_REGION=${var.region}
    export BMA_WORKSPACE_DIRECTORY=/opt/break-me/workspace
    EOF
    # Next (manual, see README): copy the repo + BMA example bundle, pip install -r requirements.txt,
    # then run scripts/bma/1.attach-exec-server.sh from the bundle.
  EOT
  tags = { Name = "${local.name}-exec-host" }
  lifecycle {
    ignore_changes = [ami, user_data] # a new AMI must not silently rebuild the host
  }
}
