output "tool_api_url" {
  value = aws_apigatewayv2_stage.default.invoke_url
}

output "bma_session_role_arn" {
  description = "Use as BMA_INFERENCE_ROLE_ARN when creating the Managed Agent session."
  value       = aws_iam_role.bma_session.arn
}

output "exec_host_instance_id" {
  value = aws_instance.exec_host.id
}

output "guardrail_id" {
  value = aws_bedrock_guardrail.agent.guardrail_id
}

output "glassbox_url" {
  value = "https://${aws_cloudfront_distribution.glassbox.domain_name}"
}

output "resource_map" {
  value = jsonencode(local.resource_map)
}
