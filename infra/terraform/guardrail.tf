# ------------------------------------------------------------------ layer 1
resource "aws_bedrock_guardrail" "agent" {
  name                      = local.guardrail.name
  description               = local.guardrail.description
  blocked_input_messaging   = local.guardrail.blockedInputMessaging
  blocked_outputs_messaging = local.guardrail.blockedOutputsMessaging

  content_policy_config {
    dynamic "filters_config" {
      for_each = local.guardrail.contentPolicyConfig.filtersConfig
      content {
        type            = filters_config.value.type
        input_strength  = filters_config.value.inputStrength
        output_strength = filters_config.value.outputStrength
      }
    }
  }

  topic_policy_config {
    dynamic "topics_config" {
      for_each = local.guardrail.topicPolicyConfig.topicsConfig
      content {
        name       = topics_config.value.name
        definition = topics_config.value.definition
        examples   = topics_config.value.examples
        type       = topics_config.value.type
      }
    }
  }

  sensitive_information_policy_config {
    dynamic "pii_entities_config" {
      for_each = local.guardrail.sensitiveInformationPolicyConfig.piiEntitiesConfig
      content {
        type   = pii_entities_config.value.type
        action = pii_entities_config.value.action
      }
    }
    dynamic "regexes_config" {
      for_each = local.guardrail.sensitiveInformationPolicyConfig.regexesConfig
      content {
        name    = regexes_config.value.name
        pattern = regexes_config.value.pattern
        action  = regexes_config.value.action
      }
    }
  }
}

resource "aws_bedrock_guardrail_version" "agent" {
  guardrail_arn = aws_bedrock_guardrail.agent.guardrail_arn
  description   = "rules.yaml ${filesha256("${local.generated}/guardrail.json")}"
}
