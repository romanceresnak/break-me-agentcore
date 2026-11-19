variable "region" {
  description = "Region for the sandbox shop and the Tool API."
  type        = string
  default     = "us-east-1" # BMA preview: us-east-1, us-east-2, us-west-2
}

variable "approver_secret" {
  description = "HMAC secret of the human approval channel (Slack app / CLI). Never given to the agent."
  type        = string
  sensitive   = true
}

variable "approval_email" {
  description = "Where approval requests are sent (SNS email subscription). Empty = none."
  type        = string
  default     = ""
}

variable "budget_usd" {
  description = "Monthly budget for the sandbox account; arena is switched off above it."
  type        = number
  default     = 60
}

variable "enable_rds" {
  description = "Create the prod-orders RDS instance (about 13 USD/month). Off = sandbox fakes it."
  type        = bool
  default     = true
}

variable "scp_target_id" {
  description = "Organizations account/OU id to attach the compiled SCP to. Empty = skip (needs the management account)."
  type        = string
  default     = ""
}

variable "exec_host_instance_type" {
  description = "Instance type of the Managed Agent exec host (codex exec-server + MCP server)."
  type        = string
  default     = "t4g.small"
}
