# BREAK ME - sandbox account infrastructure.
# Everything that enforces a rule is read from ../../generated (compiled from rules/rules.yaml),
# so `make compile && terraform apply` is the only way a rule change reaches AWS.

terraform {
  required_version = ">= 1.7"
  required_providers {
    aws     = { source = "hashicorp/aws", version = ">= 5.80" }
    archive = { source = "hashicorp/archive", version = ">= 2.4" }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { Project = "break-me", ManagedBy = "terraform" }
  }
}

data "aws_caller_identity" "me" {}
data "aws_region" "current" {}

locals {
  name         = "break-me"
  generated    = "${path.module}/../../generated"
  guardrail    = jsondecode(file("${local.generated}/guardrail.json"))
  iam_boundary = file("${local.generated}/iam_boundary.json")
  scp          = file("${local.generated}/scp.json")
  account_id   = data.aws_caller_identity.me.account_id
  services     = ["dev/shop-web", "dev/shop-api", "prod/shop-web", "prod/shop-api", "prod/checkout"]
}
