# ------------------------------------------------------------------ deploy bucket
# CloudShell uploads the repo and the BMA example bundle here; the exec host pulls them.
resource "aws_s3_bucket" "deploy" {
  bucket_prefix = "${local.name}-deploy-"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "deploy" {
  bucket                  = aws_s3_bucket.deploy.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

output "deploy_bucket" {
  value = aws_s3_bucket.deploy.id
}
