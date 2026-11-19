# ------------------------------------------------------------------ Glass Box (static) on CloudFront
resource "aws_s3_bucket" "glassbox" {
  bucket_prefix = "${local.name}-glassbox-"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "glassbox" {
  bucket                  = aws_s3_bucket.glassbox.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_cloudfront_origin_access_control" "glassbox" {
  name                              = "${local.name}-glassbox"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "glassbox" {
  enabled             = true
  default_root_object = "index.html"
  price_class         = "PriceClass_100"
  web_acl_id          = aws_wafv2_web_acl.arena.arn
  origin {
    domain_name              = aws_s3_bucket.glassbox.bucket_regional_domain_name
    origin_id                = "s3"
    origin_access_control_id = aws_cloudfront_origin_access_control.glassbox.id
  }
  origin {
    domain_name = replace(aws_apigatewayv2_stage.arena.invoke_url, "/^https?://([^/]*).*/", "$1")
    origin_id   = "arena-api"
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }
  ordered_cache_behavior {
    path_pattern             = "/api/*"
    target_origin_id         = "arena-api"
    viewer_protocol_policy   = "redirect-to-https"
    allowed_methods          = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods           = ["GET", "HEAD"]
    cache_policy_id          = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad" # CachingDisabled
    origin_request_policy_id = "b689b0a8-53d0-40ab-baf2-68738e2966ac" # AllViewerExceptHostHeader
  }
  default_cache_behavior {
    target_origin_id       = "s3"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    cache_policy_id        = "658327ea-f89d-4fab-a63d-7e88639e58f6" # CachingOptimized
  }
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

resource "aws_s3_bucket_policy" "glassbox" {
  bucket = aws_s3_bucket.glassbox.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow", Principal = { Service = "cloudfront.amazonaws.com" },
      Action    = "s3:GetObject", Resource = "${aws_s3_bucket.glassbox.arn}/*",
      Condition = { StringEquals = { "AWS:SourceArn" = aws_cloudfront_distribution.glassbox.arn } }
    }]
  })
}

resource "aws_s3_object" "glassbox_index" {
  bucket       = aws_s3_bucket.glassbox.id
  key          = "index.html"
  source       = "${path.module}/../../glassbox/index.html"
  etag         = filemd5("${path.module}/../../glassbox/index.html")
  content_type = "text/html; charset=utf-8"
}
