### S3
### Source Bucket ###
locals {
  filepath = "./content"
}

resource "random_string" "bucket_random" {
  length           = 4
  upper   = false
  lower   = true
  numeric  = false
  special = false
}

resource "aws_s3_bucket" "source" {
  bucket   = "wsc-frontend-${random_string.bucket_random.result}"
}

resource "aws_s3_object" "static" {
  bucket = aws_s3_bucket.source.id
  key    = "static/index.html"
  source = "${local.filepath}/index.html"
  etag   = filemd5("${local.filepath}/index.html")
  content_type = "text/html"
}

resource "aws_s3_object" "customer" {
  bucket = aws_s3_bucket.source.id
  key    = "customer"
  source = "${local.filepath}/customer"
  etag   = filemd5("${local.filepath}/customer")
  content_type = "application/octet-stream"
}

resource "aws_s3_object" "order" {
  bucket = aws_s3_bucket.source.id
  key    = "order"
  source = "${local.filepath}/order"
  etag   = filemd5("${local.filepath}/order")
  content_type = "application/octet-stream"
}

resource "aws_s3_object" "product" {
  bucket = aws_s3_bucket.source.id
  key    = "product"
  source = "${local.filepath}/product"
  etag   = filemd5("${local.filepath}/product")
  content_type = "application/octet-stream"
}

resource "aws_s3_bucket_policy" "cdn-oac-bucket-policy" {
  bucket = aws_s3_bucket.source.id
  policy = data.aws_iam_policy_document.static_s3_policy.json
}

data "aws_iam_policy_document" "static_s3_policy" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.source.arn}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.cf_dist.arn]
    }
  }
}

resource "aws_s3_bucket_website_configuration" "source" {
  bucket = aws_s3_bucket.source.id

  index_document {
    suffix = "index.html"
  }
}

resource "aws_s3_bucket_versioning" "source" {
  bucket   = aws_s3_bucket.source.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_cloudfront_origin_access_control" "s3_oac" {
  name                              = "s3_oac_${random_string.bucket_random.result}"
  description                       = "S3 OAC Policy"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

data "aws_s3_bucket" "source_bucket" {
  bucket = aws_s3_bucket.source.bucket
}

resource "aws_cloudfront_distribution" "cf_dist" {
  origin {
    domain_name              = data.aws_s3_bucket.source_bucket.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.s3_oac.id
    origin_id                = "frontend-id"
  }

  enabled             = true #콘텐츠에 대한 최종 사용자 요청을 수락하도록 배포가 활성화되어 있는지 여부입니다
  is_ipv6_enabled     = false
  comment             = "CloudFront For S3, ALB"
  default_root_object = "index.html"

  default_cache_behavior { #S3 behavior
    cache_policy_id  = "658327ea-f89d-4fab-a63d-7e88639e58f6" #CachingOptimized
    target_origin_id = "frontend-id"

    allowed_methods = ["GET", "HEAD"]
    cached_methods  = ["GET", "HEAD"]

    compress = true
    viewer_protocol_policy = "redirect-to-https"
    }
  ordered_cache_behavior {
    path_pattern     = "/static/*"
    cache_policy_id  = "658327ea-f89d-4fab-a63d-7e88639e58f6" # CachingOptimized
    target_origin_id = "frontend-id"

    allowed_methods = ["GET", "HEAD"]
    cached_methods  = ["GET", "HEAD"]

    compress = true
    viewer_protocol_policy = "redirect-to-https"
  }
  price_class = "PriceClass_All"
  restrictions { #국가 제한
    geo_restriction {
      restriction_type = "none"
      locations        = []
    }
  }
  viewer_certificate { #인증서 HTTPS를 사용하여 객체를 요청하도록 한다
    cloudfront_default_certificate = true
  }
  tags = {
    Name = "wsc-prod-cdn"
  }
}