resource "random_string" "cf_random" {
  length           = 4
  upper            = false
  lower            = true
  numeric          = false
  special          = false
}

resource "aws_s3_bucket_policy" "cdn_oac_policy" {
  bucket = aws_s3_bucket.s3.id
  policy = data.aws_iam_policy_document.s3.json
}

data "aws_iam_policy_document" "s3" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.s3.arn}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.cf.arn]
    }
  }

  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.s3.arn}/*"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_lambda_function.lambda.arn]
    }
  }
}

resource "aws_cloudfront_origin_access_control" "s3_oac" {
  name                              = "s3_oac_${random_string.cf_random.result}"
  description                       = "S3 OAC Policy"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

locals { 
  s3_origin_id = "s3_origin"
}

resource "aws_cloudfront_origin_request_policy" "cf" {
  name    = "origin-policy"
  comment = "origin-policy"
    cookies_config {
      cookie_behavior = "none"
    }
    headers_config {
      header_behavior = "none"
    }
  query_strings_config {
    query_string_behavior = "whitelist"
    query_strings {
      items = ["img"]
    }
  }
}

resource "aws_cloudfront_distribution" "cf" {
    provider = aws.us-east-1

    origin {
        domain_name              = aws_s3_bucket.s3.bucket_regional_domain_name
        origin_access_control_id = aws_cloudfront_origin_access_control.s3_oac.id
        origin_id                = local.s3_origin_id
        origin_path              = "/frontend"
    }
    enabled             = true
    is_ipv6_enabled     = false
    comment             = "CloudFront For S3, ALB"
    default_root_object = "index.html"
    default_cache_behavior {
        cache_policy_id  = "658327ea-f89d-4fab-a63d-7e88639e58f6"
        target_origin_id = local.s3_origin_id

        allowed_methods = ["GET", "HEAD"]
        cached_methods  = ["GET", "HEAD"]

        compress = true
        viewer_protocol_policy = "redirect-to-https"
    }
    price_class = "PriceClass_All"

    restrictions {
      geo_restriction {
        restriction_type = "none"
        locations        = []
      }
    }

    ordered_cache_behavior {
      path_pattern     = "/preview"
      cache_policy_id  = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
      origin_request_policy_id = aws_cloudfront_origin_request_policy.cf.id
      target_origin_id = local.s3_origin_id

      allowed_methods = ["GET", "HEAD"]
      cached_methods  = ["GET", "HEAD"]

      compress = true
      viewer_protocol_policy = "redirect-to-https"

      lambda_function_association {
        event_type   = "origin-request"
        lambda_arn   = aws_lambda_function.lambda.qualified_arn
        include_body = true
      }
    }
    
    viewer_certificate {
      cloudfront_default_certificate = true
    }

    tags = {
      Name = "wsi-cdn"
    }
}

output "cloudfront" {
  value = aws_cloudfront_distribution.cf.id
}