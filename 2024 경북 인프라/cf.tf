resource "random_string" "bucket_random" {
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
}

resource "aws_cloudfront_origin_access_control" "s3_oac" {
  name                              = "s3_oac_${random_string.bucket_random.result}"
  description                       = "S3 OAC Policy"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

locals { 
  s3_origin_id = "s3_origin"
}

resource "aws_cloudfront_distribution" "cf" {
    provider = aws.us-east-1

    origin {
        domain_name              = aws_s3_bucket.s3.bucket_regional_domain_name
        origin_access_control_id = aws_cloudfront_origin_access_control.s3_oac.id
        origin_id                = local.s3_origin_id
    }
    enabled             = true
    is_ipv6_enabled     = false
    comment             = "CloudFront For S3, ALB"
    default_root_object = "stattic/index.html"
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
    
    viewer_certificate {
      cloudfront_default_certificate = true
    }
    
    web_acl_id = aws_wafv2_web_acl.cf.arn

    tags = {
      Name = "wsi-cdn"
    }
}

output "cloudfront" {
  value = aws_cloudfront_distribution.cf.id
}