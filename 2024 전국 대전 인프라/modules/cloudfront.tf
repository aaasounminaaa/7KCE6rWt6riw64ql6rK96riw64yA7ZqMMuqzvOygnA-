# resource "aws_cloudfront_origin_access_control" "s3_oac" {
#   provider = aws.seoul
#   name                              = "s3_oac"
#   description                       = "S3 OAC Policy"
#   origin_access_control_origin_type = "s3"
#   signing_behavior                  = "always"
#   signing_protocol                  = "sigv4"
# }

# locals {
#   s3_origin_id = "myS3Origin"
#   alb_origin_id = "alb-origin"
# }

# resource "aws_cloudfront_distribution" "cf_dist" {
#   origin {
#     domain_name              = "${var.bucket}"
#     origin_access_control_id = "${var.S3_oac}" # 사용자 지정 오리진 구성 정보
#     origin_id                = local.s3_origin_id
#   }


# #   origin {
# #     domain_name = aws_lb.web.dns_name
# #     custom_origin_config {
# #       http_port              = 80
# #       https_port             = 443
# #       origin_protocol_policy = "http-only"
# #       origin_ssl_protocols   = ["TLSv1"]
# #     }
# #     origin_id = local.alb_origin_id
# #   }

#   enabled             = true #콘텐츠에 대한 최종 사용자 요청을 수락하도록 배포가 활성화되어 있는지 여부입니다
#   is_ipv6_enabled     = false
#   comment             = "CloudFront For S3, ALB"
#   default_root_object = "index.html"

#   default_cache_behavior { #S3 behavior
#     cache_policy_id  = "658327ea-f89d-4fab-a63d-7e88639e58f6" #CachingOptimized
#     target_origin_id = local.s3_origin_id

#     allowed_methods = ["GET", "HEAD"]
#     cached_methods  = ["GET", "HEAD"]

#     compress = true
#     viewer_protocol_policy = "https-only"
#     # lambda_function_association {
#     #   event_type   = "viewer-request"
#     #   lambda_arn   = aws_lambda_function.example.qualified_arn
#     #   include_body = false
#     # }
#   }

# #   ordered_cache_behavior { #ALB behavior
# #     path_pattern             = "/v1/*"
# #     cache_policy_id          = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad" #CachingDisabled
# #     origin_request_policy_id = "216adef6-5c7f-47e4-b989-5492eafa07d3" #AllViewer
# #     target_origin_id         = local.alb_origin_id

# #     allowed_methods = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
# #     cached_methods  = ["GET", "HEAD"]

# #     compress = true
# #     viewer_protocol_policy = "https-only"
# #   }

#   price_class = "PriceClass_All"

#   restrictions { #국가 제한
#     geo_restriction {
#       restriction_type = "none"
#       locations        = []
#     }
#   }

#   tags = {
#     Name = "hrdkorea-cdn"
#   }

#   viewer_certificate { #인증서 HTTPS를 사용하여 객체를 요청하도록 한다
#     cloudfront_default_certificate = true
#   }
# }
# output "cloudfront_arn" {
#   value = aws_cloudfront_distribution.cf_dist.arn
# }