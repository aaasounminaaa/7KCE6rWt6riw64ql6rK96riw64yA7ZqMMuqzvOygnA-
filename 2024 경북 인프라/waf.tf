resource "aws_wafv2_web_acl" "cf" {
  provider = aws.us-east-1

  name  = "wsi-waf"
  scope = "CLOUDFRONT"

  default_action {
    block {
      custom_response {
        response_code = 403
        custom_response_body_key = "access-denied-text"
      }
    }
  }

  custom_response_body {
    key          = "access-denied-text"
    content      = "Access Denied"
    content_type = "TEXT_PLAIN"
  }

  rule {
    name     = "AllowSafeClientUserAgent"
    priority = 1

    statement {
      byte_match_statement {
        search_string = "safe-client"

        field_to_match {
          single_header {
            name = "user-agent"
          }
        }

        text_transformation {
          priority = 0
          type     = "NONE"
        }

        positional_constraint = "CONTAINS"
      }
    }

    action {
      allow {}
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "AllowSafeClientUserAgent"
    }
  }

  rule {
    name     = "VerifyCustomHeader"
    priority = 2

    statement {
      byte_match_statement {
        search_string = "Skills2024"

        field_to_match {
          single_header {
            name = "x-wsi-header"
          }
        }

        text_transformation {
          priority = 0
          type     = "NONE"
        }

        positional_constraint = "EXACTLY"
      }
    }

    action {
      allow {}
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "VerifyCustomHeader"
    }
  }

  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = "wsi-waf"
  }
}

resource "aws_wafv2_web_acl" "alb" {

  name  = "wsi-wafv2"
  scope = "REGIONAL"

  default_action {
    block {
      custom_response {
        response_code = 403
        custom_response_body_key = "access-denied-text"
      }
    }
  }

  custom_response_body {
    key          = "access-denied-text"
    content      = "Access Denied"
    content_type = "TEXT_PLAIN"
  }

  rule {
    name     = "AllowSafeClientUserAgent"
    priority = 1

    statement {
      byte_match_statement {
        search_string = "safe-client"

        field_to_match {
          single_header {
            name = "user-agent"
          }
        }

        text_transformation {
          priority = 0
          type     = "NONE"
        }

        positional_constraint = "CONTAINS"
      }
    }

    action {
      allow {}
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "AllowSafeClientUserAgent"
    }
  }

  rule {
    name     = "VerifyCustomHeader"
    priority = 2

    statement {
      byte_match_statement {
        search_string = "Skills2024"

        field_to_match {
          single_header {
            name = "x-wsi-header"
          }
        }

        text_transformation {
          priority = 0
          type     = "NONE"
        }

        positional_constraint = "EXACTLY"
      }
    }

    action {
      allow {}
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "VerifyCustomHeader"
    }
  }

  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = "wsi-waf"
  }
}