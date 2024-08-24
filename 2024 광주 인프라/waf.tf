resource "aws_wafv2_web_acl" "cf" {
    provider = aws.us-east-1

    name        = "skills-waf"
    scope       = "CLOUDFRONT"
    
    default_action {
        allow {}
    }
    rule {
        name     = "Allow-only-HTTP-GET-and-POST"
        priority = 0
        action {
        block {
            custom_response {
            response_code = 405
            }
        }
        }

        statement {
        and_statement {
            statement {
            not_statement {
                statement {
                byte_match_statement {
                    field_to_match {
                    method {}
                    }
                    positional_constraint = "EXACTLY"
                    search_string         = "GET"
                    text_transformation {
                    priority = 1
                    type     = "NONE"
                    }
                }
                }
            }
            }
            statement {
            not_statement {
                statement {
                byte_match_statement {
                    field_to_match {
                    method {}
                    }
                    positional_constraint = "EXACTLY"
                    search_string         = "POST"
                    text_transformation {
                    priority = 0
                    type     = "NONE"
                    }
                }
                }
            }
            }
        }
        }

        visibility_config {
        sampled_requests_enabled = true
        cloudwatch_metrics_enabled = true
        metric_name               = "Allow-only-HTTP-GET-and-POST"
        }
    }

  rule {
    name     = "BlockBadUserInQuery"
    priority = 1
    action {
      block {
        custom_response {
          response_code = 403
        }
      }
    }

    statement {
      byte_match_statement {
        field_to_match {
          single_query_argument {
            name = "id"
          }
        }
        positional_constraint = "CONTAINS"
        search_string         = "baduser"
        text_transformation {
          priority = 0
          type     = "NONE"
        }
      }
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "BlockBadUserInQuery"
    }
  }

    visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "skills-waf"
        sampled_requests_enabled   = true
    }
}
