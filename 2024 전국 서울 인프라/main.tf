### Module 선언
module "seoul" {
    source = "./modules"
    create_region = "ap-northeast-2"
    kms_arn = aws_kms_key.dynamodb.arn
    kms_id = aws_kms_key.dynamodb.id
    providers = {
      aws = aws.seoul
    }
}
data "aws_caller_identity" "current" {}

resource "aws_kms_key" "dynamodb" {
  enable_key_rotation     = true
  deletion_window_in_days = 7

  tags = {
    Name = "dynamodb-kms"
  }
}

resource "aws_kms_alias" "dynamodb" { 
  target_key_id = aws_kms_key.dynamodb.key_id
  name = "alias/dynamodb-kms"
}

resource "aws_kms_key" "eks" {
  enable_key_rotation     = true
  deletion_window_in_days = 7

  tags = {
    Name = "eks-kms"
  }
}

resource "aws_kms_alias" "eks" { 
  target_key_id = aws_kms_key.eks.key_id
  name = "alias/eks-kms"
}

resource "aws_kms_key" "kms" {
  provider = aws.usa
  key_usage = "ENCRYPT_DECRYPT"
  deletion_window_in_days = 7
  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "key-default-1"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudFrontServicePrincipalSSE-KMS for home account"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
          Service = "cloudfront.amazonaws.com"
        },
        Action = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey*"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = "arn:aws:cloudfront::${data.aws_caller_identity.current.account_id}:distribution/${aws_cloudfront_distribution.cf_dist.id}"
          }
        }
      }
    ]
  })
  tags = {
    Name = "s3-kms"
  }
}

resource "aws_kms_alias" "kms" {
  provider = aws.usa
  target_key_id = aws_kms_key.kms.key_id
  name = "alias/s3-kms"
}

### S3
### Source Bucket and Versioning (Seoul) ###
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
  bucket   = "ap-wsi-static-${random_string.bucket_random.result}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "source" {
  bucket = aws_s3_bucket.source.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.dynamodb.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_object" "static_index" {
  bucket = aws_s3_bucket.source.id
  key    = "index.html"
  source = "${local.filepath}/index.html"
  etag   = filemd5("${local.filepath}/index.html")
  content_type = "text/html"
}

resource "aws_s3_object" "static_error" {
  bucket = aws_s3_bucket.source.id
  key    = "error/error.html"
  source = "${local.filepath}/error.html"
  etag   = filemd5("${local.filepath}/error.html")
  content_type = "text/html"
}

resource "aws_s3_object" "css" {
  bucket = aws_s3_bucket.source.id
  key    = "css/bootstrap.min.css"
  source = "${local.filepath}/css/bootstrap.min.css"
  etag   = filemd5("${local.filepath}/css/bootstrap.min.css")
  content_type = "text/css"
}

resource "aws_s3_object" "js" {
  bucket = aws_s3_bucket.source.id
  key    = "js/main.js"
  source = "${local.filepath}/js/main.js"
  etag   = filemd5("${local.filepath}/js/main.js")
  content_type = "application/javascript"
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

### US_Bucket
resource "aws_s3_bucket" "destination" {
  provider = aws.usa
  bucket   = "us-wsi-static-${random_string.bucket_random.result}"
}


resource "aws_s3_bucket_server_side_encryption_configuration" "destination" {
  bucket = aws_s3_bucket.destination.id
  provider = aws.usa
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.kms.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_object" "destination" {
  provider = aws.usa
  bucket = aws_s3_bucket.destination.id
  key    = "index.html"
  source = "${local.filepath}/index.html"
  etag   = filemd5("${local.filepath}/index.html")
  content_type = "text/html"
}

resource "aws_s3_object" "us_css" {
  provider = aws.usa
  bucket = aws_s3_bucket.destination.id
  key    = "css/bootstrap.min.css"
  source = "${local.filepath}/css/bootstrap.min.css"
  etag   = filemd5("${local.filepath}/css/bootstrap.min.css")
  content_type = "text/css"
}

resource "aws_s3_object" "us_js" {
  provider = aws.usa
  bucket = aws_s3_bucket.destination.id
  key    = "js/main.js"
  source = "${local.filepath}/js/main.js"
  etag   = filemd5("${local.filepath}/js/main.js")
  content_type = "application/javascript"
}

resource "aws_s3_bucket_policy" "destination_cdn-oac-bucket-policy" {
  provider = aws.usa
  bucket = aws_s3_bucket.destination.id
  policy = data.aws_iam_policy_document.destination_s3_policy.json
}

data "aws_iam_policy_document" "destination_s3_policy" {
  provider = aws.usa
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.destination.arn}/*"]
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

resource "aws_s3_bucket_website_configuration" "destination" {
  provider = aws.usa
  bucket = aws_s3_bucket.destination.id

  index_document {
    suffix = "index.html"
  }
}

resource "aws_s3_bucket_versioning" "destination" {
  provider = aws.usa
  bucket   = aws_s3_bucket.destination.id
  versioning_configuration {
    status = "Enabled"
  }
}

### IAM Policy and Role for Replication ###
data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "replication" {
  name               = "s3-role-replication-12345"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

data "aws_iam_policy_document" "replication" {
  statement {
    effect = "Allow"
    actions = [
				"s3:ListBucket",
				"s3:GetReplicationConfiguration",
				"s3:GetObjectVersionForReplication",
				"s3:GetObjectVersionAcl",
				"s3:GetObjectVersionTagging"
    ]
    resources = [aws_s3_bucket.source.arn,"${aws_s3_bucket.source.arn}/*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:ReplicateObject",
      "s3:ReplicateDelete",
      "s3:ReplicateTags",
    ]
    condition {
      test     = "StringLikeIfExists"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms", "AES256", "aws:kms:dsse"]
    }
    condition {
      test     = "StringLikeIfExists"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = ["*"]
    }
    resources = ["${aws_s3_bucket.destination.arn}/*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "kms:Decrypt"
    ]
    condition {
      test     = "StringLike"
      variable = "kms:ViaService"
      values   = ["s3.ap-northeast-2.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = ["${aws_s3_bucket.source.arn}/*"]
    }
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "kms:Encrypt"
    ]
    condition {
      test     = "StringLike"
      variable = "kms:ViaService"
      values   = ["s3.us-east-1.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = ["${aws_s3_bucket.destination.arn}/*"]
    }
    resources = ["*"]
  }
}


resource "aws_iam_policy" "replication" {
  name   = "tf-iam-role-policy-replication-${random_string.bucket_random.result}"
  policy = data.aws_iam_policy_document.replication.json
}

resource "aws_iam_role_policy_attachment" "replication" {
  role       = aws_iam_role.replication.name
  policy_arn = aws_iam_policy.replication.arn
}

### Replication Configuration (Seoul Source to USA Destination) ###
resource "aws_s3_bucket_replication_configuration" "replication" {
  provider = aws.seoul
  depends_on = [aws_s3_bucket_versioning.source, aws_s3_bucket_versioning.destination]

  role   = aws_iam_role.replication.arn
  bucket = aws_s3_bucket.source.id

  rule {
    id     = "ReplicationRule"
    status = "Enabled"

    filter {
      prefix = ""
    }
    destination {
      bucket            = aws_s3_bucket.destination.arn
      storage_class     = "STANDARD"
      encryption_configuration {
        replica_kms_key_id = aws_kms_key.kms.arn
      }
    }
    delete_marker_replication {
      status = "Disabled"
    }

    source_selection_criteria {
      replica_modifications {
        status = "Enabled"
      }
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
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
  seoul_s3_origin_id = "seoul_S3Origin"
  usa_s3_origin_id = "usa_s3_origin_id"
}

resource "aws_cloudfront_distribution" "cf_dist" {
  origin_group {
    origin_id = "groupS3"

    failover_criteria {
      status_codes = [400,403, 404, 416, 500, 502, 503, 504]
    }
    member {
      origin_id = local.seoul_s3_origin_id
    }

    member {
      origin_id = local.usa_s3_origin_id
    }
  }
  origin {
    domain_name              = aws_s3_bucket.source.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.s3_oac.id # 사용자 지정 오리진 구성 정보
    origin_id                = local.seoul_s3_origin_id
  }
  origin {
    domain_name              = aws_s3_bucket.destination.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.s3_oac.id # 사용자 지정 오리진 구성 정보
    origin_id                = local.usa_s3_origin_id
  }
  enabled             = true #콘텐츠에 대한 최종 사용자 요청을 수락하도록 배포가 활성화되어 있는지 여부입니다
  is_ipv6_enabled     = false
  comment             = "CloudFront For S3, ALB"
  default_root_object = "index.html"
  default_cache_behavior { #S3 behavior
    cache_policy_id  = "658327ea-f89d-4fab-a63d-7e88639e58f6" #CachingOptimized
    target_origin_id = "groupS3"

    allowed_methods = ["GET", "HEAD"]
    cached_methods  = ["GET", "HEAD"]

    compress = true
    viewer_protocol_policy = "redirect-to-https"
    # forwarded_values {
    #   query_string = false
    #   cookies {
    #     forward = "none"
    #   }
    #   headers = ["Origin"]
    # }
  }

  ordered_cache_behavior { 
    path_pattern     = "/error/error.html"
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "groupS3"
    viewer_protocol_policy = "redirect-to-https"
    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
      headers = ["Origin"]
    }
  }
  price_class = "PriceClass_All"

  restrictions { #국가 제한
    geo_restriction {
      restriction_type = "none"
      locations        = []
    }
  }
  tags = {
    Name = "wsi-cdn"
  }
  viewer_certificate { #인증서 HTTPS를 사용하여 객체를 요청하도록 한다
    cloudfront_default_certificate = true
  }
  custom_error_response {
    error_code          = 403
    response_code       = 503
    response_page_path  = "/error/error.html"
  }
}