### Module 선언
module "seoul" {
    source = "./modules"
    create_region = "ap-northeast-2"
    destination_region = "us-east-1"   
    key_name = aws_key_pair.keypair.key_name
    # bucket = aws_s3_bucket.source.bucket_regional_domain_name
    # eks_host = module.eks.cluster_endpoint
    # cluster_role        = aws_iam_role.cluster.arn
    # default_role        = aws_iam_role_policy_attachment.cluster-default
    # controller_role     = aws_iam_role_policy_attachment.vpc-resource-controller
    # S3_oac              = aws_cloudfront_origin_access_control.s3_oac.id
    node_role           = aws_iam_role.nodes.arn
    fargate_role        = aws_iam_role.example.arn
    providers = {
      aws = aws.seoul
    }
}

module "usa" {
    source = "./modules"
    create_region = "us-east-1"
    destination_region = "ap-northeast-2"
    key_name = aws_key_pair.usa_keypair.key_name
    # bucket = "aws_s3_bucket.destination.bucket_regional_domain_name"
    # cluster_role = aws_iam_role.cluster.arn
    # default_role        = aws_iam_role_policy_attachment.cluster-default
    # controller_role     = aws_iam_role_policy_attachment.vpc-resource-controller
    # S3_oac              = aws_cloudfront_origin_access_control.s3_oac.id
    node_role           = aws_iam_role.nodes.arn
    fargate_role        = aws_iam_role.example.arn
    # eks_host = module.eks_us.cluster_endpoint
    providers = {
      aws = aws.usa
    }
}

locals {
  filepath      = "./content"
}
## Keypair
resource "tls_private_key" "rsa" {
  algorithm = "RSA"
  rsa_bits = 4096
}

resource "aws_key_pair" "keypair" {
  key_name = "hrdkorea"
  public_key = tls_private_key.rsa.public_key_openssh
}

resource "aws_key_pair" "usa_keypair" {
  provider = aws.usa
  key_name = "hrdkorea"
  public_key = tls_private_key.rsa.public_key_openssh
}

resource "local_file" "keypair" {
  content = tls_private_key.rsa.private_key_pem
  filename = "./hrdkorea.pem"
}


### Dynamo DB
resource "aws_dynamodb_global_table" "myTable" {

  depends_on = [
    aws_dynamodb_table.ap_northeast_2,
    aws_dynamodb_table.us_east_1,
  ]

  provider = aws.seoul
  name     = "order"

  replica {
    region_name = "ap-northeast-2"
  }

  replica {
    region_name = "us-east-1"
  }
}


resource "aws_dynamodb_table" "us_east_1" {
  provider = aws.usa
  billing_mode   = "PAY_PER_REQUEST"
  hash_key         = "id"
  name             = "order"
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"
  # read_capacity    = 1
  # write_capacity   = 1

  attribute {
    name = "id"
    type = "S"
  }
}

# resource "aws_dynamodb_resource_policy" "example" {
#   resource_arn = aws_dynamodb_table.example.arn
#   policy       = data.aws_iam_policy_document.test.json
# }

resource "aws_dynamodb_table" "ap_northeast_2" {
  provider = aws.seoul
  billing_mode   = "PAY_PER_REQUEST"
  hash_key         = "id"
  name             = "order"
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"
  # read_capacity    = 1
  # write_capacity   = 1

  attribute {
    name = "id"
    type = "S"
  }
}

### S3
### Source Bucket and Versioning (Seoul) ###
resource "random_string" "bucket_random" {
  length           = 4
  upper   = false
  lower   = false
  numeric  = true
  special = false
}
resource "aws_s3_bucket" "source" {
  provider = aws.seoul
  bucket   = "hrdkorea-static-${random_string.bucket_random.result}"
}

resource "aws_s3_object" "static" {
  bucket = aws_s3_bucket.source.id
  key    = "static/index.html"
  source = "${local.filepath}/seoul/index.html"
  etag   = filemd5("${local.filepath}/seoul/index.html")
  content_type = "text/html"
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
  provider = aws.seoul
  bucket   = aws_s3_bucket.source.id
  versioning_configuration {
    status = "Enabled"
  }
}

## US_Bucket
# resource "aws_s3_bucket" "destination" {
#   provider = aws.usa
#   bucket   = "us-static-${random_string.bucket_random.result}"
# }

# resource "aws_s3_object" "destination" {
#   provider = aws.usa
#   bucket = aws_s3_bucket.destination.id
#   key    = "static/index.html"
#   source = "${local.filepath}/usa/index.html"
#   etag   = filemd5("${local.filepath}/usa/index.html")
#   content_type = "text/html"
# }

# resource "aws_s3_bucket_policy" "destination_cdn-oac-bucket-policy" {
#   provider = aws.usa
#   bucket = aws_s3_bucket.destination.id
#   policy = data.aws_iam_policy_document.destination_s3_policy.json
# }

# data "aws_iam_policy_document" "destination_s3_policy" {
#   provider = aws.usa
#   statement {
#     actions   = ["s3:GetObject"]
#     resources = ["${aws_s3_bucket.destination.arn}/*"]
#     principals {
#       type        = "Service"
#       identifiers = ["cloudfront.amazonaws.com"]
#     }
#     condition {
#       test     = "StringEquals"
#       variable = "AWS:SourceArn"
#       values   = [aws_cloudfront_distribution.cf_dist.arn]
#     }
#   }
# }

# resource "aws_s3_bucket_website_configuration" "destination" {
#   provider = aws.usa
#   bucket = aws_s3_bucket.destination.id

#   index_document {
#     suffix = "index.html"
#   }
# }

# resource "aws_s3_bucket_versioning" "destination" {
#   provider = aws.usa
#   bucket   = aws_s3_bucket.destination.id
#   versioning_configuration {
#     status = "Enabled"
#   }
# }

### IAM Policy and Role for Replication ###
# data "aws_iam_policy_document" "assume_role" {
#   statement {
#     effect = "Allow"
#     principals {
#       type        = "Service"
#       identifiers = ["s3.amazonaws.com"]
#     }
#     actions = ["sts:AssumeRole"]
#   }
# }

# resource "aws_iam_role" "replication" {
#   name               = "tf-iam-role-replication-12345"
#   assume_role_policy = data.aws_iam_policy_document.assume_role.json
# }

# data "aws_iam_policy_document" "replication" {
#   statement {
#     effect = "Allow"
#     actions = [
#       "s3:GetReplicationConfiguration",
#       "s3:ListBucket",
#     ]
#     resources = [aws_s3_bucket.source.arn]
#   }

#   statement {
#     effect = "Allow"
#     actions = [
#       "s3:GetObjectVersionForReplication",
#       "s3:GetObjectVersionAcl",
#       "s3:GetObjectVersionTagging",
#     ]
#     resources = ["${aws_s3_bucket.source.arn}/*"]
#   }

#   statement {
#     effect = "Allow"
#     actions = [
#       "s3:ReplicateObject",
#       "s3:ReplicateDelete",
#       "s3:ReplicateTags",
#     ]
#     resources = ["${aws_s3_bucket.destination.arn}/*"]
#   }
# }

# resource "aws_iam_policy" "replication" {
#   name   = "tf-iam-role-policy-replication-${random_string.bucket_random.result}"
#   policy = data.aws_iam_policy_document.replication.json
# }

# resource "aws_iam_role_policy_attachment" "replication" {
#   role       = aws_iam_role.replication.name
#   policy_arn = aws_iam_policy.replication.arn
# }

### Replication Configuration (Seoul Source to USA Destination) ###
# resource "aws_s3_bucket_replication_configuration" "replication" {
#   provider = aws.seoul
#   depends_on = [aws_s3_bucket_versioning.source, aws_s3_bucket_versioning.destination]

#   role   = aws_iam_role.replication.arn
#   bucket = aws_s3_bucket.source.id

#   rule {
#     id     = "ReplicationRule"
#     status = "Enabled"

#     filter {
#       prefix = ""
#     }
#     destination {
#       bucket        = aws_s3_bucket.destination.arn
#       storage_class = "STANDARD"
#     }

#     delete_marker_replication {
#       status = "Disabled"
#     }
#   }
# }

### RDS
resource "aws_rds_global_cluster" "example" {
  global_cluster_identifier = "hrdkorea-rds"
  engine                    = "aurora-mysql"
  engine_version            = "8.0.mysql_aurora.3.05.2"
  database_name             = "hrdkorea-global"
  lifecycle {
    ignore_changes = [
      "global_cluster_identifier",
      "engine",
      "engine_version"
    ]
  }
}

resource "aws_rds_cluster" "primary" {
  provider                  = aws.seoul
  engine                    = aws_rds_global_cluster.example.engine
  engine_version            = aws_rds_global_cluster.example.engine_version
  cluster_identifier        = "hrdkorea-rds-instance"
  master_username           = "hrdkorea_user"
  master_password           = "Skill53##"
  # manage_master_user_password = true
  db_cluster_parameter_group_name = module.seoul.cluster_parameter_group
  port = 3409
  database_name             = "hrdkorea"
  global_cluster_identifier = aws_rds_global_cluster.example.id
  db_subnet_group_name      = module.seoul.subnet_group
  vpc_security_group_ids    = [module.seoul.security_group]
  skip_final_snapshot = true
  lifecycle {
    ignore_changes = [
      "db_subnet_group_name",
      "cluster_identifier",
      "db_cluster_parameter_group_name"
    ]
  }
}

resource "aws_rds_cluster_instance" "primary" {
  provider             = aws.seoul
  engine               = aws_rds_global_cluster.example.engine
  engine_version       = aws_rds_global_cluster.example.engine_version
  db_parameter_group_name = module.seoul.paramter_group
  identifier           = "hrdkorea-rds-instance"
  cluster_identifier   = aws_rds_cluster.primary.id
  instance_class       = "db.r5.large"
  db_subnet_group_name = module.seoul.subnet_group
  lifecycle {
    ignore_changes = [
      "db_parameter_group_name",
      "cluster_identifier",
      "db_subnet_group_name"
    ]
  }
}

resource "aws_rds_cluster" "secondary" {
  provider                  = aws.usa
  engine                    = aws_rds_global_cluster.example.engine
  engine_version            = aws_rds_global_cluster.example.engine_version
  cluster_identifier        = "hrdkorea-rds-instance-us"
  global_cluster_identifier = aws_rds_global_cluster.example.id
  db_cluster_parameter_group_name = module.seoul.cluster_parameter_group
  port = 3409
  db_subnet_group_name      = module.usa.subnet_group
  vpc_security_group_ids    = [module.usa.security_group]
  skip_final_snapshot = true
  enable_global_write_forwarding = true
  depends_on = [
    aws_rds_cluster_instance.primary
  ]
  lifecycle {
    ignore_changes = [
      "global_cluster_identifier",
      "db_cluster_parameter_group_name",
      "db_cluster_parameter_group_name"
    ]
  }
}

resource "aws_rds_cluster_instance" "secondary" {
  provider             = aws.usa
  engine               = aws_rds_global_cluster.example.engine
  engine_version       = aws_rds_global_cluster.example.engine_version
  db_parameter_group_name = module.usa.paramter_group
  identifier           = "hrdkorea-rds-instance-us"
  cluster_identifier   = aws_rds_cluster.secondary.id
  instance_class       = "db.r5.large"
  db_subnet_group_name = module.usa.subnet_group
  lifecycle {
    ignore_changes = [
      "db_parameter_group_name",
      "cluster_identifier",
      "db_subnet_group_name"
    ]
  }
}


resource "aws_secretsmanager_secret" "seoul" {
  provider                  = aws.seoul

  name = "mysql/secret"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret" "usa" {
  provider                  = aws.usa

  name = "mysql/secret"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "seoul" {
  provider                  = aws.seoul

  secret_id     = aws_secretsmanager_secret.seoul.id
  secret_string = jsonencode({
    "username"            = aws_rds_cluster.primary.master_username
    "password"            = aws_rds_cluster.primary.master_password
    "engine"              = aws_rds_cluster.primary.engine
    "host"                = aws_rds_cluster.primary.endpoint
    "port"                = aws_rds_cluster.primary.port
    "dbClusterIdentifier" = aws_rds_cluster.primary.cluster_identifier
    "dbname"              = aws_rds_cluster.primary.database_name
    "seoul_region"          = "ap-northeast-2"
  })
}

resource "aws_secretsmanager_secret_version" "usa" {
  provider                  = aws.usa

  secret_id     = aws_secretsmanager_secret.usa.id
  secret_string = jsonencode({
    "username"            = aws_rds_cluster.secondary.master_username
    "password"            = aws_rds_cluster.primary.master_password
    "engine"              = aws_rds_cluster.secondary.engine
    "host"                = aws_rds_cluster.secondary.endpoint
    "port"                = aws_rds_cluster.secondary.port
    "dbClusterIdentifier" = aws_rds_cluster.secondary.cluster_identifier
    "dbname"              = aws_rds_cluster.secondary.database_name
    "us_region"          = "us-east-1"
  })
}

## Cluster Role
data "aws_iam_policy_document" "cluster" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "cluster" {
  name               = "eksClusterRole"
  assume_role_policy = data.aws_iam_policy_document.cluster.json
}

resource "aws_iam_role_policy_attachment" "cluster-default" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.cluster.name
}

resource "aws_iam_role_policy_attachment" "vpc-resource-controller" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.cluster.name
}


### Node group
resource "aws_iam_role" "nodes" {
  name = "AmazonEKSNodeRole"

  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "nodes-AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.nodes.name
}

resource "aws_iam_role_policy_attachment" "nodes-AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.nodes.name
}

resource "aws_iam_role_policy_attachment" "nodes-AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.nodes.name
}

### Fargate Role
resource "aws_iam_role" "example" {
  name = "eks-fargate-profile-example"

  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "eks-fargate-pods.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "example-AmazonEKSFargatePodExecutionRolePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"
  role       = aws_iam_role.example.name
}

### Cloudfront
##S3_oac
resource "aws_cloudfront_origin_access_control" "s3_oac" {
  name                              = "s3_oac_${random_string.bucket_random.result}"
  description                       = "S3 OAC Policy"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

locals {
  seoul_s3_origin_id = "seoul_S3Origin"
  # us_s3_origin_id = "us_S3Origin"
  alb_origin_id = "alb-origin"
}

data "aws_s3_bucket" "seoul_bucket" {
  bucket = aws_s3_bucket.source.bucket
  provider = aws.seoul
}

# data "aws_s3_bucket" "us_bucket" {
#   bucket = aws_s3_bucket.destination.bucket
#   provider = aws.usa
# }

resource "aws_cloudfront_distribution" "cf_dist" {
  origin {
    domain_name              = data.aws_s3_bucket.seoul_bucket.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.s3_oac.id # 사용자 지정 오리진 구성 정보
    origin_id                = local.seoul_s3_origin_id
  }
  # origin {
  #   domain_name              = data.aws_s3_bucket.us_bucket.bucket_regional_domain_name
  #   origin_access_control_id = aws_cloudfront_origin_access_control.s3_oac.id
  #   origin_id                = local.us_s3_origin_id
  # }

  enabled             = true #콘텐츠에 대한 최종 사용자 요청을 수락하도록 배포가 활성화되어 있는지 여부입니다
  is_ipv6_enabled     = false
  comment             = "CloudFront For S3, ALB"
  default_root_object = "index.html"

  default_cache_behavior { #S3 behavior
    cache_policy_id  = "658327ea-f89d-4fab-a63d-7e88639e58f6" #CachingOptimized
    target_origin_id = local.seoul_s3_origin_id

    allowed_methods = ["GET", "HEAD"]
    cached_methods  = ["GET", "HEAD"]

    compress = true
    viewer_protocol_policy = "https-only"
    # lambda_function_association {
    #   event_type   = "viewer-request"
    #   lambda_arn   = aws_lambda_function.example.qualified_arn
    #   include_body = false
    # }
  }

  # ordered_cache_behavior {
  #   path_pattern     = "/v1/"
  #   cache_policy_id  = "658327ea-f89d-4fab-a63d-7e88639e58f6" # CachingOptimized
  #   target_origin_id = local.us_s3_origin_id

  #   allowed_methods = ["GET", "HEAD"]
  #   cached_methods  = ["GET", "HEAD"]

  #   compress = true
  #   viewer_protocol_policy = "https-only"
  # }

#   ordered_cache_behavior { #ALB behavior
#     path_pattern             = "/v1/*"
#     cache_policy_id          = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad" #CachingDisabled
#     origin_request_policy_id = "216adef6-5c7f-47e4-b989-5492eafa07d3" #AllViewer
#     target_origin_id         = local.alb_origin_id

#     allowed_methods = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
#     cached_methods  = ["GET", "HEAD"]

#     compress = true
#     viewer_protocol_policy = "https-only"
#   }

  price_class = "PriceClass_All"

  restrictions { #국가 제한
    geo_restriction {
      restriction_type = "none"
      locations        = []
    }
  }

  tags = {
    Name = "hrdkorea-cdn"
  }

  viewer_certificate { #인증서 HTTPS를 사용하여 객체를 요청하도록 한다
    cloudfront_default_certificate = true
  }
}
output "cloudfront_arn" {
  value = aws_cloudfront_distribution.cf_dist.arn
}

locals {
  code_path = "./code"
}

# Assume Role Policy Document
data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com", "edgelambda.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

# Inline Policy Document
data "aws_iam_policy_document" "lambda_policy" {
  statement {
    effect = "Allow"
    actions   = [
      "s3:GetObject",
      "logs:CreateLogStream",
      "iam:CreateServiceLinkedRole",
      "logs:DescribeLogStreams",
      "lambda:GetFunction",
      "cloudfront:UpdateDistribution",
      "logs:CreateLogGroup",
      "logs:PutLogEvents",
      "lambda:EnableReplication",
      "ec2:*",
      "elasticloadbalancing:DescribeLoadBalancers"
    ]
    resources = ["*"]
  }
}

# IAM Role
resource "aws_iam_role" "lambda" {
  name               = "Lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

# IAM Role Policy
resource "aws_iam_role_policy" "lambda_policy" {
  name   = "LambdaPolicy"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda_policy.json
}

data "archive_file" "lambda" {
  type        = "zip"
  source_file = "${local.code_path}/lambda_function.py"
  output_path = "lambda_function_payload.zip"
}

resource "aws_lambda_function" "lambda" {
    provider = aws.usa
    filename = "lambda_function_payload.zip"
    function_name = "hrdkorea-function"
    role = aws_iam_role.lambda.arn
    handler = "lambda_function.lambda_handler"
    timeout = "5"
    source_code_hash = data.archive_file.lambda.output_base64sha256
    runtime = "python3.12"
}
output "lambda" {
    value = aws_lambda_function.lambda.arn
}