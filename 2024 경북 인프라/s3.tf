resource "aws_kms_key" "s3" {
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
          AWS = "arn:aws:iam::${data.aws_caller_identity.gyeongbuk.account_id}:root"
        },
        Action   = "kms:*"
        Resource = "*"
      }
      # {
      #   Sid    = "AllowCloudFrontServicePrincipalSSE-KMS for home account"
      #   Effect = "Allow"
      #   Principal = {
      #     AWS = "arn:aws:iam::${data.aws_caller_identity.gyeongbuk.account_id}:root"
      #     Service = "cloudfront.amazonaws.com"
      #   },
      #   Action = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey*"]
      #   Resource = "*"
      #   Condition = {
      #     StringEquals = {
      #       "AWS:SourceArn" = "arn:aws:cloudfront::${data.aws_caller_identity.gyeongbuk.account_id}:distribution/${aws_cloudfront_distribution.cf.id}"
      #     }
      #   }
      # }
    ]
  })
  tags = {
    Name = "s3-kms"
  }
}

resource "aws_kms_alias" "s3" {
  target_key_id = aws_kms_key.s3.key_id
  name = "alias/s3-kms"
}



resource "aws_s3_bucket" "s3" {
  bucket = "apne2-wsi-static-101"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.s3.arn
        sse_algorithm = "aws:kms"
      }
    }
  }

    tags = {
        Name = "apne2-wsi-static-101"
    }
}

resource "aws_s3_bucket_object" "static_folder" {
  bucket = aws_s3_bucket.s3.bucket
  key = "static/"
}

resource "aws_s3_object" "static" {
  bucket = aws_s3_bucket.s3.id
  key    = "/static/index.html"
  source = "./src/index.html"
  etag   = filemd5("./src/index.html")
  content_type = "text/html"
}

output "s3" {
    value = aws_s3_bucket.s3.id
}