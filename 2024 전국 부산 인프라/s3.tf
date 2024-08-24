resource "random_string" "bucket_random" {
  length           = 4
  upper            = false
  lower            = true
  numeric          = false
  special          = false
}

resource "aws_s3_bucket" "s3" {
    bucket = "wsi-cc-data-101-${random_string.bucket_random.result}"

    tags = {
        Name = "wsi-cc-data-101-${random_string.bucket_random.result}"
    } 
}

resource "aws_s3_bucket_object" "static_folder" {
  bucket = aws_s3_bucket.s3.bucket
  key = "frontend/"
}

resource "aws_s3_object" "static" {
  bucket = aws_s3_bucket.s3.id
  key    = "/frontend/index.html"
  source = "./src/index.html"
  etag   = filemd5("./src/index.html")
  content_type = "text/html"
}

resource "aws_s3_object" "image" {
  bucket = aws_s3_bucket.s3.id
  key    = "/frontend/skills.png"
  source = "./src/skills.png"
  etag   = filemd5("./src/skills.png")
  content_type = "image/png"
}

resource "aws_s3_bucket_website_configuration" "source" {
  bucket = aws_s3_bucket.s3.id

  index_document {
    suffix = "index.html"
  }
}

output "s3" {
    value = aws_s3_bucket.s3.id
}