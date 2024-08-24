data "aws_caller_identity" "current" {}
resource "aws_ecr_repository" "customer" {
  name = "customer"
  image_tag_mutability = "IMMUTABLE"
  encryption_configuration {
  encryption_type="KMS"
  kms_key = "${var.kms_id}"
  }
  image_scanning_configuration {
    scan_on_push = true
    }
    tags = {
        Name = "customer"
    }
}

resource "aws_ecr_repository" "product" {
  name = "product"
  image_tag_mutability = "IMMUTABLE"
  encryption_configuration {
  encryption_type="KMS"
  kms_key = "${var.kms_id}"
  }
  image_scanning_configuration {
    scan_on_push = true
    }
    tags = {
        Name = "product"
    }
}

resource "aws_ecr_repository" "order" {
  name = "order"
  image_tag_mutability = "IMMUTABLE"
  encryption_configuration {
  encryption_type="KMS"
  kms_key = "${var.kms_id}"
  }
  image_scanning_configuration {
    scan_on_push = true
    }
    tags = {
        Name = "order"
    }
}

resource "aws_ecr_replication_configuration" "example" {
  replication_configuration {
    rule {
      destination {
        region      = "us-east-1"
        registry_id = data.aws_caller_identity.current.account_id
      }
    }
  }
}