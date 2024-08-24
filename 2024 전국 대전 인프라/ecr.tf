data "aws_caller_identity" "current" {}
resource "aws_ecr_repository" "ecr" {
  name = "hrdkorea-ecr-repo"
  image_scanning_configuration {
    scan_on_push = true
    }
    tags = {
        Name = "hrdkorea-ecr-repo"
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