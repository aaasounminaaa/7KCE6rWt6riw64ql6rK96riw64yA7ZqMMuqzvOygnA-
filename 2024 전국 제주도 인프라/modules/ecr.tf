data "aws_caller_identity" "customer" {}
resource "aws_ecr_repository" "ecr" {
  name = "customer"
    tags = {
        Name = "customer"
    } 
}
resource "aws_ecr_repository" "Product" {
  name = "product"
    tags = {
        Name = "product"
    } 
}

resource "aws_ecr_repository" "order" {
  name = "order"
    tags = {
        Name = "order"
    } 
}