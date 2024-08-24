resource "aws_ecr_repository" "customer" {
  name = "customer"
  image_tag_mutability = "MUTABLE"

    tags = {
        Name = "customer"
    } 
}

resource "aws_ecr_repository" "product" {
  name = "product"
  image_tag_mutability = "MUTABLE"

    tags = {
        Name = "product"
    } 
}

resource "aws_ecr_repository" "order" {
  name = "order"
  image_tag_mutability = "MUTABLE"

    tags = {
        Name = "order"
    } 
}
