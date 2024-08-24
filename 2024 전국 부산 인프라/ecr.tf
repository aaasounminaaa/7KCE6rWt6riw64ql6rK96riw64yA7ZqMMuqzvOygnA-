resource "aws_ecr_repository" "customer" {
  name = "wsi-customer-ecr"
  image_tag_mutability = "MUTABLE"

    tags = {
        Name = "wsi-customer-ecr"
    } 
}

resource "aws_ecr_repository" "product" {
  name = "wsi-product-ecr"
  image_tag_mutability = "MUTABLE"

    tags = {
        Name = "wsi-order-ecr"
    } 
}

resource "aws_ecr_repository" "order" {
  name = "wsi-order-ecr"
  image_tag_mutability = "MUTABLE"

    tags = {
        Name = "wsi-order-ecr"
    } 
}

output "customer-ecr" {
    value = aws_ecr_repository.customer.name
}

output "product-ecr" {
    value = aws_ecr_repository.product.name
}

output "order" {
    value = aws_ecr_repository.order.name
}