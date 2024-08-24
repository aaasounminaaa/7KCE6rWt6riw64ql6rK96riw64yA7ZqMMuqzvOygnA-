resource "aws_ecr_repository" "customer" {
  name = "customer-ecr"

  image_scanning_configuration {
    scan_on_push = true
    }

    tags = {
        Name = "customer-ecr"
    } 
}

resource "aws_ecr_repository" "product" {
  name = "product-ecr"

  image_scanning_configuration {
    scan_on_push = true
    }

    tags = {
        Name = "product-ecr"
    } 
}

resource "aws_ecr_repository" "order" {
  name = "order-ecr"

  image_scanning_configuration {
    scan_on_push = true
    }

    tags = {
        Name = "order-ecr"
    } 
}

output "customer_ecr" {
    value = aws_ecr_repository.customer.id
}

output "product_ecr" {
    value = aws_ecr_repository.product.id
}

output "order_ecr" {
    value = aws_ecr_repository.order.id
}