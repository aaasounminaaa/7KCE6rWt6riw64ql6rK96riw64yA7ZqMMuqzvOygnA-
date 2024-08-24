resource "aws_dynamodb_table" "ap_northeast_2" {
    name             = "order"
    billing_mode     = "PAY_PER_REQUEST"
    hash_key         = "id"

    attribute {
        name = "id"
        type = "S"
    }

    tags = {
        Name = "order"
    }
}