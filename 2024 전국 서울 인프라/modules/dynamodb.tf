resource "aws_dynamodb_table" "order-table" {
  name           = "order"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "id"
  attribute {
    name = "id"
    type = "S"
  }
  server_side_encryption {
    enabled = true
    kms_key_arn = "${var.kms_arn}"
  }
  # attribute {
  #   name = "customerid"
  #   type = "S"
  # }
  # attribute {
  #   name = "productid"
  #   type = "S"
  # }
  point_in_time_recovery {
    enabled = true
  }
  tags = {
    Name        = "order"
  }
}