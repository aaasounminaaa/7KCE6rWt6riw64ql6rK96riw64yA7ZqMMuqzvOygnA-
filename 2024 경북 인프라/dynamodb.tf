resource "aws_kms_key" "kms" {
  key_usage = "ENCRYPT_DECRYPT"
  deletion_window_in_days = 7

  tags = {
    Name = "db-kms"
  }
}

resource "aws_kms_alias" "kms" {
  target_key_id = aws_kms_key.kms.key_id
  name = "alias/db-kms"
}

resource "aws_dynamodb_table" "dynamodb" {
    name           = "order"
    billing_mode   = "PAY_PER_REQUEST"
    hash_key       = "id"

    attribute {
        name = "id"
        type = "S"
    }

    server_side_encryption {
        enabled    = true
        kms_key_arn  = aws_kms_key.kms.arn
    }

    tags = {
        Name = "order"
    }
}

output "dynamodb" {
    value = aws_dynamodb_table.dynamodb.name
}