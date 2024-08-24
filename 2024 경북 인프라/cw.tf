data "aws_caller_identity" "current" {
}

resource "aws_kms_key" "cw" {
    key_usage = "ENCRYPT_DECRYPT"
    deletion_window_in_days = 7

    policy = jsonencode({
        "Version" : "2012-10-17",
        "Id" : "key-default-1",
        "Statement" : [
            {
                "Sid" : "Enable IAM User Permissions",
                "Effect" : "Allow",
                "Principal" : {
                    "AWS" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
                },
                "Action" : "kms:*",
                "Resource" : "*"
            },
            {
                "Sid" : "Allow CloudWatch Logs use of the key",
                "Effect" : "Allow",
                "Principal" : {
                    "Service" : "logs.ap-northeast-2.amazonaws.com"
                },
                "Action" : [
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:DescribeKey"
                ],
                "Resource" : "*"
            }
        ]
    })

    tags = {
        Name = "cw-kms"
    }
}

resource "aws_kms_alias" "cw" {
    target_key_id = aws_kms_key.cw.key_id
    name = "alias/cw-kms"
}

resource "aws_cloudwatch_log_group" "customer" {
    name = "/wsi/webapp/customer"
    kms_key_id = aws_kms_key.cw.arn
    
    tags = {
        Name = "/wsi/webapp/customer"
    }
}

resource "aws_cloudwatch_log_group" "product" {
    name = "/wsi/webapp/product"
    kms_key_id = aws_kms_key.cw.arn
    
    tags = {
        Name = "/wsi/webapp/product"
    }
}

resource "aws_cloudwatch_log_group" "order" {
    name = "/wsi/webapp/order"
    kms_key_id = aws_kms_key.cw.arn

    tags = {
        Name = "/wsi/webapp/order"
    }
}

output "customer_cw_log" {
    value = aws_cloudwatch_log_group.customer.id
}

output "product_cw_log" {
    value = aws_cloudwatch_log_group.product.id
}

output "order_cw_log" {
    value = aws_cloudwatch_log_group.order.id
}
