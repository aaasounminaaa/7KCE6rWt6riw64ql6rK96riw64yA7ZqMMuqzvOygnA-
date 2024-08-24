resource "aws_kms_key" "eks" {
  key_usage = "ENCRYPT_DECRYPT"
  deletion_window_in_days = 7

  tags = {
    Name = "eks-kms"
  }
}

resource "aws_kms_alias" "eks" {
  target_key_id = aws_kms_key.kms.key_id
  name = "alias/eks-kms"
}