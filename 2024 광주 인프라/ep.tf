resource "aws_vpc_endpoint" "ecr_api" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.ap-northeast-2.ecr.api"
  vpc_endpoint_type = "Interface"
  subnet_ids        = [aws_subnet.app_a.id, aws_subnet.app_b.id]
  security_group_ids = [aws_security_group.bastion.id]

  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "ecr_dkr" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.ap-northeast-2.ecr.dkr"
  vpc_endpoint_type = "Interface"
  subnet_ids        = [aws_subnet.app_a.id, aws_subnet.app_b.id]
  security_group_ids = [aws_security_group.bastion.id]

  private_dns_enabled = true
}

output "ecr_api_vpc_endpoint_id" {
  value = aws_vpc_endpoint.ecr_api.id
}

output "ecr_dkr_vpc_endpoint_id" {
  value = aws_vpc_endpoint.ecr_dkr.id
}
