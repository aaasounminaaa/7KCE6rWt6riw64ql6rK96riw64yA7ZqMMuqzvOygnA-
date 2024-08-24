resource "aws_ec2_transit_gateway" "example" {
  description = "example"
  auto_accept_shared_attachments = "enable"
  default_route_table_association = "disable"
  default_route_table_propagation = "disable"
  dns_support = "enable"
  multicast_support = "enable"
  vpn_ecmp_support = "enable"
  tags = {
    Name = "wsc-vpc-tgw"
  }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "prod" {
  subnet_ids         = [aws_subnet.prod_peering_a.id,aws_subnet.prod_peering_c.id]
  transit_gateway_id = aws_ec2_transit_gateway.example.id
  vpc_id             = aws_vpc.prod.id
  tags = {
    Name = "wsc-prod-tgw-attache"
  }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "inspect" {
  subnet_ids         = [aws_subnet.inspect-peering-a.id, aws_subnet.inspect-peering-c.id]
  transit_gateway_id = aws_ec2_transit_gateway.example.id
  vpc_id             = aws_vpc.inspect.id
  tags = {
    Name = "wsc-inspect-tgw-attache"
  }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "ingress" {
  subnet_ids         = [aws_subnet.ingress-peering-a.id,aws_subnet.ingress-peering-c.id]
  transit_gateway_id = aws_ec2_transit_gateway.example.id
  vpc_id             = aws_vpc.ingress.id
  tags = {
    Name = "wsc-ingress-tgw-attache"
  }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "egress" {
  subnet_ids         = [aws_subnet.egress-peering-a.id,aws_subnet.egress-peering-c.id]
  transit_gateway_id = aws_ec2_transit_gateway.example.id
  vpc_id             = aws_vpc.egress.id
  tags = {
    Name = "wsc-egress-tgw-attache"
  }
}

resource "aws_ec2_transit_gateway_route_table" "prod" {
  transit_gateway_id = aws_ec2_transit_gateway.example.id
  tags = {
    Name = "wsc-prod-tgw-rt"
  }
}

resource "aws_ec2_transit_gateway_route_table_association" "prod" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.prod.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.prod.id
}

resource "aws_ec2_transit_gateway_route" "prod-inspect" {
  destination_cidr_block         = "0.0.0.0/0"
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.inspect.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.prod.id
}

resource "aws_ec2_transit_gateway_route_table" "inspect" {
  transit_gateway_id = aws_ec2_transit_gateway.example.id
  tags = {
    Name = "wsc-inspect-tgw-rt"
  }
}
resource "aws_ec2_transit_gateway_route_table_association" "inspect" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.inspect.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.inspect.id
}

resource "aws_ec2_transit_gateway_route" "inspect-egress" {
  destination_cidr_block         = "0.0.0.0/0"
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.egress.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.inspect.id
}

resource "aws_ec2_transit_gateway_route" "inspect-prod" {
  destination_cidr_block         = "10.100.0.0/16"
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.prod.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.inspect.id
}

resource "aws_ec2_transit_gateway_route" "inspect-ingress" {
  destination_cidr_block         = "172.20.0.0/16"
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.ingress.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.inspect.id
}

resource "aws_ec2_transit_gateway_route_table" "ingress" {
  transit_gateway_id = aws_ec2_transit_gateway.example.id
  tags = {
    Name = "wsc-ingress-tgw-rt"
  }
}

resource "aws_ec2_transit_gateway_route_table_association" "ingress" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.ingress.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.ingress.id
}

resource "aws_ec2_transit_gateway_route" "ingress-inspect" {
  destination_cidr_block         = "0.0.0.0/0"
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.inspect.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.ingress.id
}

resource "aws_ec2_transit_gateway_route_table" "egress" {
  transit_gateway_id = aws_ec2_transit_gateway.example.id
  tags = {
    Name = "wsc-egress-tgw-rt"
  }
}

resource "aws_ec2_transit_gateway_route_table_association" "egress" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.egress.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.egress.id
}

resource "aws_ec2_transit_gateway_route" "egress-inspect" {
  destination_cidr_block         = "0.0.0.0/0"
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.inspect.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.egress.id
}