resource "aws_ec2_transit_gateway" "example" {
  description = "example"
  auto_accept_shared_attachments = "enable"
  default_route_table_association = "disable"
  default_route_table_propagation = "disable"
  dns_support = "enable"
  multicast_support = "enable"
  vpn_ecmp_support = "enable"
  tags = {
    Name = "wsc2024-vpc-tgw"
  }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "ma" {
  subnet_ids         = [aws_subnet.public_a.id]
  transit_gateway_id = aws_ec2_transit_gateway.example.id
  vpc_id             = aws_vpc.ma.id
  tags = {
    Name = "wsc2024-ma-tgw-attach"
  }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "prod" {
  subnet_ids         = [aws_subnet.prod_a.id, aws_subnet.prod_b.id]
  transit_gateway_id = aws_ec2_transit_gateway.example.id
  vpc_id             = aws_vpc.prod.id
  tags = {
    Name = "wsc2024-prod-tgw-attach"
  }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "storage" {
  subnet_ids         = [aws_subnet.storage_a.id,aws_subnet.storage_b.id]
  transit_gateway_id = aws_ec2_transit_gateway.example.id
  vpc_id             = aws_vpc.storage.id
  tags = {
    Name = "wsc2024-storage-tgw-attach"
  }
}

resource "aws_ec2_transit_gateway_route_table" "customer" {
  transit_gateway_id = aws_ec2_transit_gateway.example.id
  tags = {
    Name = "wsc2024-ma-tgw-rt"
  }
}

resource "aws_ec2_transit_gateway_route_table_association" "ma" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.ma.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.customer.id
}

resource "aws_ec2_transit_gateway_route" "ma-prod-rt" {
  destination_cidr_block         = "0.0.0.0/0"
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.prod.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.customer.id
}

resource "aws_ec2_transit_gateway_route" "ma-storage-rt" {
  destination_cidr_block         = "192.168.0.0/16"
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.storage.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.customer.id
}

resource "aws_ec2_transit_gateway_route_table" "prod" {
  transit_gateway_id = aws_ec2_transit_gateway.example.id
  tags = {
    Name = "wsc2024-prod-tgw-rt"
  }
}

resource "aws_ec2_transit_gateway_route_table_association" "prod" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.prod.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.prod.id
}

resource "aws_ec2_transit_gateway_route" "prod-ma-rt" {
  destination_cidr_block         = "0.0.0.0/0"
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.ma.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.prod.id
}

resource "aws_ec2_transit_gateway_route" "prod-storage-rt" {
  destination_cidr_block         = "192.168.0.0/16"
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.storage.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.prod.id
}

resource "aws_ec2_transit_gateway_route_table" "storage" {
  transit_gateway_id = aws_ec2_transit_gateway.example.id
  tags = {
    Name = "wsc2024-storage-tgw-rt"
  }
}
resource "aws_ec2_transit_gateway_route_table_association" "order" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.storage.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.storage.id
}
resource "aws_ec2_transit_gateway_route" "storage-prod-rt" {
  destination_cidr_block         = "0.0.0.0/0"
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.prod.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.storage.id
}
resource "aws_ec2_transit_gateway_route" "storage-ma-rt" {
  destination_cidr_block         = "10.0.0.0/16"
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.ma.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.storage.id
}