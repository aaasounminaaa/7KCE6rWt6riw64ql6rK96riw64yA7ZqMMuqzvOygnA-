resource "aws_vpc" "storage" {
  cidr_block = "192.168.0.0/16"

  enable_dns_hostnames = true
  enable_dns_support = true

  tags = {
    Name = "wsc2024-storage-vpc"
  }
}

## Public Subnet
resource "aws_subnet" "storage_a" {
  vpc_id = aws_vpc.storage.id
  cidr_block = "192.168.0.0/24"
  availability_zone = "${var.create_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "wsc2024-storage-db-sn-a"
  }
}

resource "aws_subnet" "storage_b" {
  vpc_id = aws_vpc.storage.id
  cidr_block = "192.168.1.0/24"
  availability_zone = "${var.create_region}b"
  map_public_ip_on_launch = true

  tags = {
    Name = "wsc2024-storage-db-sn-b"
  }
}

## Route Table
resource "aws_route_table" "storage_a" {
  vpc_id = aws_vpc.storage.id

  tags = {
    Name = "wsc2024-storage-db-rt-a"
  }
}

resource "aws_route_table" "storage_b" {
  vpc_id = aws_vpc.storage.id

  tags = {
    Name = "wsc2024-storage-db-rt-b"
  }
}

## Attach Public Subnet in Route Table
resource "aws_route_table_association" "storage_a" {
  subnet_id = aws_subnet.storage_a.id
  route_table_id = aws_route_table.storage_a.id
}

resource "aws_route_table_association" "storage_b" {
  subnet_id = aws_subnet.storage_b.id
  route_table_id = aws_route_table.storage_b.id
}

resource "aws_route" "main_tgw_ma" {
  route_table_id = aws_route_table.storage_a.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id = aws_ec2_transit_gateway.example.id
  depends_on = [ aws_ec2_transit_gateway.example,aws_ec2_transit_gateway_vpc_attachment.storage ]
}

resource "aws_route" "main_tgw_ma_b" {
  route_table_id = aws_route_table.storage_b.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id = aws_ec2_transit_gateway.example.id
  depends_on = [ aws_ec2_transit_gateway.example,aws_ec2_transit_gateway_vpc_attachment.storage ]
}

## VPC
output "aws_vpc_storage" {
  value = aws_vpc.storage.id
}

## Public Subnet
output "storage_public_a" {
  value = aws_subnet.storage_a.id
}

output "storage_public_b" {
  value = aws_subnet.storage_b.id
}