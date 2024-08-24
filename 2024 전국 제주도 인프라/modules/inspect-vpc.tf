resource "aws_vpc" "inspect" {
  cidr_block           = "100.64.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "wsc-inspect-vpc"
  }
}

# 공용 라우팅 테이블
resource "aws_route_table" "inspect-peering-a-rt" {
  vpc_id = aws_vpc.inspect.id

  tags = {
    Name = "wsc-inspect-peering-a-rt"
  }
}

resource "aws_route_table" "inspect-peering-c-rt" {
  vpc_id = aws_vpc.inspect.id

  tags = {
    Name = "wsc-inspect-peering-c-rt"
  }
}

resource "aws_route" "public_tgw_prod-a" {
  route_table_id         = aws_route_table.inspect-peering-a-rt.id
  destination_cidr_block = "172.20.0.0/16"
  transit_gateway_id             = aws_ec2_transit_gateway.example.id
}

resource "aws_route" "public_tgw_prod-c" {
  route_table_id         = aws_route_table.inspect-peering-c-rt.id
  destination_cidr_block = "172.20.0.0/16"
  transit_gateway_id             = aws_ec2_transit_gateway.example.id
}

# 공용 서브넷
resource "aws_subnet" "inspect-peering-a" {
  vpc_id                  = aws_vpc.inspect.id
  cidr_block              = "100.64.0.64/28"
  availability_zone       = "ap-northeast-2a"
  map_public_ip_on_launch = true

  tags = {
    Name = "wsc-inspect-peering-sn-a"
  }
}

resource "aws_subnet" "inspect-peering-c" {
  vpc_id                  = aws_vpc.inspect.id
  cidr_block              = "100.64.0.80/28"
  availability_zone       = "ap-northeast-2c"
  map_public_ip_on_launch = true

  tags = {
    Name = "wsc-inspect-peering-sn-c"
  }
}

# 공용 서브넷을 라우팅 테이블에 연결
resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.inspect-peering-a.id
  route_table_id = aws_route_table.inspect-peering-a-rt.id
}

resource "aws_route_table_association" "public_c" {
  subnet_id      = aws_subnet.inspect-peering-c.id
  route_table_id = aws_route_table.inspect-peering-c-rt.id
}

# 보안 라우팅 테이블
resource "aws_route_table" "inspect-secure-a-rt" {
  vpc_id = aws_vpc.inspect.id

  tags = {
    Name = "wsc-inspect-secure-a-rt"
  }
}

resource "aws_route_table" "inspect-secure-c-rt" {
  vpc_id = aws_vpc.inspect.id

  tags = {
    Name = "wsc-inspect-secure-c-rt"
  }
}

resource "aws_route" "secure_tgw_prod-a" {
  route_table_id         = aws_route_table.inspect-secure-a-rt.id
  destination_cidr_block = "0.0.0.0/0"
  transit_gateway_id             = aws_ec2_transit_gateway.example.id
}

resource "aws_route" "secure_tgw_prod-c" {
  route_table_id         = aws_route_table.inspect-secure-c-rt.id
  destination_cidr_block = "0.0.0.0/0"
  transit_gateway_id             = aws_ec2_transit_gateway.example.id
}

# 보안 서브넷
resource "aws_subnet" "inspect-secure-a" {
  vpc_id            = aws_vpc.inspect.id
  cidr_block        = "100.64.0.32/28"
  availability_zone = "ap-northeast-2a"

  tags = {
    Name = "wsc-inspect-secure-sn-a"
  }
}

resource "aws_subnet" "inspect-secure-c" {
  vpc_id            = aws_vpc.inspect.id
  cidr_block        = "100.64.0.48/28"
  availability_zone = "ap-northeast-2c"

  tags = {
    Name = "wsc-inspect-secure-sn-c"
  }
}

# 보안 서브넷을 라우팅 테이블에 연결
resource "aws_route_table_association" "inspect-secure-a" {
  subnet_id      = aws_subnet.inspect-secure-a.id
  route_table_id = aws_route_table.inspect-secure-a-rt.id
}

resource "aws_route_table_association" "inspect-secure-c" {
  subnet_id      = aws_subnet.inspect-secure-c.id
  route_table_id = aws_route_table.inspect-secure-c-rt.id
}

# 네트워크 방화벽
resource "aws_networkfirewall_firewall" "inspect-firewall" {
  name                = "wsc-inspect-firewall"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.inspect-firewall-policy.arn
  vpc_id              = aws_vpc.inspect.id

  subnet_mapping {
    subnet_id = aws_subnet.inspect-secure-a.id
  }

  subnet_mapping {
    subnet_id = aws_subnet.inspect-secure-c.id
  }

  tags = {
    Name = "wsc-inspect-firewall"
  }
}

resource "aws_networkfirewall_rule_group" "example" {
  capacity = 10
  name     = "wsc-deny"
  type     = "STATEFUL"
  rules    = file("./wsc-deny.rules")
  tags = {
    Name = "wsc-deny"
  }
}

resource "aws_networkfirewall_firewall_policy" "inspect-firewall-policy" {
  name = "wsc-inspect-rules"

  firewall_policy {
    # stateful_default_actions           = ["aws:drop_strict"]
    # stateful_engine_options {
    #   rule_order = "STRICT_ORDER"
    # }
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]
    stateful_rule_group_reference {
      # priority     = 1
      resource_arn = aws_networkfirewall_rule_group.example.arn
    }
  }

  tags = {
    Name = "wsc-inspect-rules"
  }
}


# 방화벽 엔드포인트에 대한 라우트 업데이트
resource "aws_route" "public_firewall_prod-a" {
  route_table_id         = aws_route_table.inspect-peering-a-rt.id
  destination_cidr_block = "0.0.0.0/0"
  vpc_endpoint_id        = element([for ss in tolist(aws_networkfirewall_firewall.inspect-firewall.firewall_status[0].sync_states) : ss.attachment[0].endpoint_id if ss.availability_zone == aws_subnet.inspect-peering-a.availability_zone], 0)
}

resource "aws_route" "public_firewall_prod-c" {
  route_table_id         = aws_route_table.inspect-peering-c-rt.id
  destination_cidr_block = "0.0.0.0/0"
  vpc_endpoint_id        = element([for ss in tolist(aws_networkfirewall_firewall.inspect-firewall.firewall_status[0].sync_states) : ss.attachment[0].endpoint_id if ss.availability_zone == aws_subnet.inspect-peering-c.availability_zone], 0)
}


# 출력

## VPC
output "aws_inspect_vpc" {
  value = aws_vpc.inspect.id
}

## 공용 서브넷
output "public_a" {
  value = aws_subnet.inspect-peering-a.id
}

output "public_c" {
  value = aws_subnet.inspect-peering-c.id
}

## 보안 서브넷
output "private_a" {
  value = aws_subnet.inspect-secure-a.id
}

output "private_c" {
  value = aws_subnet.inspect-secure-c.id
}
