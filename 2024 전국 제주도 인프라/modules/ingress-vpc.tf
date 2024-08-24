resource "aws_vpc" "ingress" {
  cidr_block = "172.20.0.0/16"

  enable_dns_hostnames = true
  enable_dns_support = true

  tags = {
    Name = "wsc-ingress-vpc"
  }
}

# Public
## Internet Gateway
resource"aws_internet_gateway" "ingress" {
  vpc_id = aws_vpc.ingress.id

  tags = {
    Name = "wsc-ingress-pub-igw"
  }
}

## Route Table
resource "aws_route_table" "ingress" {
  vpc_id = aws_vpc.ingress.id

  tags = {
    Name = "wsc-ingress-pub-rt"
  }
}
 
resource "aws_route" "ingress" {
  route_table_id = aws_route_table.ingress.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id = aws_internet_gateway.ingress.id
}

resource "aws_route" "ingress-tgw" {
  route_table_id = aws_route_table.ingress.id
  destination_cidr_block = "10.100.0.0/16"
  transit_gateway_id = aws_ec2_transit_gateway.example.id
}

## Public Subnet
resource "aws_subnet" "ingress-pub-a" {
  vpc_id = aws_vpc.ingress.id
  cidr_block = "172.20.0.32/28"
  availability_zone = "ap-northeast-2a"
  map_public_ip_on_launch = true

  tags = {
    Name = "wsc-ingress-pub-sn-a"
  }
}

resource "aws_subnet" "ingress-pub-c" {
  vpc_id = aws_vpc.ingress.id
  cidr_block = "172.20.0.64/28"
  availability_zone = "ap-northeast-2c"
  map_public_ip_on_launch = true

  tags = {
    Name = "wsc-ingress-pub-sn-c"
  }
}

## Attach Public Subnet in Route Table
resource "aws_route_table_association" "ingress-pub-a" {
  subnet_id = aws_subnet.ingress-pub-a.id
  route_table_id = aws_route_table.ingress.id
}

resource "aws_route_table_association" "ingress-pub-c" {
  subnet_id = aws_subnet.ingress-pub-c.id
  route_table_id = aws_route_table.ingress.id
}

# Private

# ## Elastic IP
# resource "aws_eip" "private_a" {
# }

# resource "aws_eip" "private_b" {
# }

## NAT Gateway
# resource "aws_nat_gateway" "private_a" {
#   depends_on = [aws_internet_gateway.main]

#   allocation_id = aws_eip.private_a.id
#   subnet_id = aws_subnet.public_a.id

#   tags = {
#     Name = "wsc-ingress-pub-NGW-a"
#   }
# }

# resource "aws_nat_gateway" "private_b" {
#   depends_on = [aws_internet_gateway.main]

#   allocation_id = aws_eip.private_b.id
#   subnet_id = aws_subnet.public_b.id

#   tags = {
#     Name = "wsc-ingress-pub-NGW-b"
#   }
# }

## Route Table
resource "aws_route_table" "ingress-peering-a" {
  vpc_id = aws_vpc.ingress.id

  tags = {
    Name = "wsc-ingress-peering-rt"
  }
}

# resource "aws_route_table" "ingress-peering-c" {
#   vpc_id = aws_vpc.ingress.id

#   tags = {
#     Name = "wsc-ingress-peering-c-rt"
#   }
# }

# resource "aws_route" "ingress-perring-a" {
#   route_table_id = aws_route_table.ingress-perring-a.id
#   destination_cidr_block = "0.0.0.0/0"
#   nat_gateway_id = aws_nat_gateway.private_a.id
# }

# resource "aws_route" "ingress-perring-c" {
#   route_table_id = aws_route_table.private_b.id
#   destination_cidr_block = "0.0.0.0/0"
#   nat_gateway_id = aws_nat_gateway.private_b.id
# }

resource "aws_subnet" "ingress-peering-a" {
  vpc_id = aws_vpc.ingress.id
  cidr_block = "172.20.0.96/28"
  availability_zone = "ap-northeast-2a"

  tags = {
    Name = "wsc-ingress-peering-sn-a"
  }
}

resource "aws_subnet" "ingress-peering-c" {
  vpc_id = aws_vpc.ingress.id
  cidr_block = "172.20.0.128/28"
  availability_zone = "ap-northeast-2c"

  tags = {
    Name = "wsc-ingress-peering-sn-c"
  }
}

## Attach Private Subnet in Route Table
resource "aws_route_table_association" "ingress-peering-a" {
  subnet_id = aws_subnet.ingress-peering-a.id
  route_table_id = aws_route_table.ingress-peering-a.id
}

resource "aws_route_table_association" "ingress-peering-c" {
  subnet_id = aws_subnet.ingress-peering-c.id
  route_table_id = aws_route_table.ingress-peering-a.id
}

resource "aws_route" "ingress_tgw_inspect" {
  route_table_id = aws_route_table.ingress-peering-a.id
  destination_cidr_block = "0.0.0.0/0"
  transit_gateway_id = aws_ec2_transit_gateway.example.id
}

resource "aws_security_group" "ingress-lb-sg" {
  name = "wsc-ingress-alb-SG"
  vpc_id = aws_vpc.ingress.id

  ingress {
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port = "80"
    to_port = "80"
  }
  egress {
    protocol = -1
    cidr_blocks = ["0.0.0.0/0"]
    from_port = 0
    to_port = 0
  }

    tags = {
    Name = "wsc-ingress-alb-SG"
  }
}

# EC2
## AMI
# data "aws_ami" "amazonlinux2023" {
#   most_recent = true

#   filter {
#     name   = "name"
#     values = ["al2023-ami-*x86*"]
#   }

#   filter {
#     name   = "virtualization-type"
#     values = ["hvm"]
#   }

#   owners = ["137112412989"] # Amazon's official account ID
# }

# ## Keypair
# resource "tls_private_key" "rsa" {
#   algorithm = "RSA"
#   rsa_bits = 4096
# }

# resource "aws_key_pair" "keypair" {
#   key_name = "<env>"
#   public_key = tls_private_key.rsa.public_key_openssh
# }

# resource "local_file" "keypair" {
#   content = tls_private_key.rsa.private_key_pem
#   filename = "./<env>.pem"
# }

# ## Public EC2
# resource "aws_instance" "bastion" {
#   ami = data.aws_ami.amazonlinux2023.id
#   subnet_id = aws_subnet.public_a.id
#   instance_type = "<Type>"
#   key_name = aws_key_pair.keypair.key_name
#   vpc_security_group_ids = [aws_security_group.bastion.id]
#   associate_public_ip_address = true
#   iam_instance_profile = aws_iam_instance_profile.bastion.name
#   user_data = <<-EOF
#   #!/bin/bash
#   yum update -y
#   ...
#   EOF
#   tags = {
#     Name = "wsc-ingress-pub-bastion-ec2"
#   }
# }

# ## Public Security Group
# resource "aws_security_group" "bastion" {
#   name = "wsc-ingress-pub-EC2-SG"
#   vpc_id = aws_vpc.ingress.id

#   ingress {
#     protocol = "tcp"
#     cidr_blocks = ["0.0.0.0/0"]
#     from_port = "<Port>"
#     to_port = "<Port>"
#   }

#   egress {
#     protocol = "tcp"
#     cidr_blocks = ["0.0.0.0/0"]
#     from_port = "<Port>"
#     to_port = "<Port>"
#   }
 
#     tags = {
#     Name = "wsc-ingress-pub-EC2-SG"
#   }
# }

# ## IAM
# resource "aws_iam_role" "bastion" {
#   name = "wsc-ingress-pub-role-bastion"
  
#   assume_role_policy = jsonencode({
#     Version = "2012-10-17"
#     Statement = [
#       {
#         Action = "sts:AssumeRole"
#         Effect = "Allow"
#         Sid = ""
#         Principal = {
#           Service = "ec2.amazonaws.com"
#         }
#       }
#     ]
#   })

#   managed_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]
# }

# resource "aws_iam_instance_profile" "bastion" {
#   name = "wsc-ingress-pub-profile-bastion"
#   role = aws_iam_role.bastion.name
# }

# OutPut

## VPC
output "aws_ingress_vpc" {
  value = aws_vpc.ingress.id
}

## Public Subnet
output "ingress_public_a" {
  value = aws_subnet.ingress-pub-a.id
}

output "ingress_public_c" {
  value = aws_subnet.ingress-pub-c.id
}

## Private Subnet
output "ingress_peering_a" {
  value = aws_subnet.ingress-peering-a.id
}

output "ingress_peering_c" {
  value = aws_subnet.ingress-peering-c.id
}

# output "bastion" {
#   value = aws_instance.bastion.id
# }

# output "bastion-sg" {
#   value = aws_security_group.bastion.id
# }