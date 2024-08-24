resource "aws_vpc" "prod" {
  cidr_block = "172.16.0.0/16"

  enable_dns_hostnames = true
  enable_dns_support = true

  tags = {
    Name = "wsc2024-prod-vpc"
  }
}

# Public

## Internet Gateway
resource"aws_internet_gateway" "prod" {
  vpc_id = aws_vpc.prod.id

  tags = {
    Name = "wsc2024-prod-igw"
  }
}

## Route Table
resource "aws_route_table" "prod" {
  vpc_id = aws_vpc.prod.id

  tags = {
    Name = "wsc2024-prod-load-rt"
  }
}
 
resource "aws_route" "prod" {
  route_table_id = aws_route_table.prod.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id = aws_internet_gateway.prod.id
}

resource "aws_route" "prod_tgw_ma" {
  route_table_id = aws_route_table.prod.id
  destination_cidr_block = "10.0.0.0/16"
  gateway_id = aws_ec2_transit_gateway.example.id
  depends_on = [ aws_ec2_transit_gateway.example,aws_ec2_transit_gateway_vpc_attachment.ma ]
}

resource "aws_route" "prod_tgw_storage_ma" {
  route_table_id = aws_route_table.prod.id
  destination_cidr_block = "192.168.0.0/16"
  gateway_id = aws_ec2_transit_gateway.example.id
  depends_on = [ aws_ec2_transit_gateway.example,aws_ec2_transit_gateway_vpc_attachment.ma ]
}

## prod Subnet
resource "aws_subnet" "prod_a" {
  vpc_id = aws_vpc.prod.id
  cidr_block = "172.16.0.0/24"
  availability_zone = "${var.create_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "wsc2024-prod-load-sn-a"
  }
}

resource "aws_subnet" "prod_b" {
  vpc_id = aws_vpc.prod.id
  cidr_block = "172.16.1.0/24"
  availability_zone = "${var.create_region}b"
  map_public_ip_on_launch = true

  tags = {
    Name = "wsc2024-prod-load-sn-b"
  }
}

## Attach Public Subnet in Route Table
resource "aws_route_table_association" "prod_a" {
  subnet_id = aws_subnet.prod_a.id
  route_table_id = aws_route_table.prod.id
}

resource "aws_route_table_association" "prod_b" {
  subnet_id = aws_subnet.prod_b.id
  route_table_id = aws_route_table.prod.id
}

# Private

## Elastic IP
resource "aws_eip" "private_a" {
}

resource "aws_eip" "private_b" {
}

## NAT Gateway
resource "aws_nat_gateway" "private_a" {
  depends_on = [aws_internet_gateway.prod]

  allocation_id = aws_eip.private_a.id
  subnet_id = aws_subnet.prod_a.id

  tags = {
    Name = "wsc2024-prod-natgw-a"
  }
}

resource "aws_nat_gateway" "private_b" {
  depends_on = [aws_internet_gateway.prod]

  allocation_id = aws_eip.private_b.id
  subnet_id = aws_subnet.prod_b.id

  tags = {
    Name = "wsc2024-prod-natgw-b"
  }
}

## Route Table
resource "aws_route_table" "private_a" {
  vpc_id = aws_vpc.prod.id

  tags = {
    Name = "wsc2024-prod-app-rt-a"
  }
}

resource "aws_route_table" "private_b" {
  vpc_id = aws_vpc.prod.id

  tags = {
    Name = "wsc2024-prod-app-rt-b"
  }
}

resource "aws_route" "private_a" {
  route_table_id = aws_route_table.private_a.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id = aws_nat_gateway.private_a.id
}

resource "aws_route" "private_b" {
  route_table_id = aws_route_table.private_b.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id = aws_nat_gateway.private_b.id
}

resource "aws_route" "main_prod_tgw_ma" {
  route_table_id = aws_route_table.private_a.id
  destination_cidr_block = "10.0.0.0/16"
  gateway_id = aws_ec2_transit_gateway.example.id
  depends_on = [ aws_ec2_transit_gateway.example,aws_ec2_transit_gateway_vpc_attachment.ma ]
}

resource "aws_route" "prod_tgw_storage" {
  route_table_id = aws_route_table.private_a.id
  destination_cidr_block = "192.168.0.0/16"
  gateway_id = aws_ec2_transit_gateway.example.id
  depends_on = [ aws_ec2_transit_gateway.example,aws_ec2_transit_gateway_vpc_attachment.ma ]
}

resource "aws_route" "main_private_tgw_ma" {
  route_table_id = aws_route_table.private_b.id
  destination_cidr_block = "10.0.0.0/16"
  gateway_id = aws_ec2_transit_gateway.example.id
  depends_on = [ aws_ec2_transit_gateway.example,aws_ec2_transit_gateway_vpc_attachment.ma ]
}

resource "aws_route" "private_prod_tgw_storage" {
  route_table_id = aws_route_table.private_b.id
  destination_cidr_block = "192.168.0.0/16"
  gateway_id = aws_ec2_transit_gateway.example.id
  depends_on = [ aws_ec2_transit_gateway.example,aws_ec2_transit_gateway_vpc_attachment.ma ]
}

resource "aws_subnet" "private_a" {
  vpc_id = aws_vpc.prod.id
  cidr_block = "172.16.2.0/24"
  availability_zone = "${var.create_region}a"

  tags = {
    Name = "wsc2024-prod-app-sn-a"
  }
}

resource "aws_subnet" "private_b" {
  vpc_id = aws_vpc.prod.id
  cidr_block = "172.16.3.0/24"
  availability_zone = "${var.create_region}b"

  tags = {
    Name = "wsc2024-prod-app-sn-b"
  }
}

## Attach Private Subnet in Route Table
resource "aws_route_table_association" "private_a" {
  subnet_id = aws_subnet.private_a.id
  route_table_id = aws_route_table.private_a.id
}

resource "aws_route_table_association" "private_b" {
  subnet_id = aws_subnet.private_b.id
  route_table_id = aws_route_table.private_b.id
}

resource "aws_security_group" "ep-prod" {
  name = "wsc2024-prod-EP-SG"
  vpc_id = aws_vpc.prod.id

  ingress {
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port = "443"
    to_port = "443"
  }

  egress {
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    from_port = "0"
    to_port = "0"
  }
 
    tags = {
    Name = "wsc2024-prod-EP-SG"
  }
}

# resource "aws_security_group" "ep-ma" {
#   name = "wsc2024-ma-EP-SG"
#   vpc_id = aws_vpc.prod.id

#   ingress {
#     protocol = "tcp"
#     cidr_blocks = ["0.0.0.0/0"]
#     from_port = "443"
#     to_port = "443"
#   }

#   egress {
#     protocol = "-1"
#     cidr_blocks = ["0.0.0.0/0"]
#     from_port = "0"
#     to_port = "0"
#   }
 
#     tags = {
#     Name = "wsc2024-ma-EP-SG"
#   }
# }

resource "aws_vpc_endpoint" "ecr" {
  vpc_id            = aws_vpc.prod.id
  service_name      = "com.amazonaws.us-east-1.ecr.dkr"
  vpc_endpoint_type = "Interface"

  security_group_ids = [
    aws_security_group.ep-prod.id
  ]
  private_dns_enabled = true
  tags = {
    Name = "wsc2024-ecr-endpoint"
  }
}

resource "aws_vpc_endpoint_subnet_association" "prod_a" {
  vpc_endpoint_id = aws_vpc_endpoint.ecr.id
  subnet_id       = aws_subnet.private_a.id
}
resource "aws_vpc_endpoint_subnet_association" "prod_b" {
  vpc_endpoint_id = aws_vpc_endpoint.ecr.id
  subnet_id       = aws_subnet.private_b.id
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.ma.id
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  tags = {
    Name = "wsc2024-s3-endpoint"
  }
}

resource "aws_vpc_endpoint_policy" "s3" {
  vpc_endpoint_id = aws_vpc_endpoint.s3.id
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "AllowAll",
        "Effect" : "Deny",
        "Principal" : "*",
        "Action" : [
          "s3:*"
        ],
        "Resource" : "arn:aws:s3:::prod-us-east-1-starport-layer-bucket/*"
      },
      {
         "Sid": "allow-s3",
         "Effect": "Allow",
         "Principal": "*",
         "Action": "s3:*",
         "Resource": "*"
      }
    ]
  })
}

resource "aws_vpc_endpoint_route_table_association" "private_a" {
  vpc_endpoint_id = aws_vpc_endpoint.s3.id
  route_table_id  = aws_route_table.public.id
}

# resource "aws_vpc_endpoint_route_table_association" "private_b" {
#   vpc_endpoint_id = aws_vpc_endpoint.s3.id
#   route_table_id  = aws_route_table.private_b.id
# }


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
#   key_name = "wsc2024-prod"
#   public_key = tls_private_key.rsa.public_key_openssh
# }

# resource "local_file" "keypair" {
#   content = tls_private_key.rsa.private_key_pem
#   filename = "./wsc2024-prod.pem"
# }

## Public EC2
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
#     Name = "wsc2024-prod-bastion-ec2"
#   }
# }

# ## Public Security Group
# resource "aws_security_group" "bastion" {
#   name = "wsc2024-prod-EC2-SG"
#   vpc_id = aws_vpc.prod.id

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
#     Name = "wsc2024-prod-EC2-SG"
#   }
# }

# ## IAM
# resource "aws_iam_role" "bastion" {
#   name = "wsc2024-prod-role-bastion"
  
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
#   name = "wsc2024-prod-profile-bastion"
#   role = aws_iam_role.bastion.name
# }

# OutPut
## VPC
output "aws_vpc_prod" {
  value = aws_vpc.prod.id
}

## Public Subnet
output "prod_public_a" {
  value = aws_subnet.prod_a.id
}

output "prod_public_b" {
  value = aws_subnet.prod_b.id
}

## Private Subnet
output "private_a" {
  value = aws_subnet.private_a.id
}

output "private_b" {
  value = aws_subnet.private_b.id
}

# output "bastion" {
#   value = aws_instance.bastion.id
# }

# output "bastion-sg" {
#   value = aws_security_group.bastion.id
# }