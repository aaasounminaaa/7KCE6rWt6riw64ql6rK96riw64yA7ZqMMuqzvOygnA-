resource "aws_vpc" "prod" {
  cidr_block = "10.100.0.0/16"

  enable_dns_hostnames = true
  enable_dns_support = true

  tags = {
    Name = "wsc-prod-vpc"
  }
}

# Public
# # Route Table
resource "aws_route_table" "prod_peering" {
  vpc_id = aws_vpc.prod.id

  tags = {
    Name = "wsc-prod-peering-rt"
  }
}

resource "aws_route" "prod_tgw_inspect" {
  route_table_id = aws_route_table.prod_peering.id
  destination_cidr_block = "0.0.0.0/0"
  transit_gateway_id = aws_ec2_transit_gateway.example.id
}

# resource "aws_route" "public" {
#   route_table_id = aws_route_table.public.id
#   destination_cidr_block = "0.0.0.0/0"
#   gateway_id = aws_internet_gateway.main.id
# }

## Public Subnet
resource "aws_subnet" "prod_peering_a" {
  vpc_id = aws_vpc.prod.id
  cidr_block = "10.100.1.0/24"
  availability_zone = "ap-northeast-2a"
  map_public_ip_on_launch = true

  tags = {
    Name = "wsc-prod-peering-sn-a"
  }
}

resource "aws_subnet" "prod_peering_c" {
  vpc_id = aws_vpc.prod.id
  cidr_block = "10.100.2.0/24"
  availability_zone = "ap-northeast-2c"
  map_public_ip_on_launch = true

  tags = {
    Name = "wsc-prod-peering-sn-c"
  }
}

## Attach Public Subnet in Route Table
resource "aws_route_table_association" "prod_peering_a" {
  subnet_id = aws_subnet.prod_peering_a.id
  route_table_id = aws_route_table.prod_peering.id
}

resource "aws_route_table_association" "prod_peering_c" {
  subnet_id = aws_subnet.prod_peering_c.id
  route_table_id = aws_route_table.prod_peering.id
}


# Private

## Elastic IP
# resource "aws_eip" "private_a" {
# }

# resource "aws_eip" "private_b" {
# }

## NAT Gateway
resource "aws_nat_gateway" "prod_workload_a" {
#   allocation_id = aws_eip.private_a.id
  connectivity_type = "private"
  subnet_id = aws_subnet.prod_peering_a.id
  tags = {
    Name = "wsc-prod-ngw-a"
  }
}

resource "aws_nat_gateway" "prod_workload_c" {
#   depends_on = [aws_internet_gateway.main]
#   allocation_id = aws_eip.private_b.id
  connectivity_type = "private"
  subnet_id = aws_subnet.prod_peering_c.id

  tags = {
    Name = "wsc-prod-ngw-c"
  }
}

## Route Table
resource "aws_route_table" "workload_a" {
  vpc_id = aws_vpc.prod.id

  tags = {
    Name = "wsc-prod-workload-a-rt"
  }
}

resource "aws_route_table" "workload_c" {
  vpc_id = aws_vpc.prod.id

  tags = {
    Name = "wsc-prod-workload-c-rt"
  }
}

resource "aws_route" "workload_a" {
  route_table_id = aws_route_table.workload_a.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id = aws_nat_gateway.prod_workload_a.id
}

resource "aws_route" "workload_c" {
  route_table_id = aws_route_table.workload_c.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id = aws_nat_gateway.prod_workload_c.id
}

resource "aws_subnet" "workload_a" {
  vpc_id = aws_vpc.prod.id
  cidr_block = "10.100.10.0/24"
  availability_zone = "ap-northeast-2a"

  tags = {
    Name = "wsc-prod-workload-sn-a"
  }
}

resource "aws_subnet" "workload_c" {
  vpc_id = aws_vpc.prod.id
  cidr_block = "10.100.11.0/24"
  availability_zone = "ap-northeast-2c"

  tags = {
    Name = "wsc-prod-workload-sn-c"
  }
}

## Attach Private Subnet in Route Table
resource "aws_route_table_association" "workload_a" {
  subnet_id = aws_subnet.workload_a.id
  route_table_id = aws_route_table.workload_a.id
}

resource "aws_route_table_association" "workload_b" {
  subnet_id = aws_subnet.workload_c.id
  route_table_id = aws_route_table.workload_c.id
}

# protect

#Route Table
resource "aws_route_table" "protect_a" {
  vpc_id = aws_vpc.prod.id

  tags = {
    Name = "wsc-prod-protect-rt"
  }
}
 
# resource "aws_route_table" "protect_b" {
#   vpc_id = aws_vpc.prod.id

#   tags = {
#     Name = "wsc-prod-protect-c-rt"
#   }
# }

## protect Subnet
resource "aws_subnet" "protect_a" {
  vpc_id = aws_vpc.prod.id
  cidr_block = "10.100.20.0/24"
  availability_zone = "ap-northeast-2a"

  tags = {
    Name = "wsc-prod-protect-sn-a"
  }
}

resource "aws_subnet" "protect_c" {
  vpc_id = aws_vpc.prod.id
  cidr_block = "10.100.21.0/24"
  availability_zone = "ap-northeast-2c"

  tags = {
    Name = "wsc-prod-protect-sn-c"
  }
}

## Attach protect Subnet in Route Table
resource "aws_route_table_association" "protect_a" {
  subnet_id = aws_subnet.protect_a.id
  route_table_id = aws_route_table.protect_a.id
}

resource "aws_route_table_association" "protect_c" {
  subnet_id = aws_subnet.protect_c.id
  route_table_id = aws_route_table.protect_a.id
}

# EC2
## AMI
data "aws_ami" "amazonlinux2023" {
  most_recent = true

  filter {
    name   = "name"
    values = ["al2023-ami-*x86*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["137112412989"] # Amazon's official account ID
}

## Keypair
# resource "tls_private_key" "rsa" {
#   algorithm = "RSA"
#   rsa_bits = 4096
# }

# resource "aws_key_pair" "keypair" {
#   key_name = "wsc"
#   public_key = tls_private_key.rsa.public_key_openssh
# }

# resource "local_file" "keypair" {
#   content = tls_private_key.rsa.private_key_pem
#   filename = "./wsc.pem"
# }

resource "aws_security_group" "endpoint" {
  name = "wsc-endpoint-SG"
  vpc_id = aws_vpc.prod.id

  ingress {
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port = "443"
    to_port = "443"
  }

  egress {
    protocol = -1
    cidr_blocks = ["0.0.0.0/0"]
    from_port = 0
    to_port = 0
  }

    tags = {
    Name = "wsc-endpoint-SG"
  }
}

resource "aws_vpc_endpoint" "ssm-1" {
  vpc_id            = aws_vpc.prod.id
  service_name      = "com.amazonaws.ap-northeast-2.ssm"
  vpc_endpoint_type = "Interface"

  security_group_ids = [
    aws_security_group.endpoint.id
  ]
  private_dns_enabled = true
  tags = {
    Name = "wsc-ssm-endpoint"
  }
}

resource "aws_vpc_endpoint_subnet_association" "sub-a-1" {
  vpc_endpoint_id = aws_vpc_endpoint.ssm-1.id
  subnet_id       = aws_subnet.workload_a.id
}
resource "aws_vpc_endpoint_subnet_association" "sub-c-1" {
  vpc_endpoint_id = aws_vpc_endpoint.ssm-1.id
  subnet_id       = aws_subnet.workload_c.id
}

resource "aws_vpc_endpoint" "ssm-message-1" {
  vpc_id            = aws_vpc.prod.id
  service_name      = "com.amazonaws.ap-northeast-2.ssmmessages"
  vpc_endpoint_type = "Interface"

  security_group_ids = [
    aws_security_group.endpoint.id
  ]
  private_dns_enabled = true
  tags = {
    Name = "wsc-ssmmessages-endpoint"
  }
}

resource "aws_vpc_endpoint_subnet_association" "sub-a-message-1" {
  vpc_endpoint_id = aws_vpc_endpoint.ssm-message-1.id
  subnet_id       = aws_subnet.workload_a.id
}
resource "aws_vpc_endpoint_subnet_association" "sub-c-message-1" {
  vpc_endpoint_id = aws_vpc_endpoint.ssm-message-1.id
  subnet_id       = aws_subnet.workload_c.id
}

resource "aws_vpc_endpoint" "ec2-1" {
  vpc_id            = aws_vpc.prod.id
  service_name      = "com.amazonaws.ap-northeast-2.ec2"
  vpc_endpoint_type = "Interface"

  security_group_ids = [
    aws_security_group.endpoint.id
  ]
  private_dns_enabled = true
  tags = {
    Name = "wsc-ec2-endpoint"
  }
}

resource "aws_vpc_endpoint_subnet_association" "sub-a-ec2-1" {
  vpc_endpoint_id = aws_vpc_endpoint.ec2-1.id
  subnet_id       = aws_subnet.workload_a.id
}
resource "aws_vpc_endpoint_subnet_association" "sub-c-ec2-1" {
  vpc_endpoint_id = aws_vpc_endpoint.ec2-1.id
  subnet_id       = aws_subnet.workload_c.id
}
resource "aws_vpc_endpoint" "ec2-message-1" {
  vpc_id            = aws_vpc.prod.id
  service_name      = "com.amazonaws.ap-northeast-2.ec2messages"
  vpc_endpoint_type = "Interface"

  security_group_ids = [
    aws_security_group.endpoint.id
  ]
  private_dns_enabled = true
  tags = {
    Name = "wsc-ec2-message-endpoint"
  }
}

resource "aws_vpc_endpoint_subnet_association" "sub-a-ec2-message-1" {
  vpc_endpoint_id = aws_vpc_endpoint.ec2-message-1.id
  subnet_id       = aws_subnet.workload_a.id
}
resource "aws_vpc_endpoint_subnet_association" "sub-c-ec2-message-1" {
  vpc_endpoint_id = aws_vpc_endpoint.ec2-message-1.id
  subnet_id       = aws_subnet.workload_c.id
}

resource "aws_vpc_endpoint" "ecr" {
  vpc_id            = aws_vpc.prod.id
  service_name      = "com.amazonaws.ap-northeast-2.ecr.dkr"
  vpc_endpoint_type = "Interface"

  security_group_ids = [
    aws_security_group.endpoint.id
  ]
  private_dns_enabled = true
  tags = {
    Name = "wsc-prod-ecr-endpoint"
  }
}

resource "aws_vpc_endpoint_subnet_association" "prod_a" {
  vpc_endpoint_id = aws_vpc_endpoint.ecr.id
  subnet_id       = aws_subnet.workload_a.id
}
resource "aws_vpc_endpoint_subnet_association" "prod_b" {
  vpc_endpoint_id = aws_vpc_endpoint.ecr.id
  subnet_id       = aws_subnet.workload_c.id
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.prod.id
  service_name      = "com.amazonaws.ap-northeast-2.dynamodb"
  vpc_endpoint_type = "Interface"

  security_group_ids = [
    aws_security_group.endpoint.id
  ]
  # private_dns_enabled = true
  tags = {
    Name = "wsi-prod-dynamodb-endpoint"
  }
}

resource "aws_vpc_endpoint_subnet_association" "prod_dynamodb_a" {
  vpc_endpoint_id = aws_vpc_endpoint.dynamodb.id
  subnet_id       = aws_subnet.workload_a.id
}
resource "aws_vpc_endpoint_subnet_association" "prod_dynamodb_b" {
  vpc_endpoint_id = aws_vpc_endpoint.dynamodb.id
  subnet_id       = aws_subnet.workload_c.id
}

## Public EC2
resource "aws_instance" "bastion" {
  ami = data.aws_ami.amazonlinux2023.id
  subnet_id = aws_subnet.workload_c.id
  instance_type = "t3.medium"
#   key_name = aws_key_pair.keypair.key_name
  # vpc_security_group_ids = [aws_security_group.bastion.id,aws_security_group.outbound.id]
  vpc_security_group_ids = [aws_security_group.bastion.id]
  associate_public_ip_address = false
  iam_instance_profile = aws_iam_instance_profile.bastion.name
  user_data = <<-EOF
  #!/bin/bash
  echo "Skill53##" | passwd --stdin ec2-user
  sed -i 's|.*PasswordAuthentication.*|PasswordAuthentication yes|g' /etc/ssh/sshd_config
  systemctl restart sshd
  yum update -y
  yum install -y curl jq
  yum install -y docker
  systemctl enable --now docker
  usermod -aG docker ec2-user
  usermod -aG docker root
  chmod 666 /var/run/docker.sock
  curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
  unzip awscliv2.zip
  sudo ./aws/install
  ln -s /usr/local/bin/aws /usr/bin/
  ln -s /usr/local/bin/aws_completer /usr/bin/
  curl -O https://s3.us-west-2.amazonaws.com/amazon-eks/1.29.3/2024-04-19/bin/linux/amd64/kubectl 
  chmod +x ./kubectl
  mv -f ./kubectl /usr/local/bin/kubectl 
  curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
  mv /tmp/eksctl /usr/bin
  dnf install -y mariadb105
  sudo yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm
  curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
  sudo chmod 700 get_helm.sh
  ./get_helm.sh
  sudo mv ./get_helm.sh /usr/local/bin
  EOF
  tags = {
    Name = "wsc-prod-bastion"
  }
  depends_on = [ aws_vpc_endpoint.ec2-1,aws_vpc_endpoint.ec2-message-1,aws_vpc_endpoint.ssm-1,aws_vpc_endpoint.ssm-message-1,aws_vpc_endpoint_subnet_association.sub-a-1,aws_vpc_endpoint_subnet_association.sub-c-1,aws_vpc_endpoint_subnet_association.sub-a-message-1,aws_vpc_endpoint_subnet_association.sub-c-message-1,aws_vpc_endpoint_subnet_association.sub-a-ec2-1,aws_vpc_endpoint_subnet_association.sub-c-ec2-1,aws_vpc_endpoint_subnet_association.sub-a-ec2-message-1,aws_vpc_endpoint_subnet_association.sub-c-ec2-message-1 ]
}

## Public Security Group
resource "aws_security_group" "bastion" {
  name = "wsc-prod-bastion-SG"
  vpc_id = aws_vpc.prod.id

  ingress {
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port = "22"
    to_port = "22"
  }

  egress {
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port = "80"
    to_port = "80"
  }

  egress {
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port = "443"
    to_port = "443"
  }

  egress {
    protocol = "icmp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port = -1
    to_port = -1
  }

    tags = {
    Name = "wsc-prod-bastion-SG"
  }
}

resource "aws_security_group" "controlplan" {
  name = "wsc-controlplan-sg"
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
    Name = "wsc-controlplan-sg"
  }
}

## IAM
resource "aws_iam_role" "bastion" {
  name = "wsc-prod-role-bastion"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  managed_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess","arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]
}

resource "aws_iam_instance_profile" "bastion" {
  name = "wsc-prod-profile-bastion"
  role = aws_iam_role.bastion.name
}

# OutPut

## VPC
output "aws_prod_vpc" {
  value = aws_vpc.prod.id
}

## Public Subnet
output "prod_peering_a" {
  value = aws_subnet.prod_peering_a.id
}

output "prod_peering_c" {
  value = aws_subnet.prod_peering_c.id
}

## Private Subnet
output "prod_workload_a" {
  value = aws_subnet.workload_a.id
}

output "prod_workload_c" {
  value = aws_subnet.workload_c.id
}

output "protect_a" {
    value = aws_subnet.protect_a.id
}

output "protect_c" {
    value = aws_subnet.protect_c.id
}

output "bastion" {
  value = aws_instance.bastion.id
}

output "bastion-sg" {
  value = aws_security_group.bastion.id
}

output "bastion-iam" {
  value = aws_iam_role.bastion.arn
}